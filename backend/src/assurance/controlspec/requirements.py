"""Deterministic approval, condition, evidence, and profile assessment."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, cast

from pydantic import ValidationError

from assurance.contracts.canonical import canonical_json, sha256_digest
from assurance.controlspec.contracts import (
    ActionIntent,
    ApprovalRequirement,
    ConditionResult,
    ControlEffect,
    ControlRef,
    CoreRouteKind,
    EvidenceRequirement,
    FailureEffect,
    NamespacedValue,
    Predicate,
    ProfileRequirement,
    Verdict,
)
from assurance.controlspec.facts import (
    ApprovalFact,
    EvaluationFacts,
    FactT,
    ProfileAssessmentFact,
    ProfileAssessmentStatus,
    PublishedControlSnapshot,
    verify_fact,
)
from assurance.controlspec.predicate import (
    PredicateResult,
    evaluate_predicate,
    evaluation_document,
)
from assurance.controlspec.selection import AppliedControlOutcome

CORE_PREDICATE_VERIFIER = "controlspec.core.verifier.predicate"
CORE_PREDICATE_PARAMETER = "controlspec.core.predicate"


class TrustedFactError(ValueError):
    """A host-supplied fact is structurally invalid or has a stale digest."""


@dataclass(frozen=True)
class RequirementAssessment:
    failures: tuple[tuple[ControlRef, FailureEffect, NamespacedValue], ...]
    approval_requirements: tuple[ApprovalRequirement, ...]
    evidence_requirements: tuple[EvidenceRequirement, ...]
    condition_results: tuple[ConditionResult, ...]
    explanation_codes: tuple[NamespacedValue, ...]
    independence_failed: bool
    profile_outcomes: tuple[ControlEffect | FailureEffect, ...]


def _profile_outcome(fact: ProfileAssessmentFact) -> ControlEffect | FailureEffect:
    code = fact.explanation_code
    if fact.retained_verdict in {Verdict.BLOCK, Verdict.CONFLICT}:
        if fact.retained_route.kind is not CoreRouteKind.BLOCK:
            raise TrustedFactError("non-permissive profile result requires a block route")
        return FailureEffect(verdict="block", route=fact.retained_route, code=code)
    if fact.retained_verdict is Verdict.ROUTE:
        if fact.retained_route.kind in {
            CoreRouteKind.BLOCK,
            CoreRouteKind.CONTINUE,
            CoreRouteKind.RECORD_ONLY,
        }:
            raise TrustedFactError("profile route result requires an exact alternate route")
        return FailureEffect(verdict="route", route=fact.retained_route, code=code)
    if fact.retained_verdict is Verdict.REQUIRE_APPROVAL:
        return FailureEffect(verdict="require_approval", route=None, code=code)
    if fact.retained_route.kind is CoreRouteKind.BLOCK:
        raise TrustedFactError("permissive profile result cannot select a block route")
    permissive_verdict = cast(
        Literal["allow", "allow_with_conditions"], fact.retained_verdict.value
    )
    return ControlEffect(
        verdict=permissive_verdict,
        route=fact.retained_route,
        requirements=(),
        conditions=(),
        code=code,
    )


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")


def _actor_lineage_ids(intent: ActionIntent) -> set[str]:
    return {
        intent.actor.actor_id,
        *(reference.object_id for reference in intent.actor.lineage_refs),
    }


def _approver_lineage_ids(fact: ApprovalFact) -> set[str]:
    return {
        fact.approver.actor_id,
        *(reference.object_id for reference in fact.approver.lineage_refs),
    }


def _related(intent: ActionIntent, fact: ApprovalFact) -> bool:
    return bool(_actor_lineage_ids(intent) & _approver_lineage_ids(fact))


def _approval_matches(
    requirement: ApprovalRequirement,
    fact: ApprovalFact,
    *,
    intent: ActionIntent,
    facts: EvaluationFacts,
    observed_at: str,
) -> bool:
    if not verify_fact(fact):
        raise TrustedFactError("approval fact digest is invalid")
    expected_scope = sha256_digest(canonical_json(requirement.scope))
    return bool(
        facts.approval_basis_ref is not None
        and fact.basis_decision_ref == facts.approval_basis_ref
        and fact.intent_ref.namespace == intent.namespace
        and fact.intent_ref.intent_id == intent.intent_id
        and fact.intent_ref.intent_digest == intent.intent_digest
        and fact.requirement_id == requirement.requirement_id
        and fact.scope_digest == expected_scope
        and requirement.role in fact.roles
        and fact.approved
        and _instant(fact.valid_from) <= _instant(observed_at) < _instant(fact.valid_until)
        and fact.authority_ref.digest is not None
    )


def _independence_fails(
    requirement: ApprovalRequirement,
    fact: ApprovalFact,
    intent: ActionIntent,
) -> bool:
    if not (requirement.separate_from_actor or requirement.separate_from_roles):
        return False
    if not fact.lineage_complete:
        return True
    if any(role not in fact.separated_role_actor_ids for role in requirement.separate_from_roles):
        return True
    if requirement.separate_from_actor and _related(intent, fact):
        return True
    approver_ids = _approver_lineage_ids(fact)
    return any(
        approver_ids & set(fact.separated_role_actor_ids.get(role, ()))
        for role in requirement.separate_from_roles
    )


def _condition_result(
    condition: object,
    intent: ActionIntent,
    supported_registry: frozenset[str],
) -> tuple[ConditionResult, FailureEffect | None]:
    from assurance.controlspec.contracts import Condition

    assert isinstance(condition, Condition)
    result = PredicateResult.UNKNOWN
    if condition.verifier in supported_registry and condition.verifier == CORE_PREDICATE_VERIFIER:
        raw = condition.parameters.get(CORE_PREDICATE_PARAMETER)
        try:
            predicate = Predicate.model_validate(raw, strict=False)
            result = evaluate_predicate(predicate, evaluation_document(intent))
        except (ValidationError, ValueError, TypeError):
            result = PredicateResult.UNKNOWN
    status = cast(
        Literal["satisfied", "outstanding", "failed", "unknown"],
        {
            PredicateResult.TRUE: "satisfied",
            PredicateResult.FALSE: "failed",
            PredicateResult.UNKNOWN: "unknown",
        }[result],
    )
    return (
        ConditionResult(
            condition_id=condition.condition_id,
            status=status,
            code=(
                "controlspec.core.condition.satisfied"
                if result is PredicateResult.TRUE
                else condition.failure.code
            ),
        ),
        None if result is PredicateResult.TRUE else condition.failure,
    )


def assess_requirements(
    outcomes: tuple[AppliedControlOutcome, ...],
    *,
    intent: ActionIntent,
    snapshot: PublishedControlSnapshot,
    facts: EvaluationFacts,
    verifier_registry: frozenset[str],
) -> RequirementAssessment:
    all_facts: tuple[FactT, ...] = (
        *facts.approvals,
        *facts.evidence,
        *facts.profile_assessments,
    )
    for fact in all_facts:
        if not verify_fact(fact):
            raise TrustedFactError("trusted fact digest is invalid")
    failures: list[tuple[ControlRef, FailureEffect, NamespacedValue]] = []
    approvals: list[ApprovalRequirement] = []
    evidence: list[EvidenceRequirement] = []
    conditions: list[ConditionResult] = []
    codes: list[NamespacedValue] = []
    profile_outcomes: list[ControlEffect | FailureEffect] = []
    independence_failed = False
    for selected in outcomes:
        if not isinstance(selected.outcome, ControlEffect):
            continue
        for condition in selected.outcome.conditions:
            result, failure = _condition_result(condition, intent, verifier_registry)
            conditions.append(result)
            if failure is not None:
                failures.append((selected.control_ref, failure, result.code))
                codes.append(result.code)
        for requirement in selected.outcome.requirements:
            if isinstance(requirement, EvidenceRequirement):
                evidence.append(requirement)
                continue
            if isinstance(requirement, ApprovalRequirement):
                approvals.append(requirement)
                matching = [
                    fact
                    for fact in facts.approvals
                    if _approval_matches(
                        requirement,
                        fact,
                        intent=intent,
                        facts=facts,
                        observed_at=snapshot.observed_at,
                    )
                ]
                if any(_independence_fails(requirement, fact, intent) for fact in matching):
                    independence_failed = True
                    codes.append("controlspec.core.approval.independence_failed")
                independent = [
                    fact for fact in matching if not _independence_fails(requirement, fact, intent)
                ]
                if len(independent) < requirement.minimum_count:
                    failures.append(
                        (selected.control_ref, requirement.failure, requirement.failure.code)
                    )
                    codes.append(requirement.failure.code)
                continue
            assert isinstance(requirement, ProfileRequirement)
            if requirement.verifier not in verifier_registry:
                failures.append(
                    (selected.control_ref, requirement.failure, requirement.failure.code)
                )
                codes.append(requirement.failure.code)
                continue
            matching_profile = [
                fact
                for fact in facts.profile_assessments
                if fact.verifier == requirement.verifier
                and fact.intent_ref.namespace == intent.namespace
                and fact.intent_ref.intent_id == intent.intent_id
                and fact.intent_ref.intent_digest == intent.intent_digest
                and fact.control_ref == selected.control_ref
                and fact.snapshot_digest == snapshot.snapshot_digest
            ]
            if not matching_profile or any(
                fact.status is not ProfileAssessmentStatus.SATISFIED
                for fact in matching_profile
            ):
                failures.append(
                    (selected.control_ref, requirement.failure, requirement.failure.code)
                )
                codes.append(requirement.failure.code)
            else:
                for fact in matching_profile:
                    profile_outcomes.append(_profile_outcome(fact))
                    approvals.extend(fact.retained_approval_requirements)
                    evidence.extend(fact.retained_evidence_requirements)
                    codes.append(fact.explanation_code)
    return RequirementAssessment(
        failures=tuple(failures),
        approval_requirements=tuple(approvals),
        evidence_requirements=tuple(evidence),
        condition_results=tuple(conditions),
        explanation_codes=tuple(codes),
        independence_failed=independence_failed,
        profile_outcomes=tuple(profile_outcomes),
    )
