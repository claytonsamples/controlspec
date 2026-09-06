"""Exact, read-only RiskSpec compatibility assessment.

This leaf module is the only T02 evaluator component allowed to understand the
RiskSpec enterprise projection.  It validates retained T01 source material and
can only attest to a portable outcome that is identical to an already-derived
RiskSpec decision.  It creates no authority and performs no writes.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from assurance.contracts.canonical import canonical_json, sha256_digest
from assurance.contracts.objects import ControlDecision as RiskDecision
from assurance.contracts.policy import (
    ApprovalRequirement as RiskApprovalRequirement,
)
from assurance.contracts.policy import (
    BlockEffect,
    PostActionVerificationCondition,
    RequireApprovalEffect,
    Rule,
    SwitchRouteEffect,
)
from assurance.controlspec.canonical import verify_object_digest
from assurance.controlspec.contracts import (
    ActionIntent,
    ApprovalRequirement,
    Control,
    ControlEffect,
    Decision,
    EvidenceRequirement,
    EvidenceSeparation,
    FailureEffect,
)
from assurance.controlspec.facts import (
    ProfileAssessmentFact,
    ProfileAssessmentStatus,
    PublishedControlSnapshot,
    finalize_fact,
)
from assurance.controlspec.mapping import (
    D001_VERIFIER,
    SOURCE_EXTENSION,
    ExactRiskSpecMappingResult,
    control_ref,
    intent_ref,
    project_decision,
    project_route,
)

ADVANCE_SUPPLIER = "riskspec.enterprise.action.advance_supplier"
ACTIVATE_SUPPLIER = "riskspec.enterprise.action.activate_supplier"


class RiskSpecProfileError(ValueError):
    """The supplied enterprise projection is not an exact retained mapping."""


def _failure_effect(
    source: BlockEffect | RequireApprovalEffect | SwitchRouteEffect,
    control: Control,
) -> FailureEffect:
    if isinstance(source, RequireApprovalEffect):
        return FailureEffect(
            verdict="require_approval",
            route=None,
            code="riskspec.enterprise.requirement.approval_required",
        )
    if isinstance(source, SwitchRouteEffect) and len(source.target_routes) == 1:
        return FailureEffect(
            verdict="route",
            route=project_route(source.target_routes[0]),
            code="riskspec.enterprise.requirement.route_required",
        )
    block_route = control.on_unknown.route
    if block_route is None:
        raise RiskSpecProfileError("RiskSpec control lacks its fail-closed block route")
    return FailureEffect(
        verdict="block",
        route=block_route,
        code="riskspec.enterprise.requirement.blocked",
    )


def _retained_requirements(
    rule: Rule,
    control: Control,
) -> tuple[tuple[ApprovalRequirement, ...], tuple[EvidenceRequirement, ...]]:
    approvals: list[ApprovalRequirement] = []
    evidence: list[EvidenceRequirement] = []
    for requirement in rule.requirements:
        if isinstance(requirement, RiskApprovalRequirement):
            approvals.append(
                ApprovalRequirement(
                    requirement_id=requirement.control_key,
                    role=f"riskspec.enterprise.role.{requirement.role.value.lower()}",
                    scope={
                        "riskspec.enterprise.scope_key": requirement.scope_key,
                    },
                    minimum_count=requirement.minimum_count,
                    validity_seconds=requirement.validity_seconds,
                    separate_from_actor=any(
                        item.value == "ACTOR" for item in requirement.separate_from
                    ),
                    separate_from_roles=tuple(
                        f"riskspec.enterprise.subject_role.{item.value.lower()}"
                        for item in requirement.separate_from
                        if item.value != "ACTOR"
                    ),
                    failure=_failure_effect(requirement.failure_effect, control),
                )
            )
    for condition in rule.conditions:
        if isinstance(condition, PostActionVerificationCondition):
            evidence.append(
                EvidenceRequirement(
                    requirement_id=condition.control_key,
                    kind=f"riskspec.enterprise.evidence.{condition.evidence_kind.value.lower()}",
                    subject="riskspec.enterprise.subject.execution",
                    minimum_count=1,
                    max_age_seconds=None,
                    verifier="riskspec.enterprise.verifier.post_action_evidence",
                    separation=EvidenceSeparation(
                        producer_not_actor=False,
                        certifier_not_actor=False,
                        producer_certifier_distinct=True,
                    ),
                    failure=_failure_effect(BlockEffect(), control),
                )
            )
    return tuple(approvals), tuple(evidence)


def _retained_source(projected: ActionIntent | Control | Decision) -> dict[str, Any]:
    try:
        result = ExactRiskSpecMappingResult.model_validate(projected.extensions[SOURCE_EXTENSION])
        source = json.loads(result.canonical_json)
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        raise RiskSpecProfileError("exact retained RiskSpec source is required") from exc
    if not isinstance(source, dict):
        raise RiskSpecProfileError("retained RiskSpec source must be an object")
    encoded = canonical_json(source)
    if result.canonical_json.encode() != encoded or result.digest != sha256_digest(encoded):
        raise RiskSpecProfileError("retained RiskSpec source is not canonical and hash-bound")
    return source


class RiskSpecProfileResolver:
    """Validate an exact T01 projection without reinterpreting its semantics."""

    verifier = D001_VERIFIER

    def assess(
        self,
        *,
        intent: ActionIntent,
        control: Control,
        snapshot: PublishedControlSnapshot,
        retained_decision: Decision,
    ) -> ProfileAssessmentFact:
        if intent.action.domain_action == ACTIVATE_SUPPLIER:
            raise RiskSpecProfileError("ACTIVATE_SUPPLIER is outside the truthful v1.1 profile")
        if intent.action.domain_action != ADVANCE_SUPPLIER:
            raise RiskSpecProfileError("only ADVANCE_SUPPLIER is supported")
        if (
            intent.intent_digest is None
            or control.semantic_digest is None
            or retained_decision.semantic_digest is None
            or snapshot.snapshot_digest is None
            or not verify_object_digest(intent)
            or not verify_object_digest(control)
            or not verify_object_digest(retained_decision)
        ):
            raise RiskSpecProfileError("all projected objects require valid exact digests")
        _retained_source(intent)
        retained_control = _retained_source(control)
        retained_decision_source = _retained_source(retained_decision)
        if control not in snapshot.controls:
            raise RiskSpecProfileError("control is not a member of the exact snapshot")
        if retained_decision.intent_ref != intent_ref(intent):
            raise RiskSpecProfileError("retained decision does not bind the supplied intent")
        if control_ref(control) not in retained_decision.applied_controls:
            raise RiskSpecProfileError("retained decision does not bind the supplied control")
        if not isinstance(control.effect, ControlEffect):
            raise RiskSpecProfileError("RiskSpec projection must carry a complete rule effect")
        source_rule = retained_control.get("rule")
        source_spec = retained_control.get("risk_spec")
        if not isinstance(source_rule, dict) or not isinstance(source_spec, dict):
            raise RiskSpecProfileError("retained projection lacks exact rule and spec source")
        try:
            rule = Rule.model_validate(source_rule)
        except ValidationError as exc:
            raise RiskSpecProfileError("retained RiskSpec rule is invalid") from exc
        try:
            source_decision = RiskDecision.model_validate(retained_decision_source)
            exact_controls = tuple(
                candidate
                for candidate in snapshot.controls
                if control_ref(candidate) in retained_decision.applied_controls
            )
            reconstructed = project_decision(
                source_decision,
                intent=intent,
                controls=exact_controls,
                route=retained_decision.route,
            )
        except (ValidationError, ValueError) as exc:
            raise RiskSpecProfileError(
                "retained RiskSpec decision cannot be exactly reconstructed"
            ) from exc
        if reconstructed != retained_decision:
            raise RiskSpecProfileError(
                "portable decision differs from its exact retained RiskSpec source"
            )

        assert snapshot.snapshot_digest is not None
        approvals, evidence = _retained_requirements(rule, control)
        return finalize_fact(
            ProfileAssessmentFact(
                verifier=D001_VERIFIER,
                intent_ref=intent_ref(intent),
                control_ref=control_ref(control),
                snapshot_digest=snapshot.snapshot_digest,
                status=ProfileAssessmentStatus.SATISFIED,
                retained_verdict=retained_decision.verdict,
                retained_route=retained_decision.route,
                explanation_code="riskspec.enterprise.profile.exact_match",
                retained_approval_requirements=approvals,
                retained_evidence_requirements=evidence,
            )
        )
