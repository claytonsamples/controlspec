"""Pure orchestration for deterministic portable ControlSpec evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from assurance.contracts.canonical import canonical_json, sha256_digest
from assurance.controlspec.canonical import finalize_object, verify_object_digest
from assurance.controlspec.composition import CompositionResult, compose
from assurance.controlspec.contracts import (
    ActionIntent,
    ActorRef,
    Decision,
    DecisionBinding,
    EvaluatorBinding,
    IntentRef,
    JsonValue,
    ResourceRef,
)
from assurance.controlspec.facts import (
    EvaluationFacts,
    EvaluationTrace,
    PublishedControlSnapshot,
    SnapshotAuthorityMode,
    TraceControl,
    facts_digest,
)
from assurance.controlspec.requirements import assess_requirements
from assurance.controlspec.selection import select_controls

EVALUATOR_NAME = "controlspec.core"
EVALUATOR_VERSION = "0.1.0"
CONFORMANCE_EXTENSION = "controlspec.conformance.non_authoritative"


class EvaluationInputError(ValueError):
    """An exact trusted input or digest is invalid."""


@dataclass(frozen=True)
class EvaluationResult:
    decision: Decision
    trace: EvaluationTrace


def _timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")


class ControlSpecEvaluator:
    def __init__(
        self,
        *,
        verifier_registry: frozenset[str] = frozenset(),
        decision_ttl_seconds: int = 300,
    ) -> None:
        if decision_ttl_seconds <= 0:
            raise ValueError("decision TTL must be positive")
        self._verifier_registry = verifier_registry
        self._decision_ttl_seconds = decision_ttl_seconds

    def evaluate(
        self,
        *,
        intent: ActionIntent,
        snapshot: PublishedControlSnapshot,
        facts: EvaluationFacts,
    ) -> EvaluationResult:
        if intent.intent_digest is None or not verify_object_digest(intent):
            raise EvaluationInputError("ActionIntent digest is invalid")
        outcomes = select_controls(intent, snapshot)
        assessment = assess_requirements(
            outcomes,
            intent=intent,
            snapshot=snapshot,
            facts=facts,
            verifier_registry=self._verifier_registry,
        )
        composed = compose(outcomes, assessment)
        decision = self._decision(
            intent=intent,
            snapshot=snapshot,
            facts=facts,
            composed=composed,
        )
        assert snapshot.snapshot_digest is not None
        fact_binding = facts_digest(facts)
        trace = EvaluationTrace(
            snapshot_digest=snapshot.snapshot_digest,
            facts_digest=fact_binding,
            evaluated_controls=tuple(
                TraceControl(
                    control_ref=item.control_ref,
                    selection=("unknown_failure" if item.used_unknown_failure else "effect"),
                    predicate_results=tuple(result.value for result in item.predicate_results),
                    emitted_code=item.outcome.code,
                )
                for item in outcomes
            ),
            final_verdict=composed.verdict,
            final_route=composed.route,
            explanation_codes=composed.explanation_codes,
        )
        return EvaluationResult(decision=decision, trace=trace)

    def _decision(
        self,
        *,
        intent: ActionIntent,
        snapshot: PublishedControlSnapshot,
        facts: EvaluationFacts,
        composed: CompositionResult,
    ) -> Decision:
        assert intent.intent_digest is not None
        assert snapshot.snapshot_digest is not None
        intent_reference = IntentRef(
            namespace=intent.namespace,
            intent_id=intent.intent_id,
            intent_digest=intent.intent_digest,
        )
        control_set_digest = sha256_digest(canonical_json(composed.applied_controls))
        fact_binding = facts_digest(facts)
        envelope = {
            "intent_ref": intent_reference,
            "snapshot_digest": snapshot.snapshot_digest,
            "facts_digest": fact_binding,
            "applied_controls": composed.applied_controls,
            "verdict": composed.verdict,
            "route": composed.route,
            "evaluated_at": snapshot.observed_at,
            "evaluator": {"name": EVALUATOR_NAME, "version": EVALUATOR_VERSION},
        }
        decision_identity = sha256_digest(canonical_json(envelope)).removeprefix("sha256:")
        extensions: dict[str, JsonValue] = (
            {CONFORMANCE_EXTENSION: True}
            if snapshot.authority_mode is SnapshotAuthorityMode.NON_AUTHORITATIVE_CONFORMANCE
            else {}
        )
        value = Decision(
            schema="controlspec/v0/decision",
            namespace=intent.namespace,
            decision_id=f"decision-{decision_identity}",
            intent_ref=intent_reference,
            evaluated_at=snapshot.observed_at,
            expires_at=_timestamp(
                _instant(snapshot.observed_at) + timedelta(seconds=self._decision_ttl_seconds)
            ),
            predecessor_decision_ref=facts.approval_basis_ref,
            verdict=composed.verdict,
            route=composed.route,
            conditions=composed.conditions,
            approval_requirements=composed.approval_requirements,
            required_evidence=composed.required_evidence,
            applied_controls=composed.applied_controls,
            explanation_codes=composed.explanation_codes,
            binding=DecisionBinding(
                actor_ref=ActorRef(
                    namespace=intent.actor.namespace,
                    actor_id=intent.actor.actor_id,
                    version=intent.actor.version,
                ),
                action_type=intent.action.type,
                domain_action=intent.action.domain_action,
                resource_ref=ResourceRef(
                    namespace=intent.resource.namespace,
                    resource_id=intent.resource.resource_id,
                    version=intent.resource.version,
                    type=intent.resource.type,
                ),
                context_digest=intent.context_digest,
                intent_digest=intent.intent_digest,
                control_set_digest=control_set_digest,
                evaluator=EvaluatorBinding(
                    name=EVALUATOR_NAME,
                    version=EVALUATOR_VERSION,
                ),
            ),
            requires_recheck=composed.requires_recheck,
            extensions=extensions,
        )
        return finalize_object(value)
