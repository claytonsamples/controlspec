"""Pure system-derived receipt assurance with no ledger or external effects."""

from __future__ import annotations

from datetime import datetime

from assurance.contracts.canonical import canonical_json, sha256_digest
from assurance.controlspec.canonical import finalize_object, verify_object_digest
from assurance.controlspec.contracts import (
    ActionIntent,
    Decision,
    DecisionRef,
    EvidenceRef,
    ExecutionOutcome,
    JsonValue,
    ObjectRef,
    Receipt,
    ReceiptOutcome,
    ReceiptStatus,
    ReportedExecution,
    Verdict,
)
from assurance.controlspec.evaluator import CONFORMANCE_EXTENSION
from assurance.controlspec.facts import (
    EvaluationFacts,
    RecheckResult,
    TrustedExecutionObservation,
    VerifiedEvidenceFact,
    verify_execution,
    verify_fact,
)


class ReceiptAssessmentError(ValueError):
    """The trusted observation cannot be bound to the supplied Decision."""


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")


def _decision_ref(decision: Decision) -> DecisionRef:
    if decision.semantic_digest is None:
        raise ReceiptAssessmentError("Decision requires an exact semantic digest")
    return DecisionRef(
        namespace=decision.namespace,
        decision_id=decision.decision_id,
        semantic_digest=decision.semantic_digest,
    )


def _evidence_matches(
    fact: VerifiedEvidenceFact,
    *,
    requirement: object,
    intent: ActionIntent,
    recorded_at: str,
) -> bool:
    from assurance.controlspec.contracts import EvidenceRequirement

    assert isinstance(requirement, EvidenceRequirement)
    if not verify_fact(fact):
        raise ReceiptAssessmentError("verified evidence fact digest is invalid")
    if (
        fact.intent_ref.namespace != intent.namespace
        or fact.intent_ref.intent_id != intent.intent_id
        or fact.intent_ref.intent_digest != intent.intent_digest
        or fact.evidence_ref.namespace != intent.namespace
        or fact.evidence_ref.kind != fact.kind
        or fact.kind != requirement.kind
        or fact.subject != requirement.subject
        or _instant(fact.verified_at) > _instant(recorded_at)
    ):
        return False
    if requirement.max_age_seconds is not None:
        age = (_instant(recorded_at) - _instant(fact.verified_at)).total_seconds()
        if age > requirement.max_age_seconds:
            return False
    actor_lineage = {
        intent.actor.actor_id,
        *(reference.object_id for reference in intent.actor.lineage_refs),
    }
    producer_lineage = {fact.producer_actor_id, *fact.producer_lineage_ids}
    certifier_lineage = {fact.certifier_actor_id, *fact.certifier_lineage_ids}
    if requirement.separation.producer_not_actor and (
        not fact.producer_lineage_complete or actor_lineage & producer_lineage
    ):
        return False
    if requirement.separation.certifier_not_actor and (
        not fact.certifier_lineage_complete or actor_lineage & certifier_lineage
    ):
        return False
    return not (
        requirement.separation.producer_certifier_distinct
        and (
            not fact.producer_lineage_complete
            or not fact.certifier_lineage_complete
            or producer_lineage & certifier_lineage
        )
    )


def assess_receipt(
    *,
    decision: Decision,
    intent: ActionIntent,
    recheck_result: RecheckResult,
    facts: EvaluationFacts,
    observation: TrustedExecutionObservation,
    reported_execution: ReportedExecution,
    sequence: int = 1,
    predecessor_receipt_ref: ObjectRef | None = None,
) -> Receipt:
    if decision.semantic_digest is None or not verify_object_digest(decision):
        raise ReceiptAssessmentError("Decision semantic digest is invalid")
    if not verify_execution(observation):
        raise ReceiptAssessmentError("execution observation digest is invalid")
    exact_decision_ref = _decision_ref(decision)
    if recheck_result.prior_decision_ref != exact_decision_ref:
        raise ReceiptAssessmentError("recheck does not bind the exact Decision")
    if (
        decision.intent_ref.namespace != intent.namespace
        or decision.intent_ref.intent_id != intent.intent_id
        or decision.intent_ref.intent_digest != intent.intent_digest
    ):
        raise ReceiptAssessmentError("Decision does not bind the exact intent")
    if not (
        _instant(decision.evaluated_at)
        <= _instant(observation.occurred_at)
        < _instant(decision.expires_at)
    ):
        raise ReceiptAssessmentError("execution occurred outside the Decision window")
    if _instant(observation.recorded_at) < _instant(observation.occurred_at):
        raise ReceiptAssessmentError("execution cannot be recorded before it occurred")
    missing: list[str] = []
    verified: list[EvidenceRef] = []
    for requirement in decision.required_evidence:
        matching = [
            fact
            for fact in facts.evidence
            if _evidence_matches(
                fact,
                requirement=requirement,
                intent=intent,
                recorded_at=observation.recorded_at,
            )
        ]
        if len(matching) < requirement.minimum_count:
            missing.append(requirement.requirement_id)
        verified.extend(fact.evidence_ref for fact in matching)
    permissive = decision.verdict in {
        Verdict.ALLOW,
        Verdict.ALLOW_WITH_CONDITIONS,
    }
    exact_route = observation.actual_route == decision.route
    succeeded = observation.execution_outcome == "succeeded"
    if not recheck_result.valid or not permissive or not exact_route:
        status = ReceiptStatus.FAILED
        outcome = (
            ReceiptOutcome.BLOCKED
            if decision.verdict in {Verdict.BLOCK, Verdict.CONFLICT}
            else ReceiptOutcome.FAILED
        )
    elif missing:
        status = ReceiptStatus.INCOMPLETE
        outcome = ReceiptOutcome.INCOMPLETE
    elif not succeeded:
        status = ReceiptStatus.FAILED
        outcome = ReceiptOutcome.FAILED
    else:
        status = ReceiptStatus.COMPLETE
        outcome = ReceiptOutcome.COMPLETED
    execution_outcome = ExecutionOutcome(observation.execution_outcome)
    envelope = {
        "decision_ref": exact_decision_ref,
        "intent_ref": decision.intent_ref,
        "observation_digest": observation.observation_digest,
        "sequence": sequence,
        "predecessor": predecessor_receipt_ref,
    }
    receipt_id = sha256_digest(canonical_json(envelope)).removeprefix("sha256:")
    extensions: dict[str, JsonValue] = (
        {CONFORMANCE_EXTENSION: True}
        if decision.extensions.get(CONFORMANCE_EXTENSION) is True
        else {}
    )
    value = Receipt(
        schema="controlspec/v0/receipt",
        namespace=decision.namespace,
        receipt_id=f"receipt-{receipt_id}",
        sequence=sequence,
        decision_ref=exact_decision_ref,
        intent_ref=decision.intent_ref,
        actual_route=observation.actual_route,
        reported_execution=reported_execution,
        verified_evidence_refs=tuple(verified),
        missing_evidence_requirement_ids=tuple(missing),
        execution_outcome=execution_outcome,
        outcome=outcome,
        status=status,
        occurred_at=observation.occurred_at,
        recorded_at=observation.recorded_at,
        predecessor_receipt_ref=predecessor_receipt_ref,
        extensions=extensions,
    )
    return finalize_object(value)
