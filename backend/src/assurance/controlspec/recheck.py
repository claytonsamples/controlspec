"""Pure exact-binding recheck; never issues replacement authority."""

from __future__ import annotations

from datetime import datetime

from assurance.controlspec.contracts import ActionIntent, Decision, DecisionRef
from assurance.controlspec.evaluator import ControlSpecEvaluator
from assurance.controlspec.facts import (
    EvaluationFacts,
    PublishedControlSnapshot,
    RecheckResult,
)


def _ref(value: Decision) -> DecisionRef:
    assert value.semantic_digest is not None
    return DecisionRef(
        namespace=value.namespace,
        decision_id=value.decision_id,
        semantic_digest=value.semantic_digest,
    )


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")


def recheck(
    *,
    prior: Decision,
    intent: ActionIntent,
    snapshot: PublishedControlSnapshot,
    facts: EvaluationFacts,
    evaluator: ControlSpecEvaluator,
) -> RecheckResult:
    prior_ref = _ref(prior)
    if _instant(snapshot.observed_at) >= _instant(prior.expires_at):
        return RecheckResult(
            valid=False,
            prior_decision_ref=prior_ref,
            reason_code="controlspec.core.recheck.expired",
            current_decision_ref=None,
        )
    try:
        current = evaluator.evaluate(intent=intent, snapshot=snapshot, facts=facts).decision
    except ValueError:
        return RecheckResult(
            valid=False,
            prior_decision_ref=prior_ref,
            reason_code="controlspec.core.recheck.input_invalid",
            current_decision_ref=None,
        )
    current_ref = _ref(current)
    if current != prior:
        if current.binding.intent_digest != prior.binding.intent_digest:
            reason = "controlspec.core.recheck.intent_changed"
        elif current.applied_controls != prior.applied_controls:
            reason = "controlspec.core.recheck.controls_changed"
        elif current.binding.context_digest != prior.binding.context_digest:
            reason = "controlspec.core.recheck.context_changed"
        else:
            reason = "controlspec.core.recheck.semantic_input_changed"
        return RecheckResult(
            valid=False,
            prior_decision_ref=prior_ref,
            reason_code=reason,
            current_decision_ref=current_ref,
        )
    return RecheckResult(
        valid=True,
        prior_decision_ref=prior_ref,
        reason_code="controlspec.core.recheck.valid",
        current_decision_ref=current_ref,
    )
