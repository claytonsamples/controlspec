from __future__ import annotations

from assurance.controlspec.evaluator import ControlSpecEvaluator
from assurance.controlspec.facts import EvaluationFacts
from assurance.controlspec.recheck import recheck
from tests.controlspec.test_t02_facts import control, intent, snapshot

EMPTY = EvaluationFacts(
    approval_basis_ref=None,
    approvals=(),
    evidence=(),
    profile_assessments=(),
)


def test_recheck_accepts_only_unchanged_exact_binding() -> None:
    evaluator = ControlSpecEvaluator()
    policy_snapshot = snapshot(control())
    original_intent = intent()
    prior = evaluator.evaluate(
        intent=original_intent,
        snapshot=policy_snapshot,
        facts=EMPTY,
    ).decision
    assert recheck(
        prior=prior,
        intent=original_intent,
        snapshot=policy_snapshot,
        facts=EMPTY,
        evaluator=evaluator,
    ).valid
    changed = intent({"personal.amount_minor": 4300})
    invalid = recheck(
        prior=prior,
        intent=changed,
        snapshot=policy_snapshot,
        facts=EMPTY,
        evaluator=evaluator,
    )
    assert not invalid.valid
    assert invalid.current_decision_ref is not None
