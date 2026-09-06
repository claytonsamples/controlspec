from __future__ import annotations

from assurance.controlspec.contracts import Verdict
from assurance.controlspec.evaluator import ControlSpecEvaluator
from assurance.controlspec.facts import EvaluationFacts
from tests.controlspec.test_t02_facts import control, intent, snapshot


def test_published_control_produces_exact_bound_allow_decision() -> None:
    action = intent()
    policy = control()
    result = ControlSpecEvaluator().evaluate(
        intent=action,
        snapshot=snapshot(policy),
        facts=EvaluationFacts(
            approval_basis_ref=None,
            approvals=(),
            evidence=(),
            profile_assessments=(),
        ),
    )
    assert result.decision.verdict is Verdict.ALLOW
    assert result.decision.binding.actor_ref.actor_id == action.actor.actor_id
    assert result.decision.binding.action_type == action.action.type
    assert result.decision.binding.resource_ref.resource_id == action.resource.resource_id
    assert result.decision.binding.context_digest == action.context_digest
    assert result.decision.binding.intent_digest == action.intent_digest
    assert result.decision.semantic_digest is not None
