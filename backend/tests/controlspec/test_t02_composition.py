from __future__ import annotations

from assurance.contracts.canonical import canonical_json, sha256_digest
from assurance.controlspec.composition import NO_APPLICABLE_PUBLISHED_CONTROL
from assurance.controlspec.contracts import (
    Actor,
    ApprovalRequirement,
    ControlEffect,
    CoreRouteKind,
    DecisionRef,
    FailureEffect,
    ObjectRef,
    Verdict,
)
from assurance.controlspec.evaluator import CONFORMANCE_EXTENSION, ControlSpecEvaluator
from assurance.controlspec.facts import ApprovalFact, EvaluationFacts, finalize_fact
from tests.controlspec.test_t02_facts import control, digest, intent, route, snapshot

EMPTY_FACTS = EvaluationFacts(
    approval_basis_ref=None,
    approvals=(),
    evidence=(),
    profile_assessments=(),
)


def evaluate(*controls: object):
    return ControlSpecEvaluator().evaluate(
        intent=intent(),
        snapshot=snapshot(*controls),  # type: ignore[arg-type]
        facts=EMPTY_FACTS,
    )


def test_no_published_match_fails_closed_with_public_code() -> None:
    result = evaluate()
    assert result.decision.verdict is Verdict.BLOCK
    assert result.decision.applied_controls == ()
    assert NO_APPLICABLE_PUBLISHED_CONTROL in result.decision.explanation_codes


def test_explicit_block_dominates_allow() -> None:
    block = control(
        control_id="block",
        effect=ControlEffect(
            verdict="block",
            route=route(CoreRouteKind.BLOCK, route_id="blocked"),
            requirements=(),
            conditions=(),
            code="controlspec.core.prohibition",
        ),
    )
    result = evaluate(control(control_id="allow"), block)
    assert result.decision.verdict is Verdict.BLOCK
    assert len(result.decision.applied_controls) == 2


def test_incompatible_mandatory_routes_return_conflict() -> None:
    first = control(
        control_id="first-route",
        effect=ControlEffect(
            verdict="route",
            route=route(CoreRouteKind.HUMAN_REVIEW, route_id="human"),
            requirements=(),
            conditions=(),
            code="controlspec.core.route.human",
        ),
    )
    second = control(
        control_id="second-route",
        effect=ControlEffect(
            verdict="route",
            route=route(CoreRouteKind.ASK_USER, route_id="ask"),
            requirements=(),
            conditions=(),
            code="controlspec.core.route.ask",
        ),
    )
    result = evaluate(first, second)
    assert result.decision.verdict is Verdict.CONFLICT
    assert result.decision.route.kind is CoreRouteKind.BLOCK


def test_decision_is_deterministic_and_conformance_marked() -> None:
    first = evaluate(control())
    second = evaluate(control())
    assert first.decision == second.decision
    assert first.decision.extensions == {CONFORMANCE_EXTENSION: True}


def approval_control():
    requirement = ApprovalRequirement(
        requirement_id="manager-approval",
        role="smb.sales.manager",
        scope={"smb.sales.discount_basis_points": 1500},
        minimum_count=1,
        validity_seconds=3600,
        separate_from_actor=True,
        separate_from_roles=(),
        failure=FailureEffect(
            verdict="require_approval",
            route=None,
            code="smb.sales.manager.required",
        ),
    )
    return control(
        effect=ControlEffect(
            verdict="allow",
            route=route(),
            requirements=(requirement,),
            conditions=(),
            code="smb.sales.discount.controlled",
        )
    )


def _decision_ref(value) -> DecisionRef:
    assert value.semantic_digest is not None
    return DecisionRef(
        namespace=value.namespace,
        decision_id=value.decision_id,
        semantic_digest=value.semantic_digest,
    )


def approval_fact(action, basis, approver: Actor) -> ApprovalFact:
    return finalize_fact(
        ApprovalFact(
            approval_id="approval-1",
            intent_ref=basis.intent_ref,
            basis_decision_ref=_decision_ref(basis),
            requirement_id="manager-approval",
            scope_digest=sha256_digest(
                canonical_json({"smb.sales.discount_basis_points": 1500})
            ),
            approver=approver,
            authority_ref=ObjectRef(
                namespace="smb.sales",
                object_type="smb.sales.authority.manager",
                object_id="manager-grant",
                version="1",
                digest=digest("manager-grant"),
            ),
            roles=("smb.sales.manager",),
            separated_role_actor_ids={},
            lineage_complete=True,
            approved=True,
            valid_from="2026-08-20T11:00:00.000000Z",
            valid_until="2026-08-20T13:00:00.000000Z",
        )
    )


def test_unsatisfied_approval_requires_approval_and_independent_fact_allows() -> None:
    evaluator = ControlSpecEvaluator()
    action = intent()
    policy_snapshot = snapshot(approval_control())
    basis = evaluator.evaluate(
        intent=action,
        snapshot=policy_snapshot,
        facts=EMPTY_FACTS,
    ).decision
    assert basis.verdict is Verdict.REQUIRE_APPROVAL
    manager = action.actor.model_copy(update={"actor_id": "manager-1", "version": "1"})
    approved = evaluator.evaluate(
        intent=action,
        snapshot=policy_snapshot,
        facts=EvaluationFacts(
            approval_basis_ref=_decision_ref(basis),
            approvals=(approval_fact(action, basis, manager),),
            evidence=(),
            profile_assessments=(),
        ),
    ).decision
    assert approved.verdict is Verdict.ALLOW
    assert approved.predecessor_decision_ref == _decision_ref(basis)


def test_direct_self_approval_is_blocked() -> None:
    evaluator = ControlSpecEvaluator()
    action = intent()
    policy_snapshot = snapshot(approval_control())
    basis = evaluator.evaluate(
        intent=action,
        snapshot=policy_snapshot,
        facts=EMPTY_FACTS,
    ).decision
    blocked = evaluator.evaluate(
        intent=action,
        snapshot=policy_snapshot,
        facts=EvaluationFacts(
            approval_basis_ref=_decision_ref(basis),
            approvals=(approval_fact(action, basis, action.actor),),
            evidence=(),
            profile_assessments=(),
        ),
    ).decision
    assert blocked.verdict is Verdict.BLOCK


def test_lineage_related_self_approval_is_blocked() -> None:
    evaluator = ControlSpecEvaluator()
    action = intent()
    policy_snapshot = snapshot(approval_control())
    basis = evaluator.evaluate(
        intent=action,
        snapshot=policy_snapshot,
        facts=EMPTY_FACTS,
    ).decision
    related = action.actor.model_copy(
        update={
            "actor_id": "manager-related",
            "lineage_refs": (
                ObjectRef(
                    namespace=action.namespace,
                    object_type="controlspec.actor.lineage",
                    object_id=action.actor.actor_id,
                    version="1",
                    digest=digest("related-lineage"),
                ),
            ),
        }
    )
    blocked = evaluator.evaluate(
        intent=action,
        snapshot=policy_snapshot,
        facts=EvaluationFacts(
            approval_basis_ref=_decision_ref(basis),
            approvals=(approval_fact(action, basis, related),),
            evidence=(),
            profile_assessments=(),
        ),
    ).decision
    assert blocked.verdict is Verdict.BLOCK


def test_cross_namespace_approval_cannot_authorize_intent() -> None:
    evaluator = ControlSpecEvaluator()
    action = intent()
    policy_snapshot = snapshot(approval_control())
    basis = evaluator.evaluate(
        intent=action, snapshot=policy_snapshot, facts=EMPTY_FACTS
    ).decision
    manager = action.actor.model_copy(update={"actor_id": "manager-1"})
    valid = approval_fact(action, basis, manager)
    rebound = finalize_fact(
        valid.model_copy(
            update={
                "intent_ref": valid.intent_ref.model_copy(
                    update={"namespace": "other.tenant"}
                ),
                "fact_digest": None,
            }
        )
    )
    decision = evaluator.evaluate(
        intent=action,
        snapshot=policy_snapshot,
        facts=EvaluationFacts(
            approval_basis_ref=_decision_ref(basis),
            approvals=(rebound,),
            evidence=(),
            profile_assessments=(),
        ),
    ).decision
    assert decision.verdict is Verdict.REQUIRE_APPROVAL


def test_missing_required_separated_role_population_fails_closed() -> None:
    evaluator = ControlSpecEvaluator()
    action = intent()
    base = approval_control()
    requirement = base.effect.requirements[0].model_copy(
        update={"separate_from_roles": ("smb.sales.proposer",)}
    )
    separated = base.model_copy(
        update={
            "effect": base.effect.model_copy(update={"requirements": (requirement,)}),
            "semantic_digest": None,
        }
    )
    from assurance.controlspec.canonical import finalize_object

    separated = finalize_object(separated)
    policy_snapshot = snapshot(separated)
    basis = evaluator.evaluate(
        intent=action, snapshot=policy_snapshot, facts=EMPTY_FACTS
    ).decision
    manager = action.actor.model_copy(update={"actor_id": "manager-1"})
    missing_population = approval_fact(action, basis, manager)
    decision = evaluator.evaluate(
        intent=action,
        snapshot=policy_snapshot,
        facts=EvaluationFacts(
            approval_basis_ref=_decision_ref(basis),
            approvals=(missing_population,),
            evidence=(),
            profile_assessments=(),
        ),
    ).decision
    assert decision.verdict is Verdict.BLOCK
