from __future__ import annotations

import json
from itertools import permutations
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from assurance.contracts.canonical import canonical_json
from assurance.controlspec.canonical import finalize_object
from assurance.controlspec.composition import NO_APPLICABLE_PUBLISHED_CONTROL
from assurance.controlspec.conformance import (
    ConformanceVector,
    RecheckMutation,
    finalize_vector,
    load_vector,
    run_directory,
    run_vector,
)
from assurance.controlspec.contracts import (
    Amount,
    ControlEffect,
    ControlStatus,
    CoreRouteKind,
    DecisionRef,
    Predicate,
    ReceiptStatus,
    ReportedExecution,
    Verdict,
)
from assurance.controlspec.evaluator import ControlSpecEvaluator
from assurance.controlspec.facts import EvaluationFacts, finalize_snapshot
from assurance.controlspec.receipt import assess_receipt
from assurance.controlspec.recheck import recheck
from tests.controlspec.test_t02_composition import approval_control, approval_fact
from tests.controlspec.test_t02_facts import control, digest, intent, route, snapshot
from tests.controlspec.test_t02_receipts import evidence_control, observation

EMPTY = EvaluationFacts(
    approval_basis_ref=None,
    approvals=(),
    evidence=(),
    profile_assessments=(),
)


def test_change_local_conformance_catalog_is_canonical_and_complete() -> None:
    root = (
        Path(__file__).parents[3]
        / "changes/0005-controlspec-open-standard-reframe/conformance/controlspec-v0"
    )
    schema = json.loads((root / "vector.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    cases = []
    for path in sorted((root / "vectors").glob("*.json")):
        data = path.read_bytes()
        parsed = json.loads(data)
        validator.validate(parsed)
        assert canonical_json(parsed) == data
        assert parsed["authority_mode"] == "non_authoritative_conformance"
        cases.append(parsed["case_id"])
    assert cases == [f"CS-CF-{index:03d}" for index in range(1, 13)]
    assert all(item.passed for item in run_directory(root / "vectors"))
    for path in sorted((root / "packs").glob("*.json")):
        data = path.read_bytes()
        parsed = json.loads(data)
        assert canonical_json(parsed) == data.rstrip(b"\r\n")
        assert parsed["authority_mode"] == "non_authoritative_conformance"
        assert parsed["fixture_publication"] != "production"


def _vector(case_id: str, controls, expected: Verdict, code: str) -> ConformanceVector:
    return finalize_vector(
        ConformanceVector(
            case_id=case_id,
            authority_mode="non_authoritative_conformance",
            operation="evaluate",
            intent=intent(),
            controls=controls,
            trusted_time="2026-08-20T12:00:00.000000Z",
            supported_extensions=(),
            display_extensions=(),
            supported_verifiers=(),
            facts=EMPTY,
            expected_verdict=expected,
            expected_route_kind=(
                CoreRouteKind.BLOCK
                if expected in {Verdict.BLOCK, Verdict.CONFLICT}
                else CoreRouteKind.CONTINUE
            ),
            required_explanation_codes=(code,),
            forbidden_verdicts=(() if expected is Verdict.ALLOW else (Verdict.ALLOW,)),
        )
    )


def core_vectors() -> tuple[ConformanceVector, ...]:
    evaluator = ControlSpecEvaluator()
    action = intent()
    published = control()
    draft = control(status=ControlStatus.DRAFT)
    guarded = control(
        predicates=(
            Predicate(
                operator="lte",
                path="/context/personal.amount_minor",
                value=7500,
            ),
        )
    )
    block = control(
        control_id="prohibition",
        effect=ControlEffect(
            verdict="block",
            route=route(CoreRouteKind.BLOCK, route_id="prohibited"),
            requirements=(),
            conditions=(),
            code="controlspec.core.prohibition",
        ),
    )
    approval = approval_control()
    approval_snapshot = snapshot(approval)
    basis = evaluator.evaluate(intent=action, snapshot=approval_snapshot, facts=EMPTY).decision
    self_approval = approval_fact(action, basis, action.actor)
    self_facts = EvaluationFacts(
        approval_basis_ref=self_approval.basis_decision_ref,
        approvals=(self_approval,),
        evidence=(),
        profile_assessments=(),
    )
    human = control(
        control_id="human",
        effect=ControlEffect(
            verdict="route",
            route=route(CoreRouteKind.HUMAN_REVIEW, route_id="human"),
            requirements=(),
            conditions=(),
            code="controlspec.core.route.human",
        ),
    )
    ask = control(
        control_id="ask",
        effect=ControlEffect(
            verdict="route",
            route=route(CoreRouteKind.ASK_USER, route_id="ask"),
            requirements=(),
            conditions=(),
            code="controlspec.core.route.ask",
        ),
    )
    evidence = evidence_control()
    changed = intent({"personal.amount_minor": 4300})

    def changed_intent(**updates):
        return finalize_object(
            action.model_copy(update={**updates, "intent_digest": None})
        )

    mutation_facts = EvaluationFacts(
        approval_basis_ref=DecisionRef(
            namespace=action.namespace,
            decision_id="mutated-fact-basis",
            semantic_digest=digest("mutated-fact-basis"),
        ),
        approvals=(),
        evidence=(),
        profile_assessments=(),
    )
    mutation_cases = (
        RecheckMutation(
            mutation_id="controlspec.conformance.mutation.actor",
            intent=changed_intent(
                actor=action.actor.model_copy(update={"actor_id": "agent-mutated"})
            ),
            controls=(published,),
            trusted_time="2026-08-20T12:00:00.000000Z",
            facts=EMPTY,
        ),
        RecheckMutation(
            mutation_id="controlspec.conformance.mutation.action",
            intent=changed_intent(
                action=action.action.model_copy(
                    update={"domain_action": "personal.purchase_mutated"}
                )
            ),
            controls=(published,),
            trusted_time="2026-08-20T12:00:00.000000Z",
            facts=EMPTY,
        ),
        RecheckMutation(
            mutation_id="controlspec.conformance.mutation.resource",
            intent=changed_intent(
                resource=action.resource.model_copy(update={"resource_id": "cart-mutated"})
            ),
            controls=(published,),
            trusted_time="2026-08-20T12:00:00.000000Z",
            facts=EMPTY,
        ),
        RecheckMutation(
            mutation_id="controlspec.conformance.mutation.context",
            intent=changed,
            controls=(published,),
            trusted_time="2026-08-20T12:00:00.000000Z",
            facts=EMPTY,
        ),
        RecheckMutation(
            mutation_id="controlspec.conformance.mutation.control",
            intent=action,
            controls=(control(control_id="mutated-control"),),
            trusted_time="2026-08-20T12:00:00.000000Z",
            facts=EMPTY,
        ),
        RecheckMutation(
            mutation_id="controlspec.conformance.mutation.fact",
            intent=action,
            controls=(published,),
            trusted_time="2026-08-20T12:00:00.000000Z",
            facts=mutation_facts,
        ),
        RecheckMutation(
            mutation_id="controlspec.conformance.mutation.time",
            intent=action,
            controls=(published,),
            trusted_time="2026-08-20T12:01:00.000000Z",
            facts=EMPTY,
        ),
    )
    ordered_controls = (control(control_id="first"), control(control_id="second"))
    economic_action = finalize_object(
        intent({"personal.cost_minor": 1}).model_copy(
            update={
                "cost": Amount(currency="USD", minor_units=1),
                "intent_digest": None,
            }
        )
    )
    cost_allow = control(
        control_id="lower-cost-allow",
        predicates=(
            Predicate(
                operator="lte",
                path="/context/personal.cost_minor",
                value=100,
            ),
        ),
    )

    def exact(
        case_id: str,
        controls,
        expected: Verdict,
        route_kind: CoreRouteKind,
        codes: tuple[str, ...],
        *,
        action_intent=action,
        facts=EMPTY,
        operation="evaluate",
        prior_intent=None,
        supported_verifiers=(),
        execution_observation=None,
        reported_execution=None,
        receipt_status=None,
        recheck_valid=None,
        recheck_code=None,
        mutations=(),
        control_orders=(),
    ) -> ConformanceVector:
        return finalize_vector(
            ConformanceVector(
                case_id=case_id,
                authority_mode="non_authoritative_conformance",
                operation=operation,
                intent=action_intent,
                prior_intent=prior_intent,
                controls=controls,
                trusted_time="2026-08-20T12:00:00.000000Z",
                supported_extensions=(),
                display_extensions=(),
                supported_verifiers=supported_verifiers,
                facts=facts,
                expected_verdict=expected,
                expected_route_kind=route_kind,
                required_explanation_codes=codes,
                forbidden_verdicts=(() if expected is Verdict.ALLOW else (Verdict.ALLOW,)),
                expected_recheck_valid=recheck_valid,
                expected_recheck_code=recheck_code,
                execution_observation=execution_observation,
                reported_execution=reported_execution,
                expected_receipt_status=receipt_status,
                mutation_cases=mutations,
                control_permutations=control_orders,
            )
        )

    report = ReportedExecution(
        execution_result="personal.execution.succeeded",
        evidence_refs=(),
        business_outcome="personal.purchase.completed",
    )
    return (
        exact(
            "CS-CF-001",
            (draft,),
            Verdict.BLOCK,
            CoreRouteKind.BLOCK,
            (NO_APPLICABLE_PUBLISHED_CONTROL,),
        ),
        exact(
            "CS-CF-002",
            (published,),
            Verdict.ALLOW,
            CoreRouteKind.CONTINUE,
            ("controlspec.core.allow",),
        ),
        exact(
            "CS-CF-003",
            (guarded,),
            Verdict.BLOCK,
            CoreRouteKind.BLOCK,
            ("controlspec.core.context.unknown",),
            action_intent=intent({"personal.other": 1}),
        ),
        exact(
            "CS-CF-004",
            (block,),
            Verdict.BLOCK,
            CoreRouteKind.BLOCK,
            ("controlspec.core.prohibition",),
            operation="assess_receipt",
            execution_observation=observation(block.effect.route),
            reported_execution=report,
            receipt_status=ReceiptStatus.FAILED,
        ),
        exact(
            "CS-CF-005",
            (approval,),
            Verdict.REQUIRE_APPROVAL,
            CoreRouteKind.CONTINUE,
            ("controlspec.core.approval.required",),
        ),
        exact(
            "CS-CF-006",
            (approval,),
            Verdict.BLOCK,
            CoreRouteKind.BLOCK,
            ("controlspec.core.approval.independence_failed",),
            facts=self_facts,
        ),
        exact(
            "CS-CF-007",
            (published,),
            Verdict.ALLOW,
            CoreRouteKind.CONTINUE,
            ("controlspec.core.allow",),
            mutations=mutation_cases,
        ),
        exact(
            "CS-CF-008",
            (published,),
            Verdict.ALLOW,
            CoreRouteKind.CONTINUE,
            ("controlspec.core.allow",),
            action_intent=changed,
            operation="recheck",
            prior_intent=action,
            recheck_valid=False,
            recheck_code="controlspec.core.recheck.intent_changed",
        ),
        exact(
            "CS-CF-009",
            (evidence,),
            Verdict.ALLOW,
            CoreRouteKind.CONTINUE,
            ("controlspec.core.allow",),
            operation="assess_receipt",
            supported_verifiers=("controlspec.core.verifier.evidence",),
            execution_observation=observation(evidence.effect.route),
            reported_execution=report,
            receipt_status=ReceiptStatus.INCOMPLETE,
        ),
        exact(
            "CS-CF-010",
            ordered_controls,
            Verdict.ALLOW,
            CoreRouteKind.CONTINUE,
            ("controlspec.core.allow",),
            control_orders=(ordered_controls, tuple(reversed(ordered_controls))),
        ),
        exact(
            "CS-CF-011",
            (human, ask),
            Verdict.CONFLICT,
            CoreRouteKind.BLOCK,
            ("controlspec.core.route.conflict",),
        ),
        exact(
            "CS-CF-012",
            (cost_allow, block),
            Verdict.BLOCK,
            CoreRouteKind.BLOCK,
            ("controlspec.core.prohibition",),
            action_intent=economic_action,
        ),
    )


def test_all_twelve_full_exact_vectors_execute_through_the_shared_runner() -> None:
    observations = [run_vector(vector)[0] for vector in core_vectors()]
    assert [item.case_id for item in observations] == [
        f"CS-CF-{index:03d}" for index in range(1, 13)
    ]
    assert all(item.passed for item in observations)


def test_vectors_encode_mutation_permutation_and_economics_probes() -> None:
    vectors = {item.case_id: item for item in core_vectors()}
    mutation = vectors["CS-CF-007"]
    assert {item.mutation_id.rsplit(".", maxsplit=1)[-1] for item in mutation.mutation_cases} == {
        "actor",
        "action",
        "resource",
        "context",
        "control",
        "fact",
        "time",
    }
    mutation_observation, _ = run_vector(mutation)
    assert mutation_observation.mutation_matrix_passed

    permutation = vectors["CS-CF-010"]
    assert len(permutation.control_permutations) == 2
    assert permutation.control_permutations[0] == tuple(
        reversed(permutation.control_permutations[1])
    )
    permutation_observation, _ = run_vector(permutation)
    assert permutation_observation.control_permutations_passed

    economics = vectors["CS-CF-012"]
    assert economics.intent.cost is not None
    assert economics.intent.cost.minor_units == 1
    assert any(control.match.predicates for control in economics.controls)
    _, result = run_vector(economics)
    assert result.decision.verdict is Verdict.BLOCK


def test_vector_loader_rejects_any_noncanonical_framing(tmp_path: Path) -> None:
    vector = core_vectors()[0]
    framed = tmp_path / "framed.json"
    framed.write_bytes(canonical_json(vector) + b"\n")
    with pytest.raises(ValueError, match="canonical JSON"):
        load_vector(framed)


def test_cs_cf_001_draft_exclusion_and_cs_cf_002_published_application() -> None:
    draft = control(status=ControlStatus.DRAFT)
    draft_observation, _ = run_vector(
        _vector("CS-CF-001", (draft,), Verdict.BLOCK, NO_APPLICABLE_PUBLISHED_CONTROL)
    )
    published_observation, result = run_vector(
        _vector("CS-CF-002", (control(),), Verdict.ALLOW, "controlspec.core.allow")
    )
    assert draft_observation.passed
    assert published_observation.passed
    assert len(result.decision.applied_controls) == 1


def test_cs_cf_003_missing_context_fails_closed() -> None:
    guarded = control(
        predicates=(
            Predicate(
                operator="lte",
                path="/context/personal.amount_minor",
                value=7500,
            ),
        )
    )
    changed = intent({"personal.other": 1})
    vector = finalize_vector(
        _vector(
            "CS-CF-003",
            (guarded,),
            Verdict.BLOCK,
            "controlspec.core.context.unknown",
        ).model_copy(update={"intent": changed, "vector_digest": None})
    )
    observed, _ = run_vector(vector)
    assert observed.passed


def test_cs_cf_004_blocked_caller_success_cannot_complete_receipt() -> None:
    evaluator = ControlSpecEvaluator()
    action = intent()
    block = control(
        effect=ControlEffect(
            verdict="block",
            route=route(CoreRouteKind.BLOCK, route_id="prohibited"),
            requirements=(),
            conditions=(),
            code="controlspec.core.prohibition",
        )
    )
    policy = snapshot(block)
    decision = evaluator.evaluate(intent=action, snapshot=policy, facts=EMPTY).decision
    checked = recheck(
        prior=decision,
        intent=action,
        snapshot=policy,
        facts=EMPTY,
        evaluator=evaluator,
    )
    receipt = assess_receipt(
        decision=decision,
        intent=action,
        recheck_result=checked,
        facts=EMPTY,
        observation=observation(decision.route),
        reported_execution=ReportedExecution(
            execution_result="personal.execution.succeeded",
            evidence_refs=(),
            business_outcome="personal.purchase.completed",
        ),
    )
    assert receipt.status is ReceiptStatus.FAILED


def test_cs_cf_005_approval_required_and_cs_cf_006_independence() -> None:
    evaluator = ControlSpecEvaluator()
    action = intent()
    policy = snapshot(approval_control())
    basis = evaluator.evaluate(intent=action, snapshot=policy, facts=EMPTY).decision
    assert basis.verdict is Verdict.REQUIRE_APPROVAL
    self_fact = approval_fact(action, basis, action.actor)
    facts = EvaluationFacts(
        approval_basis_ref=self_fact.basis_decision_ref,
        approvals=(self_fact,),
        evidence=(),
        profile_assessments=(),
    )
    assert (
        evaluator.evaluate(intent=action, snapshot=policy, facts=facts).decision.verdict
        is Verdict.BLOCK
    )


def test_cs_cf_007_complete_binding_and_cs_cf_008_recheck_mutation() -> None:
    evaluator = ControlSpecEvaluator()
    policy = snapshot(control())
    original = intent()
    prior = evaluator.evaluate(intent=original, snapshot=policy, facts=EMPTY).decision
    changed = intent({"personal.amount_minor": 4300})
    current = evaluator.evaluate(intent=changed, snapshot=policy, facts=EMPTY).decision
    assert current.binding.context_digest != prior.binding.context_digest
    assert current.binding.intent_digest != prior.binding.intent_digest
    checked = recheck(
        prior=prior,
        intent=changed,
        snapshot=policy,
        facts=EMPTY,
        evaluator=evaluator,
    )
    assert not checked.valid


def test_cs_cf_009_missing_evidence_cannot_complete() -> None:
    evaluator = ControlSpecEvaluator()
    action = intent()
    policy = finalize_snapshot(
        snapshot(evidence_control()).model_copy(
            update={"supported_verifiers": ("controlspec.core.verifier.evidence",)}
        )
    )
    decision = evaluator.evaluate(intent=action, snapshot=policy, facts=EMPTY).decision
    checked = recheck(
        prior=decision,
        intent=action,
        snapshot=policy,
        facts=EMPTY,
        evaluator=evaluator,
    )
    receipt = assess_receipt(
        decision=decision,
        intent=action,
        recheck_result=checked,
        facts=EMPTY,
        observation=observation(decision.route),
        reported_execution=ReportedExecution(
            execution_result="personal.execution.succeeded",
            evidence_refs=(),
            business_outcome=None,
        ),
    )
    assert receipt.status is ReceiptStatus.INCOMPLETE


def test_cs_cf_010_determinism_under_control_order_permutations() -> None:
    evaluator = ControlSpecEvaluator()
    controls = (control(control_id="first"), control(control_id="second"))
    decisions = {
        evaluator.evaluate(
            intent=intent(), snapshot=snapshot(*ordered), facts=EMPTY
        ).decision.semantic_digest
        for ordered in permutations(controls)
    }
    assert len(decisions) == 1


def test_cs_cf_011_conflict_and_cs_cf_012_economics_never_override_block() -> None:
    evaluator = ControlSpecEvaluator()
    alternate_a = control(
        control_id="human",
        effect=ControlEffect(
            verdict="route",
            route=route(CoreRouteKind.HUMAN_REVIEW, route_id="human"),
            requirements=(),
            conditions=(),
            code="controlspec.core.route.human",
        ),
    )
    alternate_b = control(
        control_id="ask",
        effect=ControlEffect(
            verdict="route",
            route=route(CoreRouteKind.ASK_USER, route_id="ask"),
            requirements=(),
            conditions=(),
            code="controlspec.core.route.ask",
        ),
    )
    conflict = evaluator.evaluate(
        intent=intent(), snapshot=snapshot(alternate_a, alternate_b), facts=EMPTY
    ).decision
    assert conflict.verdict is Verdict.CONFLICT

    prohibited = control(
        control_id="independent-prohibition",
        effect=ControlEffect(
            verdict="block",
            route=route(CoreRouteKind.BLOCK, route_id="prohibited"),
            requirements=(),
            conditions=(),
            code="controlspec.core.prohibition",
        ),
    )
    lower_cost = intent().model_copy(update={"cost": None, "intent_digest": None})
    lower_cost = finalize_object(lower_cost)
    decision = evaluator.evaluate(
        intent=lower_cost,
        snapshot=snapshot(control(control_id="cheap-allow"), prohibited),
        facts=EMPTY,
    ).decision
    assert decision.verdict is Verdict.BLOCK
