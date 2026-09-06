from __future__ import annotations

import json
from pathlib import Path

from assurance.contracts.canonical import canonical_json, sha256_digest
from assurance.controlspec.authoring import compile_yaml_control_pack
from assurance.controlspec.canonical import canonical_context_hash, finalize_object
from assurance.controlspec.contracts import (
    Action,
    ActionIntent,
    Actor,
    ActorType,
    ApprovalRequirement,
    CanonicalAction,
    Control,
    ControlEffect,
    ControlMatch,
    ControlStatus,
    CoreRouteKind,
    EvidenceRequirement,
    EvidenceSeparation,
    FailureEffect,
    ObjectRef,
    Predicate,
    Resource,
    Route,
    Verdict,
)
from assurance.controlspec.evaluator import ControlSpecEvaluator
from assurance.controlspec.facts import (
    ApprovalFact,
    EvaluationFacts,
    PublishedControlSnapshot,
    SnapshotAuthorityMode,
    finalize_fact,
    finalize_snapshot,
)
from tests.controlspec.test_t02_composition import _decision_ref
from tests.controlspec.test_t02_facts import NOW, digest

EMPTY = EvaluationFacts(
    approval_basis_ref=None,
    approvals=(),
    evidence=(),
    profile_assessments=(),
)
EVIDENCE_VERIFIER = "controlspec.core.verifier.evidence"


def _route(namespace: str, kind: CoreRouteKind, route_id: str) -> Route:
    return Route(
        schema="controlspec/v0/route",
        namespace=namespace,
        route_id=route_id,
        kind=kind,
        target_ref=None,
        parameters={},
        requires_recheck=kind not in {CoreRouteKind.CONTINUE, CoreRouteKind.RECORD_ONLY},
        extensions={},
    )


def _intent(
    namespace: str,
    *,
    intent_id: str,
    domain_action: str,
    resource_type: str,
    context: dict[str, object],
    canonical_action: CanonicalAction = CanonicalAction.COMMIT,
) -> ActionIntent:
    value = ActionIntent(
        schema="controlspec/v0/action-intent",
        namespace=namespace,
        intent_id=intent_id,
        actor=Actor(
            schema="controlspec/v0/actor",
            namespace=namespace,
            actor_id=f"{namespace}-agent",
            version="1",
            type=ActorType.AGENT,
            owner_ref=None,
            lineage_refs=(),
            attributes={},
            extensions={},
        ),
        action=Action(
            type=canonical_action,
            domain_action=domain_action,
            requested_effect={f"{namespace}.effect": domain_action},
        ),
        resource=Resource(
            schema="controlspec/v0/resource",
            namespace=namespace,
            resource_id=f"{namespace}-resource",
            version="1",
            type=resource_type,
            business_id=None,
            attributes={},
            extensions={},
        ),
        context=context,
        requested_route=None,
        evidence_refs=(),
        cost=None,
        retry_count=0,
        requested_at=NOW,
        idempotency_key=intent_id,
        context_digest=canonical_context_hash(context),
        extensions={},
    )
    return finalize_object(value)


def _control(
    namespace: str,
    *,
    control_id: str,
    domain_action: str,
    resource_type: str,
    predicates: tuple[Predicate, ...],
    effect: ControlEffect,
) -> Control:
    value = Control(
        schema="controlspec/v0/control",
        namespace=namespace,
        control_id=control_id,
        version="1.0.0",
        status=ControlStatus.PUBLISHED,
        effective_from=None,
        effective_until=None,
        title=control_id,
        description="Executable portable example control",
        source_refs=(),
        match=ControlMatch(
            actor_types=(ActorType.AGENT,),
            action_types=(CanonicalAction.COMMIT,),
            domain_actions=(domain_action,),
            resource_types=(resource_type,),
            predicates=predicates,
        ),
        on_unknown=FailureEffect(
            verdict="block",
            route=_route(namespace, CoreRouteKind.BLOCK, "missing-context"),
            code=f"{namespace}.missing_context",
        ),
        effect=effect,
        metadata={},
        extensions={},
    )
    return finalize_object(value)


def _snapshot(*controls: Control) -> PublishedControlSnapshot:
    return finalize_snapshot(
        PublishedControlSnapshot(
            controls=controls,
            observed_at=NOW,
            authority_mode=SnapshotAuthorityMode.NON_AUTHORITATIVE_CONFORMANCE,
            host_authority_refs=(),
            supported_extensions=(),
            display_extensions=(),
            supported_verifiers=(EVIDENCE_VERIFIER,),
        )
    )


def _predicate(path: str, operator: str, value: object) -> Predicate:
    return Predicate(operator=operator, path=path, value=value, values=(), expected=None)  # type: ignore[arg-type]


def personal_controls() -> tuple[Control, ...]:
    namespace = "controlspec.personal"
    evidence = EvidenceRequirement(
        requirement_id="purchase-record",
        kind="personal.evidence.purchase_record",
        subject="personal.purchase",
        minimum_count=1,
        max_age_seconds=86400,
        verifier=EVIDENCE_VERIFIER,
        separation=EvidenceSeparation(
            producer_not_actor=False,
            certifier_not_actor=False,
            producer_certifier_distinct=False,
        ),
        failure=FailureEffect(
            verdict="block",
            route=_route(namespace, CoreRouteKind.BLOCK, "evidence-missing"),
            code="personal.purchase.evidence_missing",
        ),
    )
    approval = ApprovalRequirement(
        requirement_id="owner-approval",
        role="personal.owner",
        scope={"personal.purchase.limit_minor": 10000},
        minimum_count=1,
        validity_seconds=3600,
        separate_from_actor=True,
        separate_from_roles=(),
        failure=FailureEffect(
            verdict="require_approval",
            route=None,
            code="personal.purchase.owner_approval_required",
        ),
    )
    base = "/context"
    return (
        _control(
            namespace,
            control_id="grocery-within-limit",
            domain_action="personal.purchase",
            resource_type="personal.cart",
            predicates=(
                _predicate(f"{base}/personal.amount_minor", "lte", 10000),
                _predicate(f"{base}/personal.recurring", "eq", False),
            ),
            effect=ControlEffect(
                verdict="allow",
                route=_route(namespace, CoreRouteKind.CONTINUE, "purchase"),
                requirements=(evidence,),
                conditions=(),
                code="personal.purchase.within_limit",
            ),
        ),
        _control(
            namespace,
            control_id="grocery-over-limit",
            domain_action="personal.purchase",
            resource_type="personal.cart",
            predicates=(
                _predicate(f"{base}/personal.amount_minor", "gt", 10000),
                _predicate(f"{base}/personal.recurring", "eq", False),
            ),
            effect=ControlEffect(
                verdict="allow",
                route=_route(namespace, CoreRouteKind.CONTINUE, "purchase"),
                requirements=(approval,),
                conditions=(),
                code="personal.purchase.over_limit",
            ),
        ),
        _control(
            namespace,
            control_id="recurring-requires-approval",
            domain_action="personal.purchase",
            resource_type="personal.cart",
            predicates=(_predicate(f"{base}/personal.recurring", "eq", True),),
            effect=ControlEffect(
                verdict="allow",
                route=_route(namespace, CoreRouteKind.CONTINUE, "purchase"),
                requirements=(approval,),
                conditions=(),
                code="personal.purchase.recurring",
            ),
        ),
    )


def test_personal_agent_spending_matrix_executes_portably() -> None:
    evaluator = ControlSpecEvaluator()
    policy = _snapshot(*personal_controls())
    cases = (
        (
            "groceries-42",
            {"personal.amount_minor": 4200, "personal.recurring": False},
            Verdict.ALLOW,
        ),
        (
            "groceries-142",
            {"personal.amount_minor": 14200, "personal.recurring": False},
            Verdict.REQUIRE_APPROVAL,
        ),
        (
            "recurring-999",
            {"personal.amount_minor": 999, "personal.recurring": True},
            Verdict.REQUIRE_APPROVAL,
        ),
        ("missing-amount", {"personal.recurring": False}, Verdict.BLOCK),
    )
    for case_id, context, expected in cases:
        action = _intent(
            "controlspec.personal",
            intent_id=case_id,
            domain_action="personal.purchase",
            resource_type="personal.cart",
            context=context,
        )
        decision = evaluator.evaluate(intent=action, snapshot=policy, facts=EMPTY).decision
        assert decision.verdict is expected
        if case_id == "groceries-42":
            assert tuple(item.requirement_id for item in decision.required_evidence) == (
                "purchase-record",
            )


def smb_controls() -> tuple[Control, ...]:
    namespace = "controlspec.smb"
    manager = ApprovalRequirement(
        requirement_id="sales-manager-approval",
        role="smb.sales.manager",
        scope={"smb.sales.discount_basis_points": 1500},
        minimum_count=1,
        validity_seconds=3600,
        separate_from_actor=True,
        separate_from_roles=(),
        failure=FailureEffect(
            verdict="require_approval",
            route=None,
            code="smb.sales.manager_approval_required",
        ),
    )
    return (
        _control(
            namespace,
            control_id="draft-email",
            domain_action="smb.sales.draft_email",
            resource_type="smb.sales.opportunity",
            predicates=(),
            effect=ControlEffect(
                verdict="allow",
                route=_route(namespace, CoreRouteKind.CONTINUE, "draft"),
                requirements=(),
                conditions=(),
                code="smb.sales.draft_email_allowed",
            ),
        ),
        _control(
            namespace,
            control_id="discount-within-limit",
            domain_action="smb.sales.offer_discount",
            resource_type="smb.sales.opportunity",
            predicates=(_predicate("/context/smb.sales.discount_basis_points", "lte", 1000),),
            effect=ControlEffect(
                verdict="allow",
                route=_route(namespace, CoreRouteKind.CONTINUE, "offer"),
                requirements=(),
                conditions=(),
                code="smb.sales.discount_within_limit",
            ),
        ),
        _control(
            namespace,
            control_id="discount-manager-approval",
            domain_action="smb.sales.offer_discount",
            resource_type="smb.sales.opportunity",
            predicates=(_predicate("/context/smb.sales.discount_basis_points", "gt", 1000),),
            effect=ControlEffect(
                verdict="allow",
                route=_route(namespace, CoreRouteKind.CONTINUE, "offer"),
                requirements=(manager,),
                conditions=(),
                code="smb.sales.discount_controlled",
            ),
        ),
    )


def _manager_fact(action: ActionIntent, basis, *, self_approve: bool) -> ApprovalFact:
    approver = (
        action.actor if self_approve else action.actor.model_copy(update={"actor_id": "manager-1"})
    )
    return finalize_fact(
        ApprovalFact(
            approval_id="manager-approval",
            intent_ref=basis.intent_ref,
            basis_decision_ref=_decision_ref(basis),
            requirement_id="sales-manager-approval",
            scope_digest=sha256_digest(canonical_json({"smb.sales.discount_basis_points": 1500})),
            approver=approver,
            authority_ref=ObjectRef(
                namespace="controlspec.smb",
                object_type="smb.sales.manager_authority",
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


def test_smb_sales_matrix_and_independence_execute_portably() -> None:
    evaluator = ControlSpecEvaluator()
    policy = _snapshot(*smb_controls())
    draft = _intent(
        "controlspec.smb",
        intent_id="draft",
        domain_action="smb.sales.draft_email",
        resource_type="smb.sales.opportunity",
        context={},
    )
    assert (
        evaluator.evaluate(intent=draft, snapshot=policy, facts=EMPTY).decision.verdict
        is Verdict.ALLOW
    )
    for amount, expected in ((800, Verdict.ALLOW), (1500, Verdict.REQUIRE_APPROVAL)):
        action = _intent(
            "controlspec.smb",
            intent_id=f"discount-{amount}",
            domain_action="smb.sales.offer_discount",
            resource_type="smb.sales.opportunity",
            context={"smb.sales.discount_basis_points": amount},
        )
        assert (
            evaluator.evaluate(intent=action, snapshot=policy, facts=EMPTY).decision.verdict
            is expected
        )

    action = _intent(
        "controlspec.smb",
        intent_id="discount-1500-approved",
        domain_action="smb.sales.offer_discount",
        resource_type="smb.sales.opportunity",
        context={"smb.sales.discount_basis_points": 1500},
    )
    basis = evaluator.evaluate(intent=action, snapshot=policy, facts=EMPTY).decision
    for self_approve, expected in ((False, Verdict.ALLOW), (True, Verdict.BLOCK)):
        facts = EvaluationFacts(
            approval_basis_ref=_decision_ref(basis),
            approvals=(_manager_fact(action, basis, self_approve=self_approve),),
            evidence=(),
            profile_assessments=(),
        )
        assert (
            evaluator.evaluate(intent=action, snapshot=policy, facts=facts).decision.verdict
            is expected
        )

    missing = _intent(
        "controlspec.smb",
        intent_id="discount-missing",
        domain_action="smb.sales.offer_discount",
        resource_type="smb.sales.opportunity",
        context={},
    )
    assert (
        evaluator.evaluate(intent=missing, snapshot=policy, facts=EMPTY).decision.verdict
        is Verdict.BLOCK
    )


def _published_example(filename: str) -> PublishedControlSnapshot:
    path = (
        Path(__file__).parents[3]
        / "changes/0005-controlspec-open-standard-reframe/examples/controlpacks"
        / filename
    )
    compiled = json.loads(compile_yaml_control_pack(path.read_text(encoding="utf-8")))
    controls = tuple(
        finalize_object(
            Control.model_validate(item, strict=False).model_copy(
                update={"status": ControlStatus.PUBLISHED, "semantic_digest": None}
            )
        )
        for item in compiled["controls"]
    )
    verifiers = tuple(declaration["name"] for declaration in compiled["vocabularies"]["verifiers"])
    return finalize_snapshot(
        PublishedControlSnapshot(
            controls=controls,
            observed_at=NOW,
            authority_mode=SnapshotAuthorityMode.NON_AUTHORITATIVE_CONFORMANCE,
            host_authority_refs=(),
            supported_extensions=(),
            display_extensions=(),
            supported_verifiers=verifiers,
        )
    )


def test_accepted_draft_examples_compile_then_execute_only_as_fixture_publications() -> None:
    evaluator = ControlSpecEvaluator()
    personal = _published_example("personal-agent-spending.yaml")
    personal_cases = (
        (
            "p42",
            {"personal.spending.total_minor_units": 4200, "personal.spending.recurring": False},
            Verdict.ALLOW,
        ),
        (
            "p142",
            {"personal.spending.total_minor_units": 14200, "personal.spending.recurring": False},
            Verdict.REQUIRE_APPROVAL,
        ),
        (
            "p999r",
            {"personal.spending.total_minor_units": 999, "personal.spending.recurring": True},
            Verdict.REQUIRE_APPROVAL,
        ),
        ("pmissing", {"personal.spending.recurring": False}, Verdict.BLOCK),
    )
    for case_id, context, expected in personal_cases:
        action = _intent(
            "personal.agent.spending",
            intent_id=case_id,
            domain_action="personal.purchase",
            resource_type="personal.cart",
            context=context,
        )
        assert (
            evaluator.evaluate(intent=action, snapshot=personal, facts=EMPTY).decision.verdict
            is expected
        )

    smb = _published_example("smb-sales-controls.yaml")
    smb_cases = (
        ("draft", "smb.sales.draft_email", {}, Verdict.ALLOW),
        (
            "discount8",
            "smb.sales.offer_discount",
            {"smb.sales.discount_basis_points": 800},
            Verdict.ALLOW_WITH_CONDITIONS,
        ),
        (
            "discount15",
            "smb.sales.offer_discount",
            {"smb.sales.discount_basis_points": 1500},
            Verdict.REQUIRE_APPROVAL,
        ),
        ("discount-missing", "smb.sales.offer_discount", {}, Verdict.BLOCK),
    )
    for case_id, domain_action, context, expected in smb_cases:
        action = _intent(
            "smb.sales.controls",
            intent_id=case_id,
            domain_action=domain_action,
            resource_type="smb.customer_email",
            context=context,
            canonical_action=CanonicalAction.COMMUNICATE,
        )
        assert (
            evaluator.evaluate(intent=action, snapshot=smb, facts=EMPTY).decision.verdict
            is expected
        )
