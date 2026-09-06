"""Pure one-way RiskSpec v1.1 supplier-profile projections."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from assurance.contracts.canonical import canonical_json, model_canonical_hash, sha256_digest
from assurance.contracts.common import PrincipalIdentity, ResourceIdentity
from assurance.contracts.objects import ActionIntent as RiskActionIntent
from assurance.contracts.objects import Approval as RiskApproval
from assurance.contracts.objects import AssuranceReceipt as RiskReceipt
from assurance.contracts.objects import ControlDecision as RiskDecision
from assurance.contracts.objects import LifecycleEvent, RiskSpecVersion
from assurance.controlspec.canonical import (
    canonical_context_hash,
    finalize_object,
    verify_object_digest,
)
from assurance.controlspec.contracts import (
    Action,
    ActionIntent,
    Actor,
    ActorRef,
    ActorType,
    Amount,
    Approval,
    CanonicalAction,
    Control,
    ControlEffect,
    ControlMatch,
    ControlPack,
    ControlRef,
    ControlStatus,
    CoreRouteKind,
    Decision,
    DecisionBinding,
    DecisionRef,
    EvaluatorBinding,
    EvidenceRef,
    ExecutionOutcome,
    ExtensionBearing,
    ExtensionDeclaration,
    FailureEffect,
    HashDigest,
    IntentRef,
    JsonValue,
    ObjectRef,
    ProfileRequirement,
    Receipt,
    ReceiptOutcome,
    ReceiptStatus,
    ReportedExecution,
    Resource,
    ResourceRef,
    Route,
    SourceReference,
    Verdict,
    VerifierDeclaration,
    Vocabularies,
)
from assurance.domain import AssuranceStatus, LifecycleState, RouteId
from assurance.domain import CanonicalAction as RiskAction
from assurance.domain import ExecutionOutcome as RiskExecutionOutcome
from assurance.domain import Verdict as RiskVerdict
from assurance.runtime.selection import event_reference, spec_reference

PROFILE_NAMESPACE = "riskspec.enterprise.assurance"
SOURCE_EXTENSION = "riskspec.enterprise.source"
D001_VERIFIER = "riskspec.enterprise.verifier.d001_rule"
D001_VERIFIER_SCHEMA_DIGEST = sha256_digest(
    canonical_json({"schema": "riskspec.enterprise/d001-rule-input", "version": "1"})
)

_ACTOR_TYPES = {
    "HUMAN": ActorType.HUMAN,
    "AGENT": ActorType.AGENT,
    "SERVICE": ActorType.SERVICE,
    "APPLICATION": ActorType.APPLICATION,
}
_ACTIONS = {item: CanonicalAction(item.value.lower()) for item in RiskAction}
_VERDICTS = {
    RiskVerdict.ALLOW: Verdict.ALLOW,
    RiskVerdict.ALLOW_WITH_CONDITIONS: Verdict.ALLOW_WITH_CONDITIONS,
    RiskVerdict.REQUIRE_APPROVAL: Verdict.REQUIRE_APPROVAL,
    RiskVerdict.SWITCH_ROUTE: Verdict.ROUTE,
    RiskVerdict.BLOCK: Verdict.BLOCK,
    RiskVerdict.CONFLICT: Verdict.CONFLICT,
}
_ROUTES = {
    RouteId.AUTONOMOUS_SUPPLIER: CoreRouteKind.CONTINUE,
    RouteId.HUMAN_SUPPLIER_REVIEW: CoreRouteKind.HUMAN_REVIEW,
}
_LIFECYCLE_PREDECESSOR = {
    LifecycleState.DRAFT: None,
    LifecycleState.REVIEWED: LifecycleState.DRAFT,
    LifecycleState.APPROVED: LifecycleState.REVIEWED,
    LifecycleState.PUBLISHED: LifecycleState.APPROVED,
    LifecycleState.RETIRED: LifecycleState.PUBLISHED,
}


class ExactRiskSpecMappingResult(BaseModel):
    """Typed, non-authoritative record of one exact retained source projection."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    mapping_status: Literal["exact"] = "exact"
    source_schema: str
    canonical_json: str
    digest: HashDigest


def _time(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _mapping_result(source: Any, *, source_schema: str) -> dict[str, Any]:
    payload = canonical_json(source)
    result = ExactRiskSpecMappingResult(
        source_schema=source_schema,
        canonical_json=payload.decode(),
        digest=sha256_digest(payload),
    )
    return result.model_dump(mode="json")


def _source(source: BaseModel) -> dict[str, Any]:
    return {
        SOURCE_EXTENSION: _mapping_result(
            source,
            source_schema=source.__class__.__name__,
        )
    }


def source_projection_is_lossless(source: BaseModel, projected: ExtensionBearing) -> bool:
    return projected.extensions == _source(source)


def _retained_mapping_payload(projected: ExtensionBearing) -> dict[str, Any]:
    binding = projected.extensions.get(SOURCE_EXTENSION)
    try:
        result = ExactRiskSpecMappingResult.model_validate(binding)
        source = json.loads(result.canonical_json)
    except (TypeError, ValueError) as exc:
        raise ValueError("portable projection lacks its exact retained RiskSpec source") from exc
    if not isinstance(source, dict):
        raise ValueError("portable projection lacks its exact retained RiskSpec source")
    canonical = canonical_json(source)
    if result.canonical_json.encode() != canonical or result.digest != sha256_digest(canonical):
        raise ValueError("portable projection retained source is not canonical and hash-bound")
    return source


def _retained_source_value(projected: ExtensionBearing, field: str) -> Any:
    source = _retained_mapping_payload(projected)
    if field not in source:
        raise ValueError("portable projection source is missing an exact binding field")
    return source[field]


def _require_exact_intent_projection(intent: ActionIntent) -> None:
    retained = RiskActionIntent.model_validate(_retained_mapping_payload(intent))
    expected = project_action_intent(retained, resource_version=intent.resource.version)
    if expected != intent:
        raise ValueError("portable intent fields differ from the retained RiskSpec projection")


def _control_rule_coverage(
    control: Control,
) -> tuple[
    tuple[str, str, int, str, str],
    set[tuple[str, str, int, str, str, str]],
    tuple[str, str, int, str, str, str],
]:
    if control.status is not ControlStatus.PUBLISHED or not verify_object_digest(control):
        raise ValueError("applied controls must be exact valid published control versions")
    source = _retained_mapping_payload(control)
    if set(source) != {"risk_spec", "rule", "lifecycle_events"}:
        raise ValueError("applied control lacks one exact atomic RiskSpec rule projection")
    try:
        retained_spec = RiskSpecVersion.model_validate(source["risk_spec"])
        lifecycle_chain = tuple(
            LifecycleEvent.model_validate(event) for event in source["lifecycle_events"]
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "applied control has an invalid retained RiskSpec or lifecycle chain"
        ) from exc
    _validate_lifecycle_status(
        retained_spec,
        status=control.status,
        lifecycle_events=lifecycle_chain,
    )
    retained_rule = source["rule"]
    matching_rules = tuple(
        rule
        for rule in retained_spec.policy_module.rules
        if canonical_json(rule) == canonical_json(retained_rule)
    )
    if len(matching_rules) != 1:
        raise ValueError("applied control does not retain exactly one rule from its RiskSpec")
    rule = matching_rules[0]
    expected_metadata = {
        "module_key": retained_spec.module_key,
        "rule_key": rule.rule_key,
        "version": retained_spec.version,
        "content_hash": retained_spec.content_hash,
        "semantic_hash": retained_spec.semantic_hash,
    }
    if control.metadata != expected_metadata or control.control_id != (
        f"{retained_spec.spec_key}.{rule.rule_key}"
    ):
        raise ValueError("applied control identity differs from its retained RiskSpec rule")
    spec_identity = (
        str(retained_spec.object_id),
        retained_spec.module_key,
        retained_spec.version,
        retained_spec.content_hash,
        retained_spec.semantic_hash,
    )
    expected_rules = {
        (*spec_identity, item.rule_key) for item in retained_spec.policy_module.rules
    }
    return spec_identity, expected_rules, (*spec_identity, rule.rule_key)


def _object_ref(reference: Any, object_type: str = "riskspec.enterprise.object") -> ObjectRef:
    return ObjectRef(
        namespace=PROFILE_NAMESPACE,
        object_type=object_type,
        object_id=str(reference.object_id),
        version="1",
        digest=reference.object_hash,
    )


def actor_ref(actor: Actor) -> ActorRef:
    return ActorRef(namespace=actor.namespace, actor_id=actor.actor_id, version=actor.version)


def resource_ref(resource: Resource) -> ResourceRef:
    return ResourceRef(
        namespace=resource.namespace,
        resource_id=resource.resource_id,
        version=resource.version,
        type=resource.type,
    )


def control_ref(control: Control) -> ControlRef:
    assert control.semantic_digest is not None
    return ControlRef(
        namespace=control.namespace,
        control_id=control.control_id,
        version=control.version,
        semantic_digest=control.semantic_digest,
    )


def intent_ref(intent: ActionIntent) -> IntentRef:
    assert intent.intent_digest is not None
    return IntentRef(
        namespace=intent.namespace, intent_id=intent.intent_id, intent_digest=intent.intent_digest
    )


def decision_ref(decision: Decision) -> DecisionRef:
    assert decision.semantic_digest is not None
    return DecisionRef(
        namespace=decision.namespace,
        decision_id=decision.decision_id,
        semantic_digest=decision.semantic_digest,
    )


def project_actor(
    principal: PrincipalIdentity,
    *,
    owner_ref: ObjectRef | None = None,
    lineage_refs: tuple[ObjectRef, ...] = (),
) -> Actor:
    return Actor(
        schema="controlspec/v0/actor",
        namespace=PROFILE_NAMESPACE,
        actor_id=str(principal.principal_id),
        version=str(principal.principal_version_id),
        type=_ACTOR_TYPES[principal.principal_type.value],
        owner_ref=owner_ref,
        lineage_refs=lineage_refs,
        attributes={
            "independence_domain_id": str(principal.independence_domain_id),
            "tenant_id": str(principal.tenant_id),
        },
        extensions=_source(principal),
    )


def project_resource(resource: ResourceIdentity, *, version: str) -> Resource:
    return Resource(
        schema="controlspec/v0/resource",
        namespace=PROFILE_NAMESPACE,
        resource_id=str(resource.resource_id),
        version=version,
        type="riskspec.enterprise.resource.supplier",
        business_id=resource.business_id,
        display_name=resource.business_id,
        attributes={"tenant_id": str(resource.tenant_id)},
        extensions=_source(resource),
    )


def project_route(route_id: RouteId) -> Route:
    if route_id not in _ROUTES:
        raise ValueError(f"unsupported RiskSpec route: {route_id}")
    return Route(
        schema="controlspec/v0/route",
        namespace=PROFILE_NAMESPACE,
        route_id=f"riskspec-{route_id.value.lower()}",
        kind=_ROUTES[route_id],
        target_ref=None,
        parameters={},
        requires_recheck=route_id is RouteId.HUMAN_SUPPLIER_REVIEW,
        extensions={
            SOURCE_EXTENSION: _mapping_result(
                {"route_id": route_id.value},
                source_schema="RiskSpecRouteId",
            )
        },
    )


def _route_ref(route_id: RouteId) -> ObjectRef:
    payload = canonical_json({"route_id": route_id.value})
    return ObjectRef(
        namespace=PROFILE_NAMESPACE,
        object_type="riskspec.enterprise.route",
        object_id=route_id.value,
        version="1",
        digest=sha256_digest(payload),
    )


def project_action_intent(intent: RiskActionIntent, *, resource_version: str) -> ActionIntent:
    if intent.domain_verb.value != "ADVANCE_SUPPLIER":
        raise ValueError("only the truthful v1.1 ADVANCE_SUPPLIER profile is supported")
    actor = project_actor(intent.principal)
    resource = project_resource(intent.resource, version=resource_version)
    context: dict[str, JsonValue] = {
        f"riskspec.enterprise.context.claim_{index:04d}": claim.model_dump(
            mode="json", by_alias=True
        )
        for index, claim in enumerate(intent.context)
    }
    value = ActionIntent(
        schema="controlspec/v0/action-intent",
        namespace=PROFILE_NAMESPACE,
        intent_id=str(intent.object_id),
        actor=actor,
        action=Action(
            type=_ACTIONS[intent.canonical_action],
            domain_action=f"riskspec.enterprise.action.{intent.domain_verb.value.lower()}",
            requested_effect=intent.requested_state_change.model_dump(mode="json", by_alias=True),
        ),
        resource=resource,
        context=context,
        requested_route=project_route(intent.requested_route),
        evidence_refs=tuple(
            EvidenceRef(
                namespace=PROFILE_NAMESPACE,
                evidence_id=str(ref.object_id),
                digest=ref.object_hash,
                kind="riskspec.enterprise.evidence.object",
            )
            for ref in intent.evidence_refs
        ),
        cost=Amount(
            currency=intent.requested_cost.currency, minor_units=intent.requested_cost.minor_units
        ),
        retry_count=intent.retry.attempt_number - 1,
        requested_at=_time(intent.requested_at),
        idempotency_key=intent.idempotency_key,
        context_digest=canonical_context_hash(context),
        extensions=_source(intent),
    )
    return finalize_object(value)


def _block_route() -> Route:
    return Route(
        schema="controlspec/v0/route",
        namespace=PROFILE_NAMESPACE,
        route_id="fail-closed",
        kind=CoreRouteKind.BLOCK,
        target_ref=None,
        parameters={},
        requires_recheck=False,
    )


def _validate_lifecycle_status(
    spec: RiskSpecVersion,
    *,
    status: ControlStatus,
    lifecycle_events: tuple[LifecycleEvent, ...],
) -> tuple[LifecycleEvent, ...]:
    relevant = tuple(
        event
        for event in lifecycle_events
        if event.spec_version_ref.spec_version_id == spec.object_id
    )
    if not relevant and status is ControlStatus.DRAFT:
        return ()
    if not relevant:
        raise ValueError("non-draft projection requires exact RiskSpec lifecycle evidence")
    ordered = tuple(sorted(relevant, key=lambda event: event.sequence))
    prior: LifecycleEvent | None = None
    exact_spec_ref = spec_reference(spec)
    for event in ordered:
        expected_sequence = 1 if prior is None else prior.sequence + 1
        expected_prior_ref = None if prior is None else event_reference(prior)
        expected_prior_state = None if prior is None else prior.next_state
        if (
            event.spec_version_ref != exact_spec_ref
            or event.exact_content_hash != spec.content_hash
            or model_canonical_hash(event, excluded_fields=("event_hash",))
            != event.event_hash
            or event.sequence != expected_sequence
            or event.prior_event_ref != expected_prior_ref
            or event.prior_state is not expected_prior_state
            or _LIFECYCLE_PREDECESSOR[event.next_state] is not expected_prior_state
        ):
            raise ValueError(
                "lifecycle evidence must be one exact contiguous hash-linked transition chain"
            )
        prior = event
    current = ordered[-1]
    expected = (
        LifecycleState.PUBLISHED
        if status is ControlStatus.PUBLISHED
        else LifecycleState.RETIRED
        if status is ControlStatus.RETIRED
        else LifecycleState.DRAFT
    )
    if not (
        current.next_state is expected
        and current.spec_version_ref.spec_version_id == spec.object_id
        and current.exact_content_hash == spec.content_hash
    ):
        raise ValueError(
            "projected status must equal the current exact RiskSpec lifecycle head"
        )
    return ordered


def project_controls(
    spec: RiskSpecVersion,
    *,
    status: ControlStatus,
    lifecycle_events: tuple[LifecycleEvent, ...] = (),
) -> tuple[Control, ...]:
    if spec.policy_module.coverage.domain_verb.value != "ADVANCE_SUPPLIER":
        raise ValueError("only the truthful v1.1 ADVANCE_SUPPLIER profile is supported")
    lifecycle_chain = _validate_lifecycle_status(
        spec,
        status=status,
        lifecycle_events=lifecycle_events,
    )
    controls: list[Control] = []
    coverage = spec.policy_module.coverage
    for rule in spec.policy_module.rules:
        source_bytes = canonical_json({"risk_spec": spec, "rule": rule})
        value = Control(
            schema="controlspec/v0/control",
            namespace=PROFILE_NAMESPACE,
            control_id=f"{spec.spec_key}.{rule.rule_key}",
            version=f"{spec.version}.0.0",
            status=status,
            effective_from=None if spec.effective_from is None else _time(spec.effective_from),
            effective_until=None if spec.effective_until is None else _time(spec.effective_until),
            title=f"{spec.prose_metadata.title}: {rule.rule_key}",
            description=spec.prose_metadata.summary,
            source_refs=(
                SourceReference(
                    source_type="riskspec.enterprise.riskspec_rule",
                    locator=f"{spec.object_id}#rules/{rule.rule_key}",
                    captured_digest=sha256_digest(source_bytes),
                ),
            ),
            match=ControlMatch(
                actor_types=(_ACTOR_TYPES[coverage.principal_type.value],),
                action_types=(_ACTIONS[coverage.canonical_action],),
                domain_actions=(
                    f"riskspec.enterprise.action.{coverage.domain_verb.value.lower()}",
                ),
                resource_types=("riskspec.enterprise.resource.supplier",),
                predicates=(),
            ),
            on_unknown=FailureEffect(
                verdict="block", route=_block_route(), code="riskspec.enterprise.unknown.block"
            ),
            effect=ControlEffect(
                verdict="allow",
                route=project_route(RouteId.AUTONOMOUS_SUPPLIER),
                requirements=(
                    ProfileRequirement(
                        requirement_id=f"d001-{rule.rule_key}",
                        verifier=D001_VERIFIER,
                        parameters={
                            "riskspec.enterprise.source_digest": sha256_digest(source_bytes),
                        },
                        failure=FailureEffect(
                            verdict="block",
                            route=_block_route(),
                            code="riskspec.enterprise.d001_unavailable",
                        ),
                    ),
                ),
                conditions=(),
                code="riskspec.enterprise.rule.evaluate",
            ),
            metadata={
                "module_key": spec.module_key,
                "rule_key": rule.rule_key,
                "version": spec.version,
                "content_hash": spec.content_hash,
                "semantic_hash": spec.semantic_hash,
            },
            extensions={
                SOURCE_EXTENSION: _mapping_result(
                    {
                        "risk_spec": spec,
                        "rule": rule,
                        "lifecycle_events": lifecycle_chain,
                    },
                    source_schema="RiskSpecRuleProjection",
                )
            },
        )
        controls.append(finalize_object(value))
    return tuple(controls)


def project_decision(
    decision: RiskDecision, *, intent: ActionIntent, controls: tuple[Control, ...], route: Route
) -> Decision:
    _require_exact_intent_projection(intent)
    if str(decision.intent_ref.object_id) != intent.intent_id:
        raise ValueError("decision does not bind the projected intent")
    if _retained_source_value(intent, "intent_hash") != decision.intent_ref.object_hash:
        raise ValueError("decision intent hash does not bind the retained RiskSpec intent")
    expected_specs = {
        (
            str(spec.spec_version_id),
            spec.module_key,
            spec.version,
            spec.content_hash,
            spec.semantic_hash,
        )
        for spec in decision.semantic_payload.selected_specs
    }
    projected_specs: set[tuple[str, str, int, str, str]] = set()
    expected_rules: set[tuple[str, str, int, str, str, str]] = set()
    projected_rules: set[tuple[str, str, int, str, str, str]] = set()
    for control in controls:
        spec_identity, retained_rules, projected_rule = _control_rule_coverage(control)
        projected_specs.add(spec_identity)
        expected_rules.update(retained_rules)
        projected_rules.add(projected_rule)
    if projected_specs != expected_specs:
        raise ValueError("projected controls must exactly cover the selected RiskSpec versions")
    if projected_rules != expected_rules:
        raise ValueError("projected controls must exactly cover every selected RiskSpec rule")

    requested_route = intent.requested_route
    verdict = _VERDICTS[decision.semantic_payload.verdict]
    if verdict in {Verdict.BLOCK, Verdict.CONFLICT}:
        if route.kind is not CoreRouteKind.BLOCK:
            raise ValueError("non-permissive RiskSpec decision requires the block route")
    elif verdict is Verdict.ROUTE:
        feasible = tuple(
            project_route(item)
            for item in decision.semantic_payload.feasible_routes
            if item in _ROUTES
        )
        if not any(route == item for item in feasible) or route.kind in {
            CoreRouteKind.CONTINUE,
            CoreRouteKind.RECORD_ONLY,
        }:
            raise ValueError("route decision must use an exact feasible alternate route")
    elif requested_route is None or route != requested_route:
        raise ValueError("decision route must equal the exact requested RiskSpec route")

    refs = tuple(control_ref(item) for item in controls)
    control_set_digest = sha256_digest(canonical_json(refs))
    value = Decision(
        schema="controlspec/v0/decision",
        namespace=PROFILE_NAMESPACE,
        decision_id=str(decision.object_id),
        intent_ref=intent_ref(intent),
        evaluated_at=_time(decision.evaluated_at),
        expires_at=_time(decision.expires_at),
        predecessor_decision_ref=None
        if decision.predecessor_decision_ref is None
        else DecisionRef(
            namespace=PROFILE_NAMESPACE,
            decision_id=str(decision.predecessor_decision_ref.object_id),
            semantic_digest=decision.predecessor_decision_ref.object_hash,
        ),
        verdict=verdict,
        route=route,
        conditions=(),
        approval_requirements=(),
        required_evidence=(),
        applied_controls=refs,
        explanation_codes=tuple(
            f"riskspec.enterprise.explanation.{code.value.lower()}"
            for code in decision.semantic_payload.explanation_codes
        ),
        binding=DecisionBinding(
            actor_ref=actor_ref(intent.actor),
            action_type=intent.action.type,
            domain_action=intent.action.domain_action,
            resource_ref=resource_ref(intent.resource),
            context_digest=intent.context_digest,
            intent_digest=intent_ref(intent).intent_digest,
            control_set_digest=control_set_digest,
            evaluator=EvaluatorBinding(name="RiskSpec-D-001", version="1"),
        ),
        requires_recheck=decision.semantic_payload.requires_reauthorization,
        extensions=_source(decision),
    )
    return finalize_object(value)


def project_approval(
    approval: RiskApproval, *, decision: Decision, intent: ActionIntent
) -> Approval:
    _require_exact_intent_projection(intent)
    if (
        str(approval.decision_ref.object_id) != decision.decision_id
        or str(approval.intent_ref.object_id) != intent.intent_id
    ):
        raise ValueError("approval does not bind the supplied projected decision and intent")
    if (
        _retained_source_value(decision, "decision_hash")
        != approval.decision_ref.object_hash
        or _retained_source_value(intent, "intent_hash") != approval.intent_ref.object_hash
    ):
        raise ValueError("approval hashes do not bind the retained RiskSpec decision and intent")
    scope = approval.approved_scope.model_dump(mode="json", by_alias=True)
    value = Approval(
        schema="controlspec/v0/approval",
        namespace=PROFILE_NAMESPACE,
        approval_id=str(approval.object_id),
        decision_ref=decision_ref(decision),
        intent_ref=intent_ref(intent),
        requirement_id=approval.approved_requirement_key,
        scope={"riskspec.enterprise.scope": scope},
        scope_digest=sha256_digest(canonical_json(scope)),
        approved_route_ref=None
        if approval.approved_route is None
        else _route_ref(approval.approved_route),
        approver_ref=actor_ref(project_actor(approval.approver)),
        authority_ref=_object_ref(
            approval.authority_grant_ref, "riskspec.enterprise.authority_grant"
        ),
        approved=approval.outcome.value == "GRANTED",
        conditions=(),
        decided_at=_time(approval.created_at),
        valid_from=_time(approval.valid_from),
        valid_until=_time(approval.valid_until),
        predecessor_approval_ref=None
        if approval.predecessor_event_ref is None
        else _object_ref(approval.predecessor_event_ref),
        extensions=_source(approval),
    )
    return finalize_object(value)


def project_receipt(
    receipt: RiskReceipt,
    *,
    decision: Decision,
    intent: ActionIntent,
    sequence: int,
    recorded_at: datetime,
    missing_evidence_requirement_ids: tuple[str, ...],
) -> Receipt:
    _require_exact_intent_projection(intent)
    payload = receipt.payload
    if (
        str(payload.decision_ref.object_id) != decision.decision_id
        or str(payload.intent_ref.object_id) != intent.intent_id
    ):
        raise ValueError("receipt does not bind the supplied projected decision and intent")
    if (
        _retained_source_value(decision, "decision_hash") != payload.decision_ref.object_hash
        or _retained_source_value(intent, "intent_hash") != payload.intent_ref.object_hash
    ):
        raise ValueError("receipt hashes do not bind the retained RiskSpec decision and intent")
    execution = {
        RiskExecutionOutcome.SUCCEEDED: ExecutionOutcome.SUCCEEDED,
        RiskExecutionOutcome.FAILED: ExecutionOutcome.FAILED,
        RiskExecutionOutcome.ABORTED: ExecutionOutcome.ABORTED,
        RiskExecutionOutcome.NOT_EXECUTED: ExecutionOutcome.NOT_EXECUTED,
    }[payload.execution_outcome]
    status = {
        AssuranceStatus.ASSURANCE_SUCCEEDED: ReceiptStatus.COMPLETE,
        AssuranceStatus.ASSURANCE_INCOMPLETE: ReceiptStatus.INCOMPLETE,
        AssuranceStatus.ASSURANCE_FAILED: ReceiptStatus.FAILED,
    }[payload.assurance_status]
    evidence = tuple(
        EvidenceRef(
            namespace=PROFILE_NAMESPACE,
            evidence_id=str(entry.evidence_item_ref.object_id),
            digest=entry.evidence_item_ref.object_hash,
            kind="riskspec.enterprise.evidence.verified",
        )
        for entry in payload.supplied_evidence
    )
    value = Receipt(
        schema="controlspec/v0/receipt",
        namespace=PROFILE_NAMESPACE,
        receipt_id=str(receipt.object_id),
        sequence=sequence,
        decision_ref=decision_ref(decision),
        intent_ref=intent_ref(intent),
        actual_route=None if payload.actual_route is None else project_route(payload.actual_route),
        reported_execution=ReportedExecution(
            execution_result=f"riskspec.enterprise.execution.{payload.execution_outcome.value.lower()}",
            evidence_refs=evidence,
            business_outcome=None,
        ),
        verified_evidence_refs=evidence,
        missing_evidence_requirement_ids=missing_evidence_requirement_ids,
        execution_outcome=execution,
        outcome=ReceiptOutcome.COMPLETED
        if status is ReceiptStatus.COMPLETE
        else ReceiptOutcome.INCOMPLETE
        if status is ReceiptStatus.INCOMPLETE
        else ReceiptOutcome.FAILED,
        status=status,
        occurred_at=_time(receipt.created_at),
        recorded_at=_time(recorded_at),
        predecessor_receipt_ref=None
        if receipt.predecessor_receipt_ref is None
        else _object_ref(
            receipt.predecessor_receipt_ref,
            "riskspec.enterprise.receipt",
        ),
        extensions=_source(receipt),
    )
    return finalize_object(value)


def project_control_pack(
    spec: RiskSpecVersion,
    *,
    status: ControlStatus,
    lifecycle_events: tuple[LifecycleEvent, ...] = (),
) -> ControlPack:
    lifecycle_chain = _validate_lifecycle_status(
        spec,
        status=status,
        lifecycle_events=lifecycle_events,
    )
    controls = project_controls(
        spec,
        status=status,
        lifecycle_events=lifecycle_events,
    )
    value = ControlPack(
        schema="controlspec/v0/control-pack",
        namespace=PROFILE_NAMESPACE,
        pack_id=spec.spec_key,
        name=spec.prose_metadata.title,
        version=f"{spec.version}.0.0",
        status=status,
        title=spec.prose_metadata.title,
        description=spec.prose_metadata.summary,
        controls=controls,
        dependencies=(),
        vocabularies=Vocabularies(
            domain_actions=(
                f"riskspec.enterprise.action.{spec.policy_module.coverage.domain_verb.value.lower()}",
            ),
            resource_types=("riskspec.enterprise.resource.supplier",),
            verifiers=(
                VerifierDeclaration(
                    name=D001_VERIFIER,
                    version="1",
                    input_schema_digest=D001_VERIFIER_SCHEMA_DIGEST,
                ),
            ),
            routes=(),
        ),
        extension_requirements=(
            ExtensionDeclaration(
                key=SOURCE_EXTENSION, version="1", classification="authority", required=True
            ),
        ),
        conformance_profile="riskspec-enterprise",
        examples=(),
        metadata={"module_key": spec.module_key},
        extensions={
            SOURCE_EXTENSION: _mapping_result(
                {
                    "risk_spec": spec,
                    "lifecycle_events": lifecycle_chain,
                },
                source_schema="RiskSpecControlPackProjection",
            )
        },
    )
    return finalize_object(value)
