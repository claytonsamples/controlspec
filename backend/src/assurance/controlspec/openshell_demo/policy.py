"""Closed synthetic example inputs and separately sourced typed demo policy."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StringConstraints

from assurance.contracts.canonical import canonical_json, sha256_digest
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
    FailureEffect,
    JsonValue,
    Predicate,
    Resource,
    Route,
    SourceReference,
)
from assurance.controlspec.facts import (
    PublishedControlSnapshot,
    SnapshotAuthorityMode,
    finalize_snapshot,
)

NAMESPACE = "controlspec.synthetic.purchase"
SOURCE = (
    "Change 0011 synthetic example: nonrecurring USD purchases up to 7500 minor units "
    "may proceed; larger one-time purchases require an independent exact-action approval; "
    "recurring purchases are blocked. This is example data, not enterprise risk appetite."
)


class PurchaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    schema_version: Literal["1"]
    action_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
    amount_minor: Annotated[StrictInt, Field(gt=0, le=1_000_000_000)]
    currency: Literal["USD"]
    merchant: Literal["demo-store"]
    recurring: StrictBool


class TrustedScope(BaseModel):
    """Only construct from authenticated extension claims or marked harness fixtures."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    gateway_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    sandbox_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]

    @property
    def key(self) -> str:
        return sha256_digest(canonical_json(self))

    @property
    def actor_id(self) -> str:
        return "agent-" + self.key.removeprefix("sha256:")


def timestamp(value: datetime | None = None) -> str:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None:
        raise ValueError("clock must be timezone-aware")
    return instant.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_purchase(raw: bytes) -> PurchaseRequest:
    if len(raw) > 16384:
        raise ValueError("purchase body too large")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    return PurchaseRequest.model_validate(json.loads(raw, object_pairs_hook=unique), strict=True)


def request_digest(request: PurchaseRequest) -> str:
    # Revalidate at every trust boundary, including caller-created model_copy objects.
    validated = PurchaseRequest.model_validate(request.model_dump(), strict=True)
    return sha256_digest(canonical_json(validated))


def route(kind: CoreRouteKind = CoreRouteKind.CONTINUE) -> Route:
    return Route(
        schema="controlspec/v0/route",
        namespace=NAMESPACE,
        route_id=kind.value,
        kind=kind,
        target_ref=None,
        parameters={},
        requires_recheck=False,
    )


def synthetic_controls() -> tuple[Control, ...]:
    approval = ApprovalRequirement(
        requirement_id="exact-human-approval",
        role="controlspec.synthetic.operator",
        scope={"controlspec.synthetic.target": "POST /purchases"},
        minimum_count=1,
        validity_seconds=120,
        separate_from_actor=True,
        separate_from_roles=(),
        failure=FailureEffect(
            verdict="require_approval", route=None, code="controlspec.synthetic.approval_required"
        ),
    )
    unknown = FailureEffect(
        verdict="block",
        route=route(CoreRouteKind.BLOCK),
        code="controlspec.synthetic.missing_context",
    )

    def make(
        name: str,
        predicates: tuple[Predicate, ...],
        *,
        requires_approval: bool = False,
        blocked: bool = False,
    ) -> Control:
        return finalize_object(
            Control(
                schema="controlspec/v0/control",
                namespace=NAMESPACE,
                control_id=name,
                version="1.0.0",
                status=ControlStatus.PUBLISHED,
                effective_from=None,
                effective_until=None,
                title=name,
                description=SOURCE,
                source_refs=(
                    SourceReference(
                        source_type="controlspec.synthetic.design_decision",
                        locator="changes/0011-openshell-complement/design.md#real-evaluator-and-example-policy",
                        captured_digest=sha256_digest(SOURCE.encode()),
                    ),
                ),
                match=ControlMatch(
                    actor_types=(ActorType.AGENT,),
                    action_types=(CanonicalAction.COMMIT,),
                    domain_actions=("controlspec.synthetic.purchase",),
                    resource_types=("controlspec.synthetic.cart",),
                    predicates=predicates,
                ),
                on_unknown=unknown,
                effect=ControlEffect(
                    verdict="block" if blocked else "allow",
                    route=route(CoreRouteKind.BLOCK if blocked else CoreRouteKind.CONTINUE),
                    requirements=(approval,) if requires_approval else (),
                    conditions=(),
                    code=f"controlspec.synthetic.{name}",
                ),
                metadata={"synthetic_only": True, "source_statement": SOURCE},
            )
        )

    one_time = Predicate(
        operator="eq", path="/context/controlspec.synthetic.recurring", value=False
    )
    return (
        make(
            "within_limit",
            (
                one_time,
                Predicate(
                    operator="lte", path="/context/controlspec.synthetic.amount_minor", value=7500
                ),
            ),
        ),
        make(
            "above_limit",
            (
                one_time,
                Predicate(
                    operator="gt", path="/context/controlspec.synthetic.amount_minor", value=7500
                ),
            ),
            requires_approval=True,
        ),
        make(
            "recurring_blocked",
            (
                Predicate(
                    operator="eq", path="/context/controlspec.synthetic.recurring", value=True
                ),
            ),
            blocked=True,
        ),
    )


def policy_digest(controls: tuple[Control, ...]) -> str:
    return sha256_digest(canonical_json(controls))


def snapshot(controls: tuple[Control, ...], observed_at: str) -> PublishedControlSnapshot:
    return finalize_snapshot(
        PublishedControlSnapshot(
            controls=controls,
            observed_at=observed_at,
            authority_mode=SnapshotAuthorityMode.NON_AUTHORITATIVE_CONFORMANCE,
            host_authority_refs=(),
            supported_extensions=(),
            display_extensions=(),
            supported_verifiers=(),
        )
    )


def make_intent(request: PurchaseRequest, scope: TrustedScope, first_seen: str) -> ActionIntent:
    context: dict[str, JsonValue] = {
        "controlspec.synthetic.amount_minor": request.amount_minor,
        "controlspec.synthetic.recurring": request.recurring,
        "controlspec.synthetic.request_digest": request_digest(request),
        "controlspec.synthetic.scope_digest": scope.key,
        "controlspec.synthetic.method": "POST",
        "controlspec.synthetic.path": "/purchases",
    }
    return finalize_object(
        ActionIntent(
            schema="controlspec/v0/action-intent",
            namespace=NAMESPACE,
            intent_id=request.action_id,
            actor=Actor(
                schema="controlspec/v0/actor",
                namespace=NAMESPACE,
                actor_id=scope.actor_id,
                version="1",
                type=ActorType.AGENT,
                owner_ref=None,
                lineage_refs=(),
                attributes={},
            ),
            action=Action(
                type=CanonicalAction.COMMIT,
                domain_action="controlspec.synthetic.purchase",
                requested_effect=request.model_dump(mode="json"),
            ),
            resource=Resource(
                schema="controlspec/v0/resource",
                namespace=NAMESPACE,
                resource_id="demo-store",
                version="1",
                type="controlspec.synthetic.cart",
                business_id=None,
                attributes={},
            ),
            context=context,
            requested_route=None,
            evidence_refs=(),
            cost=None,
            retry_count=0,
            requested_at=first_seen,
            idempotency_key=request.action_id,
            context_digest=canonical_context_hash(context),
        )
    )
