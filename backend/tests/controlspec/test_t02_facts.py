from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from assurance.controlspec.canonical import canonical_context_hash, finalize_object
from assurance.controlspec.contracts import (
    Action,
    ActionIntent,
    Actor,
    ActorType,
    CanonicalAction,
    Control,
    ControlEffect,
    ControlMatch,
    ControlStatus,
    CoreRouteKind,
    FailureEffect,
    ObjectRef,
    Predicate,
    Resource,
    Route,
)
from assurance.controlspec.facts import (
    PublishedControlSnapshot,
    SnapshotAuthorityMode,
    finalize_snapshot,
    verify_snapshot,
)

NOW = "2026-08-20T12:00:00.000000Z"


def digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def route(kind: CoreRouteKind = CoreRouteKind.CONTINUE, *, route_id: str = "continue") -> Route:
    return Route(
        schema="controlspec/v0/route",
        namespace="controlspec.personal",
        route_id=route_id,
        kind=kind,
        target_ref=None,
        parameters={},
        requires_recheck=kind not in {CoreRouteKind.CONTINUE, CoreRouteKind.RECORD_ONLY},
        extensions={},
    )


def intent(context: dict[str, object] | None = None) -> ActionIntent:
    actual_context = context or {"personal.amount_minor": 4200}
    value = ActionIntent(
        schema="controlspec/v0/action-intent",
        namespace="controlspec.personal",
        intent_id="intent-1",
        actor=Actor(
            schema="controlspec/v0/actor",
            namespace="controlspec.personal",
            actor_id="agent-1",
            version="1",
            type=ActorType.AGENT,
            owner_ref=None,
            lineage_refs=(),
            attributes={},
            extensions={},
        ),
        action=Action(
            type=CanonicalAction.COMMIT,
            domain_action="personal.purchase",
            requested_effect={"personal.effect": "purchase"},
        ),
        resource=Resource(
            schema="controlspec/v0/resource",
            namespace="controlspec.personal",
            resource_id="cart-1",
            version="1",
            type="personal.cart",
            business_id=None,
            attributes={},
            extensions={},
        ),
        context=actual_context,
        requested_route=None,
        evidence_refs=(),
        cost=None,
        retry_count=0,
        requested_at=NOW,
        idempotency_key="intent-1",
        context_digest=canonical_context_hash(actual_context),
        extensions={},
    )
    return finalize_object(value)


def control(
    *,
    control_id: str = "allow",
    status: ControlStatus = ControlStatus.PUBLISHED,
    effect: ControlEffect | None = None,
    predicates: tuple[Predicate, ...] = (),
) -> Control:
    value = Control(
        schema="controlspec/v0/control",
        namespace="controlspec.personal",
        control_id=control_id,
        version="1.0.0",
        status=status,
        effective_from=None,
        effective_until=None,
        title=control_id,
        description="test",
        source_refs=(),
        match=ControlMatch(
            actor_types=(ActorType.AGENT,),
            action_types=(CanonicalAction.COMMIT,),
            domain_actions=("personal.purchase",),
            resource_types=("personal.cart",),
            predicates=predicates,
        ),
        on_unknown=FailureEffect(
            verdict="block",
            route=route(CoreRouteKind.BLOCK, route_id="unknown-block"),
            code="controlspec.core.context.unknown",
        ),
        effect=effect
        or ControlEffect(
            verdict="allow",
            route=route(),
            requirements=(),
            conditions=(),
            code="controlspec.core.allow",
        ),
        metadata={},
        extensions={},
    )
    return finalize_object(value)


def snapshot(*controls: Control) -> PublishedControlSnapshot:
    return finalize_snapshot(
        PublishedControlSnapshot(
            controls=controls,
            observed_at=NOW,
            authority_mode=SnapshotAuthorityMode.NON_AUTHORITATIVE_CONFORMANCE,
            host_authority_refs=(),
            supported_extensions=(),
            display_extensions=(),
            supported_verifiers=(),
        )
    )


def test_snapshot_mode_cannot_be_relabelled_as_host_authority() -> None:
    with pytest.raises(ValidationError, match="require authority"):
        PublishedControlSnapshot(
            controls=(),
            observed_at=NOW,
            authority_mode=SnapshotAuthorityMode.HOST_AUTHORIZED,
            host_authority_refs=(),
            supported_extensions=(),
            display_extensions=(),
            supported_verifiers=(),
        )
    with pytest.raises(ValidationError, match="cannot carry"):
        PublishedControlSnapshot(
            controls=(),
            observed_at=NOW,
            authority_mode=SnapshotAuthorityMode.NON_AUTHORITATIVE_CONFORMANCE,
            host_authority_refs=(
                ObjectRef(
                    namespace="controlspec.host",
                    object_type="controlspec.host.authority",
                    object_id="authority-1",
                    version="1",
                    digest=digest("authority"),
                ),
            ),
            supported_extensions=(),
            display_extensions=(),
            supported_verifiers=(),
        )


def test_snapshot_digest_binds_exact_controls_and_mode() -> None:
    value = snapshot(control())
    assert verify_snapshot(value)
    assert not verify_snapshot(
        value.model_copy(update={"observed_at": "2026-08-20T12:01:00.000000Z"})
    )
