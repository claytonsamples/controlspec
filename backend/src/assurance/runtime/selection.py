"""Exact lifecycle-derived selection of effective immutable policy versions."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from assurance.contracts.canonical import model_canonical_hash
from assurance.contracts.common import ObjectHashReference, VersionedSpecReference
from assurance.contracts.objects import (
    ActionIntent,
    LifecycleEvent,
    RiskSpecCorrection,
    RiskSpecVersion,
    risk_spec_semantic_hash,
)
from assurance.domain import LifecycleState
from assurance.domain.enums import WorkflowEnvironment

from .models import PolicyCatalogSnapshot, RuntimeErrorCode, RuntimeRejected


class PolicyCatalog(Protocol):
    def snapshot(self, *, tenant_id: UUID) -> PolicyCatalogSnapshot: ...


class FrozenPolicyCatalog:
    """Read-only adapter useful for retained replay inputs and local fixtures."""

    def __init__(
        self,
        *,
        versions: Sequence[RiskSpecVersion],
        lifecycle_events: Sequence[LifecycleEvent],
    ) -> None:
        self._snapshot = PolicyCatalogSnapshot(
            versions=list(versions),
            lifecycle_events=list(lifecycle_events),
        )

    def snapshot(self, *, tenant_id: UUID) -> PolicyCatalogSnapshot:
        return PolicyCatalogSnapshot(
            versions=[item for item in self._snapshot.versions if item.tenant_id == tenant_id],
            lifecycle_events=[
                item for item in self._snapshot.lifecycle_events if item.tenant_id == tenant_id
            ],
        )


@dataclass(frozen=True, slots=True)
class SelectedPolicy:
    specs: tuple[RiskSpecVersion, ...]
    lifecycle_event_refs: tuple[ObjectHashReference, ...]
    human_decision_refs: tuple[ObjectHashReference, ...]
    no_safe_policy: bool
    ambiguous: bool


def spec_reference(spec: RiskSpecVersion) -> VersionedSpecReference:
    return VersionedSpecReference(
        tenant_id=spec.tenant_id,
        spec_version_id=spec.object_id,
        module_key=spec.module_key,
        version=spec.version,
        content_hash=spec.content_hash,
        semantic_hash=spec.semantic_hash,
    )


def event_reference(event: LifecycleEvent) -> ObjectHashReference:
    return ObjectHashReference(
        tenant_id=event.tenant_id,
        object_id=event.object_id,
        object_hash=event.event_hash,
    )


def _state_at(
    *,
    spec: RiskSpecVersion,
    events: Sequence[LifecycleEvent],
    trusted_time: datetime,
) -> tuple[LifecycleState | None, tuple[LifecycleEvent, ...]]:
    relevant = sorted(
        (event for event in events if event.spec_version_ref.spec_version_id == spec.object_id),
        key=lambda event: event.sequence,
    )
    prior: LifecycleEvent | None = None
    state: LifecycleState | None = None
    applied: list[LifecycleEvent] = []
    for event in relevant:
        if (
            event.spec_version_ref != spec_reference(spec)
            or event.exact_content_hash != spec.content_hash
            or model_canonical_hash(event, excluded_fields=("event_hash",)) != event.event_hash
            or event.sequence != (1 if prior is None else prior.sequence + 1)
            or event.prior_event_ref != (None if prior is None else event_reference(prior))
            or event.prior_state is not (None if prior is None else prior.next_state)
        ):
            raise RuntimeRejected(
                RuntimeErrorCode.LIFECYCLE_HASH_INVALID,
                str(spec.object_id),
            )
        prior = event
        applies_at = event.effective_at or event.event_at
        if applies_at <= trusted_time:
            state = event.next_state
            applied.append(event)
    return state, tuple(applied)


class PublishedPolicySelector:
    """Select by trusted lifecycle state, effective time, and exact coverage."""

    def __init__(self, catalog: PolicyCatalog) -> None:
        self._catalog = catalog

    def catalog_snapshot(self, *, tenant_id: UUID) -> PolicyCatalogSnapshot:
        return self._catalog.snapshot(tenant_id=tenant_id)

    def select(
        self,
        *,
        intent: ActionIntent,
        trusted_time: datetime,
        policy_namespace: str | None,
        environment: WorkflowEnvironment | None = None,
    ) -> SelectedPolicy:
        catalog = self.catalog_snapshot(tenant_id=intent.tenant_id)
        events = tuple(catalog.lifecycle_events)
        candidates: list[tuple[RiskSpecVersion, tuple[LifecycleEvent, ...]]] = []
        for spec in catalog.versions:
            if spec.tenant_id != intent.tenant_id:
                continue
            if model_canonical_hash(spec, excluded_fields=("content_hash",)) != spec.content_hash:
                raise RuntimeRejected(RuntimeErrorCode.POLICY_HASH_INVALID, str(spec.object_id))
            expected_semantic = risk_spec_semantic_hash(spec)
            if expected_semantic != spec.semantic_hash:
                raise RuntimeRejected(RuntimeErrorCode.POLICY_HASH_INVALID, str(spec.object_id))
            state, applied = _state_at(
                spec=spec,
                events=events,
                trusted_time=trusted_time,
            )
            coverage = spec.policy_module.coverage
            if (
                state is not LifecycleState.PUBLISHED
                or (spec.effective_from is not None and trusted_time < spec.effective_from)
                or (spec.effective_until is not None and trusted_time >= spec.effective_until)
                or coverage.canonical_action is not intent.canonical_action
                or coverage.domain_verb is not intent.domain_verb
                or coverage.resource_type is not intent.resource.resource_type
                or coverage.principal_type is not intent.principal.principal_type
                or coverage.policy_namespace != policy_namespace
                or (
                    isinstance(spec, RiskSpecCorrection)
                    and (environment is None or environment not in spec.environments)
                )
            ):
                continue
            candidates.append((spec, applied))

        by_module: dict[str, list[RiskSpecVersion]] = {}
        for spec, _ in candidates:
            by_module.setdefault(spec.module_key, []).append(spec)
        ambiguous = any(len(items) > 1 for items in by_module.values())
        if ambiguous:
            return SelectedPolicy((), (), (), False, True)

        selected = tuple(
            sorted(
                (spec for spec, _ in candidates),
                key=lambda item: (
                    item.module_key,
                    item.version,
                    item.semantic_hash,
                    item.content_hash,
                ),
            )
        )
        selected_refs = {spec_reference(spec) for spec in selected}
        for spec in selected:
            if any(
                reference not in selected_refs for reference in (*spec.dependencies, *spec.overlays)
            ):
                return SelectedPolicy((), (), (), True, False)

        selected_ids = {spec.object_id for spec in selected}
        selected_events = tuple(
            event
            for _, applied in candidates
            for event in applied
            if event.spec_version_ref.spec_version_id in selected_ids
        )
        lifecycle_refs = tuple(
            sorted(
                {event_reference(event) for event in selected_events},
                key=lambda ref: (ref.object_id.bytes, ref.object_hash),
            )
        )
        decision_refs = tuple(
            sorted(
                {
                    reference
                    for event in selected_events
                    for reference in event.accepted_decision_refs
                },
                key=lambda ref: (ref.object_id.bytes, ref.object_hash),
            )
        )
        return SelectedPolicy(
            selected,
            lifecycle_refs,
            decision_refs,
            not selected,
            False,
        )

    def select_complete(
        self,
        *,
        intent: ActionIntent,
        trusted_time: datetime,
        environment: WorkflowEnvironment | None = None,
    ) -> SelectedPolicy:
        """Select every applicable root and its exact dependency closure server-side."""

        catalog = self.catalog_snapshot(tenant_id=intent.tenant_id)
        events = tuple(catalog.lifecycle_events)
        state_cache: dict[
            UUID,
            tuple[LifecycleState | None, tuple[LifecycleEvent, ...]],
        ] = {}

        def validate(spec: RiskSpecVersion) -> tuple[LifecycleEvent, ...] | None:
            if model_canonical_hash(spec, excluded_fields=("content_hash",)) != spec.content_hash:
                raise RuntimeRejected(RuntimeErrorCode.POLICY_HASH_INVALID, str(spec.object_id))
            expected_semantic = risk_spec_semantic_hash(spec)
            if expected_semantic != spec.semantic_hash:
                raise RuntimeRejected(RuntimeErrorCode.POLICY_HASH_INVALID, str(spec.object_id))
            if spec.object_id not in state_cache:
                state_cache[spec.object_id] = _state_at(
                    spec=spec,
                    events=events,
                    trusted_time=trusted_time,
                )
            state, applied = state_cache[spec.object_id]
            if (
                state is not LifecycleState.PUBLISHED
                or (spec.effective_from is not None and trusted_time < spec.effective_from)
                or (spec.effective_until is not None and trusted_time >= spec.effective_until)
            ):
                return None
            return applied

        def claims_effective_published(spec: RiskSpecVersion) -> bool:
            state: LifecycleState | None = None
            for event in sorted(
                (
                    item
                    for item in events
                    if item.spec_version_ref.spec_version_id == spec.object_id
                ),
                key=lambda item: item.sequence,
            ):
                applies_at = event.effective_at or event.event_at
                if applies_at <= trusted_time:
                    state = event.next_state
            return state is LifecycleState.PUBLISHED

        roots: list[RiskSpecVersion] = []
        for spec in catalog.versions:
            coverage = spec.policy_module.coverage
            if (
                spec.tenant_id == intent.tenant_id
                and coverage.canonical_action is intent.canonical_action
                and coverage.domain_verb is intent.domain_verb
                and coverage.resource_type is intent.resource.resource_type
                and coverage.principal_type is intent.principal.principal_type
                and (
                    not isinstance(spec, RiskSpecCorrection)
                    or (environment is not None and environment in spec.environments)
                )
                and claims_effective_published(spec)
                and validate(spec) is not None
            ):
                roots.append(spec)
        if not roots:
            return SelectedPolicy((), (), (), True, False)
        if any(len(items) > 1 for items in _group_specs_by_module(roots).values()):
            return SelectedPolicy((), (), (), False, True)

        by_reference = {spec_reference(spec): spec for spec in catalog.versions}
        selected: dict[VersionedSpecReference, RiskSpecVersion] = {}
        applied_events: dict[UUID, tuple[LifecycleEvent, ...]] = {}
        visiting: set[VersionedSpecReference] = set()

        def add_closure(spec: RiskSpecVersion) -> bool:
            reference = spec_reference(spec)
            if reference in visiting:
                return False
            if reference in selected:
                return True
            if isinstance(spec, RiskSpecCorrection) and (
                environment is None or environment not in spec.environments
            ):
                return False
            visiting.add(reference)
            applied = validate(spec)
            if applied is None:
                return False
            for dependency_ref in (*spec.dependencies, *spec.overlays):
                dependency = by_reference.get(dependency_ref)
                if (
                    dependency is None
                    or dependency.tenant_id != intent.tenant_id
                    or not add_closure(dependency)
                ):
                    return False
            visiting.remove(reference)
            selected[reference] = spec
            applied_events[spec.object_id] = applied
            return True

        if not all(add_closure(spec) for spec in roots):
            return SelectedPolicy((), (), (), True, False)
        if any(
            len(items) > 1 for items in _group_specs_by_module(tuple(selected.values())).values()
        ):
            return SelectedPolicy((), (), (), False, True)

        specs = tuple(
            sorted(
                selected.values(),
                key=lambda item: (
                    item.module_key,
                    item.version,
                    item.semantic_hash,
                    item.content_hash,
                ),
            )
        )
        lifecycle_refs = tuple(
            sorted(
                {
                    event_reference(event)
                    for applied in applied_events.values()
                    for event in applied
                },
                key=lambda ref: (ref.object_id.bytes, ref.object_hash),
            )
        )
        decision_refs = tuple(
            sorted(
                {
                    reference
                    for applied in applied_events.values()
                    for event in applied
                    for reference in event.accepted_decision_refs
                },
                key=lambda ref: (ref.object_id.bytes, ref.object_hash),
            )
        )
        return SelectedPolicy(specs, lifecycle_refs, decision_refs, False, False)


def _group_specs_by_module(
    specs: Sequence[RiskSpecVersion],
) -> dict[str, list[RiskSpecVersion]]:
    grouped: dict[str, list[RiskSpecVersion]] = {}
    for spec in specs:
        grouped.setdefault(spec.module_key, []).append(spec)
    return grouped
