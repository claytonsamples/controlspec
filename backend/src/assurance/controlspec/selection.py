"""Snapshot validation, effective control selection, and predicate routing."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from assurance.controlspec.canonical import canonical_object_digest
from assurance.controlspec.contracts import (
    ActionIntent,
    Control,
    ControlEffect,
    ControlRef,
    ControlStatus,
    EvidenceRequirement,
    FailureEffect,
    ProfileRequirement,
)
from assurance.controlspec.facts import PublishedControlSnapshot, verify_snapshot
from assurance.controlspec.predicate import (
    PredicateResult,
    evaluate_predicate,
    evaluation_document,
)


class SnapshotValidationError(ValueError):
    """Trusted snapshot input is malformed or internally inconsistent."""


@dataclass(frozen=True)
class AppliedControlOutcome:
    control: Control
    control_ref: ControlRef
    outcome: ControlEffect | FailureEffect
    predicate_results: tuple[PredicateResult, ...]
    used_unknown_failure: bool


def control_reference(control: Control) -> ControlRef:
    if control.semantic_digest is None:
        raise SnapshotValidationError("every snapshot Control requires a semantic digest")
    return ControlRef(
        namespace=control.namespace,
        control_id=control.control_id,
        version=control.version,
        semantic_digest=control.semantic_digest,
    )


def _used_verifiers(control: Control) -> set[str]:
    result = {condition.verifier for condition in control.effect.conditions}
    for requirement in control.effect.requirements:
        if isinstance(requirement, EvidenceRequirement | ProfileRequirement):
            result.add(requirement.verifier)
    return result


def validate_snapshot(snapshot: PublishedControlSnapshot) -> None:
    if not verify_snapshot(snapshot):
        raise SnapshotValidationError("snapshot digest does not match exact content")
    supported_extensions = set(snapshot.supported_extensions)
    supported_verifiers = set(snapshot.supported_verifiers)
    display_extensions = frozenset(snapshot.display_extensions)
    identities: dict[tuple[str, str, str], str] = {}
    for control in snapshot.controls:
        if control.semantic_digest != canonical_object_digest(
            control,
            display_extensions=display_extensions,
        ):
            raise SnapshotValidationError("Control semantic digest is invalid")
        unsupported_extensions = set(control.extensions) - supported_extensions
        if unsupported_extensions:
            raise SnapshotValidationError("snapshot contains an unsupported extension")
        if not _used_verifiers(control) <= supported_verifiers:
            raise SnapshotValidationError("snapshot contains an unsupported verifier")
        identity = (control.namespace, control.control_id, control.version)
        previous = identities.setdefault(identity, control.semantic_digest)
        if previous != control.semantic_digest:
            raise SnapshotValidationError("duplicate Control identity has unequal semantics")


def _time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")


def _effective(control: Control, observed_at: str) -> bool:
    observed = _time(observed_at)
    return (
        control.status is ControlStatus.PUBLISHED
        and (control.effective_from is None or _time(control.effective_from) <= observed)
        and (control.effective_until is None or observed < _time(control.effective_until))
    )


def _core_match(control: Control, intent: ActionIntent) -> bool:
    return (
        control.namespace == intent.namespace
        and intent.actor.type in control.match.actor_types
        and intent.action.type in control.match.action_types
        and intent.action.domain_action in control.match.domain_actions
        and intent.resource.type in control.match.resource_types
    )


def select_controls(
    intent: ActionIntent,
    snapshot: PublishedControlSnapshot,
) -> tuple[AppliedControlOutcome, ...]:
    validate_snapshot(snapshot)
    document = evaluation_document(intent)
    selected: list[AppliedControlOutcome] = []
    for control in snapshot.controls:
        if not _effective(control, snapshot.observed_at) or not _core_match(control, intent):
            continue
        results = tuple(
            evaluate_predicate(predicate, document) for predicate in control.match.predicates
        )
        if PredicateResult.FALSE in results:
            continue
        unknown = PredicateResult.UNKNOWN in results
        selected.append(
            AppliedControlOutcome(
                control=control,
                control_ref=control_reference(control),
                outcome=control.on_unknown if unknown else control.effect,
                predicate_results=results,
                used_unknown_failure=unknown,
            )
        )
    return tuple(
        sorted(
            selected,
            key=lambda item: (
                item.control_ref.namespace,
                item.control_ref.control_id,
                item.control_ref.version,
                item.control_ref.semantic_digest,
            ),
        )
    )
