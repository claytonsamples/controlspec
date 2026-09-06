"""Exact JSON-pointer resolution and closed tri-state predicates."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from assurance.controlspec.contracts import ActionIntent, Predicate


class PredicateResult(StrEnum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


class PointerStatus(StrEnum):
    PRESENT = "present"
    MISSING = "missing"


class PointerError(ValueError):
    """The pointer is structurally outside the accepted bounded profile."""


def evaluation_document(intent: ActionIntent) -> dict[str, Any]:
    return {
        "actor": intent.actor.model_dump(mode="json", by_alias=True),
        "action": intent.action.model_dump(mode="json", by_alias=True),
        "resource": intent.resource.model_dump(mode="json", by_alias=True),
        "context": intent.context,
    }


def _decode_segment(segment: str) -> str:
    result: list[str] = []
    index = 0
    while index < len(segment):
        if segment[index] != "~":
            result.append(segment[index])
            index += 1
            continue
        if index + 1 >= len(segment) or segment[index + 1] not in {"0", "1"}:
            raise PointerError("JSON pointer contains an invalid escape")
        result.append("~" if segment[index + 1] == "0" else "/")
        index += 2
    return "".join(result)


def resolve_pointer(document: dict[str, Any], pointer: str) -> tuple[PointerStatus, Any]:
    if not pointer.startswith("/"):
        raise PointerError("JSON pointer must be absolute")
    segments = pointer.split("/")[1:]
    if not segments or segments[0] not in {"actor", "action", "resource", "context"}:
        raise PointerError("JSON pointer root is not permitted")
    current: Any = document
    for encoded in segments:
        segment = _decode_segment(encoded)
        if isinstance(current, dict):
            if segment not in current:
                return PointerStatus.MISSING, None
            current = current[segment]
        elif isinstance(current, list | tuple):
            if (
                segment == "-"
                or not segment.isdigit()
                or (len(segment) > 1 and segment.startswith("0"))
            ):
                raise PointerError("array index must be canonical nonnegative decimal")
            index = int(segment)
            if index >= len(current):
                return PointerStatus.MISSING, None
            current = current[index]
        else:
            return PointerStatus.MISSING, None
    return PointerStatus.PRESENT, current


def _equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    if type(left) is not type(right):
        return False
    return bool(left == right)


def evaluate_predicate(
    predicate: Predicate,
    document: dict[str, Any],
) -> PredicateResult:
    status, resolved = resolve_pointer(document, predicate.path)
    if predicate.operator == "exists":
        present = status is PointerStatus.PRESENT
        return PredicateResult.TRUE if present is predicate.expected else PredicateResult.FALSE
    if status is PointerStatus.MISSING:
        return PredicateResult.UNKNOWN
    if predicate.operator == "eq":
        return PredicateResult.TRUE if _equal(resolved, predicate.value) else PredicateResult.FALSE
    if predicate.operator == "in":
        return (
            PredicateResult.TRUE
            if any(_equal(resolved, candidate) for candidate in predicate.values)
            else PredicateResult.FALSE
        )
    if (
        not isinstance(resolved, int)
        or isinstance(resolved, bool)
        or not isinstance(predicate.value, int)
        or isinstance(predicate.value, bool)
    ):
        return PredicateResult.UNKNOWN
    operation = {
        "lt": resolved < predicate.value,
        "lte": resolved <= predicate.value,
        "gt": resolved > predicate.value,
        "gte": resolved >= predicate.value,
    }[predicate.operator]
    return PredicateResult.TRUE if operation else PredicateResult.FALSE
