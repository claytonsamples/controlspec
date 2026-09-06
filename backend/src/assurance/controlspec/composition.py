"""Total deterministic reducer for selected portable Control outcomes."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from assurance.contracts.canonical import canonical_json
from assurance.controlspec.contracts import (
    ApprovalRequirement,
    ConditionResult,
    ControlEffect,
    ControlRef,
    CoreRouteKind,
    EvidenceRequirement,
    FailureEffect,
    NamespacedValue,
    Route,
    Verdict,
)
from assurance.controlspec.requirements import RequirementAssessment
from assurance.controlspec.selection import AppliedControlOutcome

NO_APPLICABLE_PUBLISHED_CONTROL = "controlspec.core.no_applicable_published_control"


def safety_route(*, conflict: bool = False) -> Route:
    return Route(
        schema="controlspec/v0/route",
        namespace="controlspec.core",
        route_id="conflict-block" if conflict else "fail-closed-block",
        kind=CoreRouteKind.BLOCK,
        target_ref=None,
        parameters={},
        requires_recheck=False,
        extensions={},
    )


def _unique[ValueT](values: Iterable[ValueT]) -> tuple[ValueT, ...]:
    keyed: dict[bytes, ValueT] = {}
    for value in values:
        keyed.setdefault(canonical_json(value), value)
    return tuple(keyed[key] for key in sorted(keyed))


@dataclass(frozen=True)
class CompositionResult:
    verdict: Verdict
    route: Route
    conditions: tuple[ConditionResult, ...]
    approval_requirements: tuple[ApprovalRequirement, ...]
    required_evidence: tuple[EvidenceRequirement, ...]
    applied_controls: tuple[ControlRef, ...]
    explanation_codes: tuple[NamespacedValue, ...]
    requires_recheck: bool


def _verdict(value: ControlEffect | FailureEffect) -> str:
    return value.verdict


def _route(value: ControlEffect | FailureEffect) -> Route | None:
    return value.route


def compose(
    outcomes: tuple[AppliedControlOutcome, ...],
    assessment: RequirementAssessment,
) -> CompositionResult:
    if not outcomes:
        return CompositionResult(
            verdict=Verdict.BLOCK,
            route=safety_route(),
            conditions=(),
            approval_requirements=(),
            required_evidence=(),
            applied_controls=(),
            explanation_codes=(NO_APPLICABLE_PUBLISHED_CONTROL,),
            requires_recheck=False,
        )

    values: list[ControlEffect | FailureEffect] = [item.outcome for item in outcomes]
    values.extend(failure for _, failure, _ in assessment.failures)
    values.extend(assessment.profile_outcomes)
    codes: list[NamespacedValue] = [item.outcome.code for item in outcomes] + list(
        assessment.explanation_codes
    )
    block_routes = [
        route
        for value in values
        if _verdict(value) == "block" and (route := _route(value)) is not None
    ]
    if assessment.independence_failed:
        block_routes.append(safety_route())
    mandatory_routes = [
        route
        for value in values
        if _verdict(value) == "route" and (route := _route(value)) is not None
    ]
    distinct_routes = _unique(mandatory_routes)
    if block_routes:
        verdict = Verdict.BLOCK
        route = _unique(block_routes)[0]
        codes.append(
            "controlspec.core.approval.independence_failed"
            if assessment.independence_failed
            else "controlspec.core.explicit_block"
        )
    elif len(distinct_routes) > 1:
        verdict = Verdict.CONFLICT
        route = safety_route(conflict=True)
        codes.append("controlspec.core.route.conflict")
    elif distinct_routes:
        verdict = Verdict.ROUTE
        route = distinct_routes[0]
        codes.append("controlspec.core.route.required")
    elif any(_verdict(value) == "require_approval" for value in values):
        verdict = Verdict.REQUIRE_APPROVAL
        base_routes = _unique(value.route for value in values if isinstance(value, ControlEffect))
        route = base_routes[0] if base_routes else safety_route()
        codes.append("controlspec.core.approval.required")
    elif any(_verdict(value) == "allow_with_conditions" for value in values):
        verdict = Verdict.ALLOW_WITH_CONDITIONS
        route = _unique(value.route for value in values if isinstance(value, ControlEffect))[0]
        codes.append("controlspec.core.allow_with_conditions")
    else:
        verdict = Verdict.ALLOW
        route = _unique(value.route for value in values if isinstance(value, ControlEffect))[0]
        codes.append("controlspec.core.allow")
    applied = _unique(item.control_ref for item in outcomes)
    return CompositionResult(
        verdict=verdict,
        route=route,
        conditions=_unique(assessment.condition_results),
        approval_requirements=_unique(assessment.approval_requirements),
        required_evidence=_unique(assessment.evidence_requirements),
        applied_controls=applied,
        explanation_codes=_unique(codes),
        requires_recheck=(
            verdict in {Verdict.REQUIRE_APPROVAL, Verdict.ROUTE} or route.requires_recheck
        ),
    )
