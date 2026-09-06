"""Fixed non-authoritative RiskSpec profile facts for the T03 reference app.

The generic ControlSpec service never interprets RiskSpec.  This isolated leaf
loads exact T01 projections and asks the accepted T02 profile resolver to
re-verify them against the selected snapshot.  A missing exact case contributes
no fact, which makes the profile requirement fail closed.
"""

from __future__ import annotations

from importlib import resources

from assurance.contracts.canonical import canonical_json
from assurance.controlspec.contracts import ActionIntent, Decision, DecisionRef
from assurance.controlspec.facts import EvaluationFacts, PublishedControlSnapshot
from assurance.controlspec.mapping import control_ref
from assurance.controlspec.profiles.riskspec import RiskSpecProfileError, RiskSpecProfileResolver
from assurance.controlspec.reference_catalog import (
    ReferenceFactFixture,
    ReferenceScenarioFixture,
    fact_fixture_digest,
)
from assurance.controlspec.reference_service import ReferenceFactSet

_DATA_PACKAGE = "assurance.controlspec.reference_catalog_data.v0.profile_cases"


class RiskSpecReferenceCase(ReferenceFactFixture):
    """Compatibility name for one exact enterprise profile fixture."""


class RiskSpecReferenceFactProvider:
    """Resolve only package-fixed, exact RiskSpec v1.1 projection cases."""

    def __init__(self, cases: tuple[RiskSpecReferenceCase, ...]) -> None:
        self._cases = cases
        self._fixture_digest = fact_fixture_digest(cases)
        self._resolver = RiskSpecProfileResolver()

    def facts_for(
        self,
        *,
        intent: ActionIntent,
        snapshot: PublishedControlSnapshot,
        prior_decision: Decision | None,
    ) -> ReferenceFactSet:
        del prior_decision
        assessments = []
        for case in self._cases:
            if case.intent != intent:
                continue
            expected = set(case.control_refs)
            selected = tuple(
                control for control in snapshot.controls if control_ref(control) in expected
            )
            if {control_ref(control) for control in selected} != expected:
                continue
            for control in selected:
                try:
                    assessments.append(
                        self._resolver.assess(
                            intent=intent,
                            control=control,
                            snapshot=snapshot,
                            retained_decision=case.retained_decision,
                        )
                    )
                except RiskSpecProfileError:
                    continue
        return ReferenceFactSet(
            fixture_digest=self._fixture_digest,
            facts=EvaluationFacts(
                approval_basis_ref=None,
                approvals=(),
                evidence=(),
                profile_assessments=tuple(assessments),
            ),
        )


def load_default_riskspec_reference_fact_provider() -> RiskSpecReferenceFactProvider:
    """Load exact canonical profile cases; YAML and runtime inference are forbidden."""

    package = resources.files(_DATA_PACKAGE)
    cases: list[RiskSpecReferenceCase] = []
    for item in sorted(package.iterdir(), key=lambda value: value.name):
        if item.name.startswith("_") or not item.name.endswith(".json"):
            continue
        raw = item.read_bytes()
        case = RiskSpecReferenceCase.model_validate_json(raw, strict=True)
        if canonical_json(case) != raw:
            raise ValueError("RiskSpec reference case is not canonical JSON")
        if any(
            not item.namespace.startswith("riskspec.enterprise.")
            for item in case.control_refs
        ):
            raise ValueError("RiskSpec reference cases must remain enterprise namespaced")
        cases.append(case)
    return RiskSpecReferenceFactProvider(tuple(cases))


class RiskSpecScenarioFactProvider:
    """Derive profile facts from one already-validated exact scenario object."""

    def __init__(self, scenario: ReferenceScenarioFixture) -> None:
        if scenario.profile_kind != "riskspec_enterprise":
            raise ValueError("RiskSpec scenario leaf requires an enterprise fixture")
        if scenario.retained_decision is None or scenario.semantic_digest is None:
            raise ValueError("RiskSpec scenario is incomplete")
        self._scenario = scenario
        self._resolver = RiskSpecProfileResolver()

    def facts_for(
        self,
        *,
        intent: ActionIntent,
        snapshot: PublishedControlSnapshot,
        prior_decision: Decision | None,
    ) -> ReferenceFactSet:
        del prior_decision
        scenario = self._scenario
        retained_decision = scenario.retained_decision
        fixture_digest = scenario.semantic_digest
        assert retained_decision is not None
        assert fixture_digest is not None
        if intent != scenario.intent:
            raise ValueError("enterprise leaf received another ActionIntent")
        selected_refs = tuple(control_ref(control) for control in snapshot.controls)
        if selected_refs != scenario.control_refs:
            raise ValueError("enterprise leaf received another Control set")
        assessments = tuple(
            self._resolver.assess(
                intent=intent,
                control=control,
                snapshot=snapshot,
                retained_decision=retained_decision,
            )
            for control in snapshot.controls
        )
        basis = scenario.approval_basis_decision
        return ReferenceFactSet(
            fixture_digest=fixture_digest,
            facts=EvaluationFacts(
                approval_basis_ref=(
                    DecisionRef(
                        namespace=basis.namespace,
                        decision_id=basis.decision_id,
                        semantic_digest=basis.semantic_digest,
                    )
                    if basis is not None and basis.semantic_digest is not None
                    else None
                ),
                approvals=scenario.approvals,
                evidence=(),
                profile_assessments=assessments,
            ),
        )


def load_riskspec_scenario_fact_provider(
    scenario: ReferenceScenarioFixture,
) -> RiskSpecScenarioFactProvider:
    """Consume only the coordinator's already-loaded immutable scenario."""

    return RiskSpecScenarioFactProvider(scenario)
