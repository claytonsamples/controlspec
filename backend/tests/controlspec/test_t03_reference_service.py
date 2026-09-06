from __future__ import annotations

import pytest

from assurance.controlspec.api_models import (
    CatalogEntryMetadata,
    DecideRequest,
    EvaluationOptions,
    PackSelection,
    RecheckRequest,
)
from assurance.controlspec.canonical import finalize_object
from assurance.controlspec.contracts import ControlStatus, Verdict
from assurance.controlspec.reference_catalog import (
    ImmutableReferenceCatalog,
    ReferencePackArtifact,
    load_default_reference_catalog,
)
from assurance.controlspec.reference_service import (
    ImmutableScenarioFactProvider,
    ReferenceControlPlaneService,
    ReferenceServiceError,
)
from tests.controlspec.test_t02_examples import _intent

NOW = "2026-08-20T12:00:00.000000Z"


def _personal_artifact() -> ReferencePackArtifact:
    catalog = load_default_reference_catalog()
    summary = next(
        item
        for item in catalog.list_packs().items
        if item.namespace == "personal.agent.spending"
    )
    detail = catalog.get_pack(summary.catalog_id)
    return ReferencePackArtifact(pack=detail.pack, metadata=summary.metadata)


def _intent_42():
    return _intent(
        "personal.agent.spending",
        intent_id="service-42",
        domain_action="personal.purchase",
        resource_type="personal.cart",
        context={
            "personal.spending.total_minor_units": 4200,
            "personal.spending.recurring": False,
        },
    )


def _selection(catalog: ImmutableReferenceCatalog, pack_id: str) -> PackSelection:
    summary = next(
        item for item in catalog.list_packs().items if item.pack_id == pack_id
    )
    return PackSelection(
        catalog_id=summary.catalog_id,
        semantic_digest=summary.semantic_digest,
    )


@pytest.mark.parametrize("status", (ControlStatus.DRAFT, ControlStatus.RETIRED))
def test_draft_and_retired_controls_never_apply(status: ControlStatus) -> None:
    source = _personal_artifact()
    control = finalize_object(
        source.pack.controls[0].model_copy(
            update={"status": status, "semantic_digest": None}
        )
    )
    pack = finalize_object(
        source.pack.model_copy(
            update={
                "pack_id": f"{status.value}-only",
                "controls": (control,),
                "semantic_digest": None,
            }
        )
    )
    catalog = ImmutableReferenceCatalog(
        (ReferencePackArtifact(pack=pack, metadata=source.metadata),)
    )
    result = ReferenceControlPlaneService(catalog=catalog).decide(
        DecideRequest(
            schema="controlspec/api/v0/decide-request",
            action_intent=_intent_42(),
            selection=_selection(catalog, pack.pack_id),
            options=EvaluationOptions(reference_time=NOW),
        )
    )
    assert result.decision.verdict is Verdict.BLOCK
    assert result.decision.applied_controls == ()
    assert "controlspec.core.no_applicable_published_control" in result.explanation_codes


def test_recheck_rejects_a_different_control_version_without_refreshing() -> None:
    original = _personal_artifact()
    v2_controls = tuple(
        finalize_object(
            control.model_copy(
                update={"version": "0.2.0", "semantic_digest": None}
            )
        )
        for control in original.pack.controls
    )
    v2_pack = finalize_object(
        original.pack.model_copy(
            update={
                "pack_id": "spending-v2",
                "version": "0.2.0",
                "controls": v2_controls,
                "semantic_digest": None,
            }
        )
    )
    catalog = ImmutableReferenceCatalog(
        (
            original,
            ReferencePackArtifact(pack=v2_pack, metadata=original.metadata),
        )
    )
    service = ReferenceControlPlaneService(catalog=catalog)
    intent = _intent_42()
    prior = service.decide(
        DecideRequest(
            schema="controlspec/api/v0/decide-request",
            action_intent=intent,
            selection=_selection(catalog, original.pack.pack_id),
            options=EvaluationOptions(reference_time=NOW),
        )
    ).decision
    checked = service.recheck(
        RecheckRequest(
            schema="controlspec/api/v0/recheck-request",
            original_action_intent=intent,
            prior_decision=prior,
            current_action_intent=intent,
            selection=_selection(catalog, v2_pack.pack_id),
            options=EvaluationOptions(reference_time=NOW),
        )
    )
    assert checked.recheck.valid is False
    assert checked.comparisons.controls.value == "changed"
    assert checked.recheck.current_decision_ref is None


def test_catalog_metadata_cannot_enable_a_disabled_reference_pack_by_selection() -> None:
    source = _personal_artifact()
    catalog = ImmutableReferenceCatalog(
        (
            ReferencePackArtifact(
                pack=source.pack,
                metadata=CatalogEntryMetadata(
                    reference_evaluation_enabled=False,
                    profile_kind="portable_core",
                    source="Catalog-only example; evaluation disabled",
                ),
            ),
        )
    )
    with pytest.raises(ValueError, match="not enabled"):
        ReferenceControlPlaneService(catalog=catalog).decide(
            DecideRequest(
                schema="controlspec/api/v0/decide-request",
                action_intent=_intent_42(),
                selection=_selection(catalog, source.pack.pack_id),
                options=EvaluationOptions(reference_time=NOW),
            )
        )


def test_exact_scenario_reference_time_does_not_fallback_or_nearest_match() -> None:
    catalog = load_default_reference_catalog()
    scenario = next(
        item
        for item in catalog.scenarios
        if item.fixture_id == "smb-discount-15-direct-self-approval"
    )
    provider = ImmutableScenarioFactProvider(
        release_id=catalog.release_id,
        catalog_digest=catalog.catalog_digest,
        scenarios=catalog.scenarios,
        enterprise_loader=lambda _scenario: (_ for _ in ()).throw(
            AssertionError("portable resolution must not load enterprise")
        ),
    )
    service = ReferenceControlPlaneService(catalog=catalog, fact_provider=provider)
    exact = service.decide(
        DecideRequest(
            schema="controlspec/api/v0/decide-request",
            action_intent=scenario.intent,
            selection=scenario.selection,
            options=EvaluationOptions(reference_time=scenario.reference_time),
        )
    )
    wrong_time = service.decide(
        DecideRequest(
            schema="controlspec/api/v0/decide-request",
            action_intent=scenario.intent,
            selection=scenario.selection,
            options=EvaluationOptions(reference_time="2026-08-20T12:00:01.000000Z"),
        )
    )
    assert exact.decision.verdict is Verdict.BLOCK
    assert wrong_time.decision.verdict is Verdict.REQUIRE_APPROVAL
    assert exact.catalog_binding.fact_fixture_digest == scenario.semantic_digest
    assert (
        wrong_time.catalog_binding.fact_fixture_digest
        != exact.catalog_binding.fact_fixture_digest
    )


def test_enterprise_leaf_is_loaded_once_after_exact_match() -> None:
    from assurance.controlspec.profiles.reference import (
        load_riskspec_scenario_fact_provider,
    )

    catalog = load_default_reference_catalog()
    scenario = next(
        item
        for item in catalog.scenarios
        if item.fixture_id == "enterprise-high-risk-missing-approval"
    )
    loads = 0

    def load(item):
        nonlocal loads
        loads += 1
        return load_riskspec_scenario_fact_provider(item)

    service = ReferenceControlPlaneService(
        catalog=catalog,
        fact_provider=ImmutableScenarioFactProvider(
            release_id=catalog.release_id,
            catalog_digest=catalog.catalog_digest,
            scenarios=catalog.scenarios,
            enterprise_loader=load,
        ),
    )
    request = DecideRequest(
        schema="controlspec/api/v0/decide-request",
        action_intent=scenario.intent,
        selection=scenario.selection,
        options=EvaluationOptions(reference_time=scenario.reference_time),
    )
    assert service.decide(request).decision.verdict is Verdict.REQUIRE_APPROVAL
    assert service.decide(request).decision.verdict is Verdict.REQUIRE_APPROVAL
    assert loads == 1


def test_provider_detaches_returned_scenario_before_nested_context_mutation() -> None:
    from assurance.controlspec.profiles.reference import (
        load_riskspec_scenario_fact_provider,
    )

    catalog = load_default_reference_catalog()
    provider_inputs = catalog.scenarios
    provider = ImmutableScenarioFactProvider(
        release_id=catalog.release_id,
        catalog_digest=catalog.catalog_digest,
        scenarios=provider_inputs,
        enterprise_loader=load_riskspec_scenario_fact_provider,
    )
    attacker_owned = next(
        item
        for item in provider_inputs
        if item.fixture_id == "enterprise-high-risk-missing-approval"
    )
    attacker_owned.intent.context["verifier.attack"] = {"nested": "mutated"}
    pristine = next(
        item
        for item in catalog.scenarios
        if item.fixture_id == attacker_owned.fixture_id
    )
    assert "verifier.attack" not in pristine.intent.context

    result = ReferenceControlPlaneService(
        catalog=catalog,
        fact_provider=provider,
    ).decide(
        DecideRequest(
            schema="controlspec/api/v0/decide-request",
            action_intent=pristine.intent,
            selection=pristine.selection,
            options=EvaluationOptions(reference_time=pristine.reference_time),
        )
    )
    assert result.decision.verdict is Verdict.REQUIRE_APPROVAL
    assert result.catalog_binding.fact_fixture_digest == pristine.semantic_digest


def test_provider_fails_closed_on_impossible_private_scenario_corruption() -> None:
    from assurance.controlspec.profiles.reference import (
        load_riskspec_scenario_fact_provider,
    )

    catalog = load_default_reference_catalog()
    provider = ImmutableScenarioFactProvider(
        release_id=catalog.release_id,
        catalog_digest=catalog.catalog_digest,
        scenarios=catalog.scenarios,
        enterprise_loader=load_riskspec_scenario_fact_provider,
    )
    retained = next(
        item
        for item in provider._scenarios
        if item.fixture_id == "enterprise-high-risk-missing-approval"
    )
    retained.intent.context["verifier.private_corruption"] = {
        "nested": "mutated"
    }
    pristine = next(
        item
        for item in catalog.scenarios
        if item.fixture_id == retained.fixture_id
    )
    service = ReferenceControlPlaneService(catalog=catalog, fact_provider=provider)
    with pytest.raises(ReferenceServiceError, match="integrity"):
        service.decide(
            DecideRequest(
                schema="controlspec/api/v0/decide-request",
                action_intent=pristine.intent,
                selection=pristine.selection,
                options=EvaluationOptions(reference_time=pristine.reference_time),
            )
        )
