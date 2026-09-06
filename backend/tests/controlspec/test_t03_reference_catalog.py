from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from assurance.contracts.canonical import canonical_json
from assurance.controlspec.api_models import DecideRequest, EvaluationOptions, PackSelection
from assurance.controlspec.contracts import ControlPack, Verdict
from assurance.controlspec.facts import finalize_fact
from assurance.controlspec.reference_catalog import (
    CatalogBindingMismatchError,
    CatalogItemNotFoundError,
    ImmutableReferenceCatalog,
    ReferenceCatalogError,
    ReferencePackArtifact,
    _validate_default_release_manifest,
    fact_fixture_digest,
    finalize_reference_scenario,
    load_default_reference_catalog,
    load_v0_reference_catalog,
    scenario_fixture_digest,
)
from assurance.controlspec.reference_service import (
    ImmutableScenarioFactProvider,
    ReferenceControlPlaneService,
)


def test_default_catalog_is_exact_canonical_and_non_authoritative() -> None:
    catalog = load_default_reference_catalog()
    packs = catalog.list_packs()
    controls = catalog.list_controls()

    assert len(packs.items) == 4
    assert len(controls.items) == 8
    assert {item.metadata.profile_kind for item in packs.items} == {
        "portable_core",
        "riskspec_enterprise",
    }
    assert all(item.metadata.example_only for item in (*packs.items, *controls.items))
    assert all(item.metadata.non_authoritative for item in (*packs.items, *controls.items))
    assert all(item.status == "published" for item in (*packs.items, *controls.items))
    assert packs.authority.may_authorize_external_effect is False
    assert packs.authority.production_publication is False
    assert packs.authority.durable is False
    assert not catalog.fact_fixtures
    assert len(catalog.scenarios) == 4
    assert catalog.fact_fixture_digest == scenario_fixture_digest(catalog.scenarios)
    assert catalog.fact_fixture_digest != fact_fixture_digest(())
    assert load_default_reference_catalog().catalog_digest == catalog.catalog_digest

    data_root = (
        Path(__file__).parents[2]
        / "src/assurance/controlspec/reference_catalog_data/v0_1_1/packs"
    )
    assert {item.name for item in data_root.glob("*.json")} == {
        "enterprise-supplier-advance.json",
        "enterprise-high-risk-approval.json",
        "personal-agent-spending.json",
        "smb-sales-controls.json",
    }
    for path in data_root.glob("*.json"):
        raw = path.read_bytes()
        assert canonical_json(json.loads(raw)) == raw

    scenario_root = data_root.parent / "scenarios"
    assert {item.name for item in scenario_root.glob("*.json")} == {
        "enterprise-attempted-self-approval.json",
        "enterprise-high-risk-missing-approval.json",
        "enterprise-routine-supplier-advance.json",
        "smb-discount-15-direct-self-approval.json",
    }
    for path in scenario_root.glob("*.json"):
        raw = path.read_bytes()
        assert canonical_json(json.loads(raw)) == raw


def test_catalog_requires_exact_id_and_digest_and_returns_complete_detail() -> None:
    catalog = load_default_reference_catalog()
    summary = catalog.list_packs().items[0]
    detail = catalog.get_pack(summary.catalog_id)
    assert detail.pack.semantic_digest == summary.semantic_digest
    assert detail.summary == summary
    assert detail.control_catalog_ids
    assert detail.catalog_digest == catalog.catalog_digest

    snapshot, binding = catalog.resolve(
        PackSelection(
            catalog_id=summary.catalog_id,
            semantic_digest=summary.semantic_digest,
        ),
        observed_at="2026-08-20T12:00:00.000000Z",
    )
    assert snapshot.authority_mode.value == "non_authoritative_conformance"
    assert snapshot.host_authority_refs == ()
    assert binding.selected_catalog_ids == (summary.catalog_id,)

    with pytest.raises(CatalogBindingMismatchError):
        catalog.resolve(
            PackSelection(
                catalog_id=summary.catalog_id,
                semantic_digest="sha256:" + "0" * 64,
            ),
            observed_at="2026-08-20T12:00:00.000000Z",
        )
    with pytest.raises(CatalogItemNotFoundError):
        catalog.get_pack("controlspec.missing:pack@1.0.0")


def test_personal_and_smb_catalog_artifacts_have_no_riskspec_profile_surface() -> None:
    catalog = load_default_reference_catalog()
    for summary in catalog.list_packs().items:
        if summary.metadata.profile_kind != "portable_core":
            continue
        encoded = canonical_json(catalog.get_pack(summary.catalog_id).pack).lower()
        assert b"supplier" not in encoded
        assert b"riskspec" not in encoded


def test_historical_v01_catalog_identities_remain_exact() -> None:
    catalog = load_v0_reference_catalog()
    assert catalog.catalog_digest == (
        "sha256:2b8825ec2728f4b001693135f21ac6fe023ec7ab1ff748acb4602d8f48e57ff2"
    )
    assert catalog.fact_fixture_digest == (
        "sha256:367e208e97a8f5e369a0899dfcedb274c9c92cb7312a0af28ec52b340b5195d4"
    )


@pytest.mark.parametrize("mutation", ("manifest", "artifact", "missing", "extra"))
def test_v011_manifest_fails_closed_on_any_inventory_or_byte_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    source = (
        Path(__file__).parents[2]
        / "src/assurance/controlspec/reference_catalog_data/v0_1_1"
    )
    release = tmp_path / "v0_1_1"
    shutil.copytree(source, release, ignore=shutil.ignore_patterns("__pycache__"))
    if mutation == "manifest":
        (release / "manifest.sha256").write_bytes(
            (release / "manifest.sha256").read_bytes() + b"\n"
        )
    elif mutation == "artifact":
        target = release / "packs/personal-agent-spending.json"
        target.write_bytes(target.read_bytes() + b"\n")
    elif mutation == "missing":
        (release / "scenarios/enterprise-high-risk-missing-approval.json").unlink()
    else:
        (release / "scenarios/extra.json").write_bytes(b"{}")
    with pytest.raises(ReferenceCatalogError):
        _validate_default_release_manifest(release)


@pytest.mark.parametrize(
    "mutation",
    (
        "requirement",
        "role",
        "scope",
        "separation",
        "approver",
        "approved",
        "lineage",
    ),
)
def test_recomputed_self_approval_source_mutations_fail_at_startup(
    mutation: str,
) -> None:
    catalog = load_default_reference_catalog()
    scenario = next(
        item
        for item in catalog.scenarios
        if item.fixture_id == "enterprise-attempted-self-approval"
    )
    approval = scenario.approvals[0]
    updates: dict[str, object] = {"fact_digest": None}
    if mutation == "requirement":
        updates["requirement_id"] = "another-requirement"
    elif mutation == "role":
        updates["roles"] = ("riskspec.enterprise.role.other",)
    elif mutation == "scope":
        updates["scope_digest"] = "sha256:" + "0" * 64
    elif mutation == "separation":
        updates["separated_role_actor_ids"] = {
            key: value
            for key, value in approval.separated_role_actor_ids.items()
            if not key.endswith(".proposer")
        }
    elif mutation == "approver":
        updates["approver"] = approval.approver.model_copy(
            update={"actor_id": "independent-approver"}
        )
    elif mutation == "approved":
        updates["approved"] = False
    else:
        updates["lineage_complete"] = False
    changed_approval = finalize_fact(approval.model_copy(update=updates))
    changed_scenario = finalize_reference_scenario(
        scenario.model_copy(
            update={"approvals": (changed_approval,), "semantic_digest": None}
        )
    )
    artifacts = tuple(
        ReferencePackArtifact(
            pack=catalog.get_pack(summary.catalog_id).pack,
            metadata=summary.metadata,
        )
        for summary in catalog.list_packs().items
    )
    scenarios = tuple(
        changed_scenario if item.fixture_id == scenario.fixture_id else item
        for item in catalog.scenarios
    )
    with pytest.raises(ReferenceCatalogError):
        ImmutableReferenceCatalog(
            artifacts,
            scenarios=scenarios,
            release_id="v0.1.1",
        )


def test_catalog_detaches_constructor_inputs_and_returns_defensive_deep_clones() -> None:
    source = load_default_reference_catalog()
    constructor_inputs = source.scenarios
    artifacts = tuple(
        ReferencePackArtifact(
            pack=source.get_pack(summary.catalog_id).pack,
            metadata=summary.metadata,
        )
        for summary in source.list_packs().items
    )
    catalog = ImmutableReferenceCatalog(
        artifacts,
        scenarios=constructor_inputs,
        release_id="v0.1.1",
    )
    attacker_owned = next(
        item
        for item in constructor_inputs
        if item.fixture_id == "enterprise-high-risk-missing-approval"
    )
    attacker_owned.intent.context["verifier.attack"] = {"nested": "mutated"}

    first = next(
        item
        for item in catalog.scenarios
        if item.fixture_id == attacker_owned.fixture_id
    )
    second = next(
        item
        for item in catalog.scenarios
        if item.fixture_id == attacker_owned.fixture_id
    )
    assert "verifier.attack" not in first.intent.context
    assert first is not second
    assert first.intent is not second.intent
    assert first.intent.context is not second.intent.context
    first.intent.context["verifier.returned"] = {"nested": "mutated"}
    pristine = next(
        item
        for item in catalog.scenarios
        if item.fixture_id == attacker_owned.fixture_id
    )
    assert "verifier.returned" not in pristine.intent.context
    assert catalog.catalog_digest == source.catalog_digest


def _smb_approval_scope(pack: ControlPack) -> dict[str, object]:
    control = next(
        item for item in pack.controls if item.control_id == "discount-independence"
    )
    return control.effect.requirements[0].scope  # type: ignore[union-attr,return-value]


def test_pack_and_control_detail_responses_never_share_live_nested_graphs() -> None:
    catalog = load_default_reference_catalog()
    summary = next(
        item for item in catalog.list_packs().items if item.namespace == "smb.sales.controls"
    )
    first_pack = catalog.get_pack(summary.catalog_id)
    second_pack = catalog.get_pack(summary.catalog_id)
    assert first_pack.pack is not second_pack.pack
    assert first_pack.pack.controls[0] is not second_pack.pack.controls[0]
    assert _smb_approval_scope(first_pack.pack) is not _smb_approval_scope(
        second_pack.pack
    )

    control_id = next(
        item
        for item in first_pack.control_catalog_ids
        if ":discount-independence@" in item
    )
    first_control = catalog.get_control(control_id)
    second_control = catalog.get_control(control_id)
    assert first_control.control is not second_control.control
    assert first_control.control.effect is not second_control.control.effect
    first_control_scope = first_control.control.effect.requirements[0].scope  # type: ignore[union-attr]
    second_control_scope = second_control.control.effect.requirements[0].scope  # type: ignore[union-attr]
    assert first_control_scope is not second_control_scope
    first_control_scope["verifier.control_attack"] = "mutated"
    fresh_control = catalog.get_control(control_id)
    assert "verifier.control_attack" not in (
        fresh_control.control.effect.requirements[0].scope  # type: ignore[union-attr]
    )

    _smb_approval_scope(first_pack.pack)["verifier.attack"] = "mutated"
    fresh = catalog.get_pack(summary.catalog_id)
    assert "verifier.attack" not in _smb_approval_scope(fresh.pack)

    scenario = next(
        item
        for item in catalog.scenarios
        if item.fixture_id == "smb-discount-15-direct-self-approval"
    )
    service = ReferenceControlPlaneService(
        catalog=catalog,
        fact_provider=ImmutableScenarioFactProvider(
            release_id=catalog.release_id,
            catalog_digest=catalog.catalog_digest,
            scenarios=catalog.scenarios,
            enterprise_loader=lambda _item: (_ for _ in ()).throw(
                AssertionError("SMB must not load the enterprise leaf")
            ),
        ),
    )
    result = service.decide(
        DecideRequest(
            schema="controlspec/api/v0/decide-request",
            action_intent=scenario.intent,
            selection=scenario.selection,
            options=EvaluationOptions(reference_time=scenario.reference_time),
        )
    )
    assert result.decision.verdict is Verdict.BLOCK
    assert result.catalog_binding.fact_fixture_digest == scenario.semantic_digest


def test_catalog_detaches_pack_artifact_constructor_graph_before_retention() -> None:
    source = load_default_reference_catalog()
    artifacts = tuple(
        ReferencePackArtifact(
            pack=source.get_pack(summary.catalog_id).pack,
            metadata=summary.metadata,
        )
        for summary in source.list_packs().items
    )
    catalog = ImmutableReferenceCatalog(
        artifacts,
        scenarios=source.scenarios,
        release_id="v0.1.1",
    )
    attacker_owned = next(
        item for item in artifacts if item.pack.namespace == "smb.sales.controls"
    )
    _smb_approval_scope(attacker_owned.pack)["verifier.constructor_attack"] = (
        "mutated"
    )
    summary = next(
        item for item in catalog.list_packs().items if item.namespace == "smb.sales.controls"
    )
    pristine = catalog.get_pack(summary.catalog_id)
    assert "verifier.constructor_attack" not in _smb_approval_scope(pristine.pack)
    scenario = next(
        item
        for item in catalog.scenarios
        if item.fixture_id == "smb-discount-15-direct-self-approval"
    )
    snapshot, _ = catalog.resolve(
        scenario.selection,
        observed_at=scenario.reference_time,
    )
    expected_snapshot, _ = source.resolve(
        scenario.selection,
        observed_at=scenario.reference_time,
    )
    assert canonical_json(snapshot) == canonical_json(expected_snapshot)
    resolved_control = next(
        item
        for item in snapshot.controls
        if item.control_id == "discount-independence"
    )
    assert "verifier.constructor_attack" not in (
        resolved_control.effect.requirements[0].scope  # type: ignore[union-attr]
    )
    assert catalog.catalog_digest == source.catalog_digest


def test_resolve_fails_closed_on_impossible_private_pack_corruption() -> None:
    catalog = load_default_reference_catalog()
    scenario = next(
        item
        for item in catalog.scenarios
        if item.fixture_id == "smb-discount-15-direct-self-approval"
    )
    retained = catalog._packs[str(scenario.selection.catalog_id)]
    _smb_approval_scope(retained.pack)["verifier.private_corruption"] = "mutated"
    with pytest.raises(ReferenceCatalogError, match="semantic digest"):
        catalog.resolve(
            scenario.selection,
            observed_at=scenario.reference_time,
        )
