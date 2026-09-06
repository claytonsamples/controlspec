from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from assurance.controlspec.authoring import load_yaml_control_pack
from assurance.controlspec.canonical import (
    canonical_object_digest,
    finalize_object,
    verify_object_digest,
)
from assurance.controlspec.contracts import (
    PORTABLE_OBJECTS,
    Control,
    ControlPack,
    Decision,
    ObjectRef,
    Resource,
)

EXAMPLES = (
    Path(__file__).parents[3]
    / "changes/0005-controlspec-open-standard-reframe/examples/controlpacks"
)


def example_pack(name: str = "personal-agent-spending.yaml") -> ControlPack:
    return load_yaml_control_pack((EXAMPLES / name).read_text(encoding="utf-8"))


def test_all_static_packs_are_valid_non_authoritative_drafts() -> None:
    for path in sorted(EXAMPLES.glob("*.yaml")):
        pack = example_pack(path.name)
        assert pack.status.value == "draft"
        assert all(control.status.value == "draft" for control in pack.controls)
        assert "no executable runtime support is claimed" in pack.description.lower()


def test_static_packs_encode_their_stated_case_boundaries() -> None:
    personal = example_pack("personal-agent-spending.yaml")
    assert {control.control_id for control in personal.controls} == {
        "grocery-purchase",
        "over-limit-approval",
        "recurring-purchase-approval",
    }
    personal_predicates = {
        predicate.path
        for control in personal.controls
        for predicate in control.match.predicates
    }
    assert personal_predicates == {
        "/context/personal.spending.recurring",
        "/context/personal.spending.total_minor_units",
    }

    sales = example_pack("smb-sales-controls.yaml")
    assert {control.control_id for control in sales.controls} == {
        "discount-independence",
        "discount-within-limit",
        "draft-customer-email",
    }
    assert any(
        requirement.requirement_type == "approval"
        and requirement.separate_from_actor
        for control in sales.controls
        for requirement in control.effect.requirements
    )

    enterprise = example_pack("enterprise-supplier-activation.yaml")
    assert {control.control_id for control in enterprise.controls} == {
        "restricted-data-privacy-review",
        "routine-supplier-evidence",
        "supplier-evidence-and-approval",
    }
    enterprise_paths = {
        predicate.path
        for control in enterprise.controls
        for predicate in control.match.predicates
    }
    assert enterprise_paths == {
        "/context/enterprise.supplier.high_risk",
        "/context/enterprise.supplier.restricted_data",
    }


def test_all_nine_candidate_schemas_are_closed() -> None:
    assert len(PORTABLE_OBJECTS) == 9
    for model in PORTABLE_OBJECTS:
        schema = model.model_json_schema()
        assert schema["additionalProperties"] is False

    decision_schema = Decision.model_json_schema()
    assert decision_schema["properties"]["conditions"]["$ref"].endswith(
        "CanonicalSet_ConditionResult_"
    )
    assert decision_schema["properties"]["approval_requirements"]["$ref"].endswith(
        "CanonicalSet_ApprovalRequirement_"
    )
    assert decision_schema["properties"]["required_evidence"]["$ref"].endswith(
        "CanonicalSet_EvidenceRequirement_"
    )


def test_closed_shapes_namespaces_and_floats_are_enforced() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        Resource.model_validate(
            {
                "namespace": "personal.agent",
                "resource_id": "cart",
                "version": "1",
                "type": "personal.cart",
                "business_id": None,
                "attributes": {},
                "extensions": {},
                "supplier_magic": True,
            }
        )
    with pytest.raises(ValidationError):
        Resource(
            namespace="personal.agent",
            resource_id="cart",
            version="1",
            type="supplier",  # type: ignore[arg-type]
            business_id=None,
            attributes={},
        )
    with pytest.raises(ValidationError, match="floating-point"):
        Resource(
            namespace="personal.agent",
            resource_id="cart",
            version="1",
            type="personal.cart",
            business_id=None,
            attributes={"amount": 1.5},
        )
    with pytest.raises(ValidationError, match="signed 64-bit"):
        Resource(
            namespace="personal.agent",
            resource_id="cart",
            version="1",
            type="personal.cart",
            business_id=None,
            attributes={"amount": 2**63},
        )


def test_canonical_sets_reject_duplicates() -> None:
    pack = example_pack()
    data = pack.model_dump(mode="python")
    data["controls"] = [pack.controls[0], pack.controls[0]]
    with pytest.raises(ValidationError, match="duplicate"):
        ControlPack.model_validate(data)


def test_semantic_digest_is_stable_and_excludes_display_fields() -> None:
    control = example_pack().controls[0]
    first = finalize_object(control)
    renamed = control.model_copy(update={"title": "Different display title"})
    assert canonical_object_digest(first) == canonical_object_digest(renamed)
    assert verify_object_digest(first)
    changed = control.model_copy(update={"metadata": {"limit_minor_units": 7600}})
    assert canonical_object_digest(first) != canonical_object_digest(changed)


def test_undeclared_extension_is_rejected_at_pack_boundary() -> None:
    pack = example_pack()
    control = pack.controls[0].model_copy(update={"extensions": {"personal.secret.authority": {}}})
    with pytest.raises(ValidationError, match="must be declared"):
        ControlPack.model_validate(pack.model_dump(mode="python") | {"controls": [control]})


def test_nested_route_extensions_cannot_escape_pack_declaration() -> None:
    pack = example_pack()
    control = pack.controls[0]
    route = control.effect.route.model_copy(
        update={"extensions": {"personal.undeclared.authority": {}}}
    )
    changed = control.model_copy(
        update={"effect": control.effect.model_copy(update={"route": route})}
    )
    with pytest.raises(ValidationError, match="must be declared"):
        ControlPack.model_validate(pack.model_dump(mode="python") | {"controls": [changed]})


def test_used_verifiers_must_be_declared_by_the_pack() -> None:
    pack = example_pack()
    vocabularies = pack.vocabularies.model_copy(update={"verifiers": ()})
    with pytest.raises(ValidationError, match="verifier must be declared"):
        ControlPack.model_validate(
            pack.model_dump(mode="python") | {"vocabularies": vocabularies}
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("effective_from", "2026-99-99T25:61:61.000000Z", "real canonical UTC"),
        ("version", "1.0.0-01", "zero-padded"),
    ],
)
def test_timestamp_and_semver_are_semantically_validated(
    field: str, value: str, message: str
) -> None:
    control = example_pack().controls[0]
    with pytest.raises(ValidationError, match=message):
        Control.model_validate(control.model_dump(mode="python") | {field: value})


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-08-19T12:00:00.000000+00:00",
        "2026-08-19T12:00:00.0Z",
    ],
)
def test_timestamp_rejects_offsets_and_noncanonical_fraction(timestamp: str) -> None:
    control = example_pack().controls[0]
    with pytest.raises(ValidationError):
        Control.model_validate(
            control.model_dump(mode="python") | {"effective_from": timestamp}
        )


def test_semver_prerelease_and_build_handling_is_explicit() -> None:
    control = example_pack().controls[0]
    candidate = Control.model_validate(
        control.model_dump(mode="python") | {"version": "1.2.3-rc.1+build.01"}
    )
    assert candidate.version == "1.2.3-rc.1+build.01"
    with pytest.raises(ValidationError):
        Control.model_validate(
            control.model_dump(mode="python") | {"version": "1.2.3+build..broken"}
        )


def test_portable_json_rejects_typed_model_smuggling() -> None:
    with pytest.raises(ValidationError, match="cannot embed"):
        Resource(
            namespace="personal.agent",
            resource_id="cart",
            version="1",
            type="personal.cart",
            business_id=None,
            attributes={
                "smuggled": ObjectRef(
                    namespace="personal.agent",
                    object_type="personal.authority.grant",
                    object_id="grant-1",
                    version="1",
                    digest=None,
                )
            },
        )


def test_control_effect_cannot_pair_block_with_continue_route() -> None:
    control = example_pack().controls[0]
    changed_effect = control.effect.model_dump(mode="python") | {"verdict": "block"}
    with pytest.raises(ValidationError, match="block effect requires a block route"):
        Control.model_validate(
            control.model_dump(mode="python") | {"effect": changed_effect}
        )
