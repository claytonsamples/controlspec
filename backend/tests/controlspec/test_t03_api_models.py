from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from assurance.contracts.canonical import canonical_json
from assurance.controlspec.api_models import (
    CatalogObjectRef,
    ControlSpecApiErrorResponse,
    DecideRequest,
    EvaluationOptions,
    PackSelection,
    ReferenceAuthorityView,
)
from assurance.controlspec.reference_catalog import load_default_reference_catalog
from tests.controlspec.test_t02_examples import _intent

NOW = "2026-08-20T12:00:00.000000Z"


def _pack_selection() -> PackSelection:
    summary = load_default_reference_catalog().list_packs().items[0]
    return PackSelection(
        catalog_id=summary.catalog_id,
        semantic_digest=summary.semantic_digest,
    )


def test_request_is_closed_and_round_trips_as_strict_canonical_json() -> None:
    intent = _intent(
        "personal.agent.spending",
        intent_id="model-roundtrip",
        domain_action="personal.purchase",
        resource_type="personal.cart",
        context={
            "personal.spending.total_minor_units": 4200,
            "personal.spending.recurring": False,
        },
    )
    request = DecideRequest(
        schema="controlspec/api/v0/decide-request",
        action_intent=intent,
        selection=_pack_selection(),
        options=EvaluationOptions(reference_time=NOW),
    )
    encoded = canonical_json(request)
    assert DecideRequest.model_validate_json(encoded, strict=True) == request
    assert canonical_json(json.loads(encoded)) == encoded
    with pytest.raises(ValidationError):
        DecideRequest.model_validate(
            {**request.model_dump(mode="python", by_alias=True), "facts": []},
            strict=True,
        )


def test_catalog_ids_require_semantic_semver_and_exact_digest() -> None:
    with pytest.raises(ValidationError):
        PackSelection(
            catalog_id="controlspec.personal:pack@1.0.0-01",
            semantic_digest="sha256:" + "0" * 64,
        )
    with pytest.raises(ValidationError):
        CatalogObjectRef(
            catalog_id="controlspec.personal:pack@latest",
            semantic_digest="sha256:" + "0" * 64,
        )


def test_reference_authority_and_error_envelopes_are_not_relabelable() -> None:
    with pytest.raises(ValidationError):
        ReferenceAuthorityView(may_authorize_external_effect=True)
    with pytest.raises(ValidationError):
        ReferenceAuthorityView(durable=True)
    schema = ControlSpecApiErrorResponse.model_json_schema()
    assert schema["additionalProperties"] is False

