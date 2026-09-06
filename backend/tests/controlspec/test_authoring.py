from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from assurance.controlspec.authoring import compile_yaml_control_pack
from assurance.controlspec.canonical import load_canonical_json_control_pack
from assurance.controlspec.contracts import ControlPack

EXAMPLE = (
    Path(__file__).parents[3]
    / "changes/0005-controlspec-open-standard-reframe"
    / "examples/controlpacks/personal-agent-spending.yaml"
)


def test_yaml_compiles_deterministically_to_canonical_json() -> None:
    text = EXAMPLE.read_text(encoding="utf-8")
    first = compile_yaml_control_pack(text)
    second = compile_yaml_control_pack(text)
    assert first == second
    parsed = json.loads(first)
    validated = ControlPack.model_validate(parsed, strict=False)
    Draft202012Validator(ControlPack.model_json_schema()).validate(parsed)
    assert validated.semantic_digest is not None
    assert all(control.semantic_digest is not None for control in validated.controls)
    assert load_canonical_json_control_pack(first) == validated


def test_candidate_schema_rejects_floating_point_portable_json() -> None:
    parsed = json.loads(compile_yaml_control_pack(EXAMPLE.read_text(encoding="utf-8")))
    parsed["metadata"] = {"fractional_value": 1.5}
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(ControlPack.model_json_schema()).validate(parsed)


@pytest.mark.parametrize(
    "mutation, message",
    [
        ('{"a":1,"a":2}', "duplicate"),
        ('{"a":1.25}', "floating-point"),
        ('{"a":9223372036854775808}', "signed 64-bit"),
        (' {"a":1}', "exact canonical"),
    ],
)
def test_runtime_json_rejects_noncanonical_or_ambiguous_input(
    mutation: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        load_canonical_json_control_pack(mutation)


@pytest.mark.parametrize(
    "mutation, message",
    [
        ("x: &a 1\ny: *a\n", "aliases|anchors"),
        ("x: 1\nx: 2\n", "duplicate"),
        ("x: !!str value\n", "tags"),
        ("x: 1.25\n", "floating|scalars"),
        ("x: 2026-08-19\n", "scalars"),
        ("x: 1\n---\ny: 2\n", "one YAML document"),
    ],
)
def test_restricted_yaml_rejects_ambiguous_or_powerful_features(
    mutation: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        compile_yaml_control_pack(mutation)
