"""Restricted YAML 1.2 authoring compiler; YAML never becomes runtime authority."""

from __future__ import annotations

from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from ruamel.yaml.events import AliasEvent, CollectionStartEvent, ScalarEvent

from assurance.controlspec.canonical import canonical_object_bytes, finalize_object
from assurance.controlspec.contracts import ControlPack


def _yaml_parser() -> YAML:
    parser = YAML(typ="safe", pure=True)
    parser.version = (1, 2)
    parser.allow_duplicate_keys = False
    return parser


def _reject_unsafe_yaml(text: str) -> None:
    parser = _yaml_parser()
    documents = 0
    for event in parser.parse(text):
        if event.__class__.__name__ == "DocumentStartEvent":
            documents += 1
        if isinstance(event, AliasEvent):
            raise ValueError("YAML aliases are forbidden")
        if isinstance(event, CollectionStartEvent | ScalarEvent):
            if event.anchor is not None:
                raise ValueError("YAML anchors are forbidden")
            if event.tag is not None:
                raise ValueError("explicit YAML tags are forbidden")
    if documents != 1:
        raise ValueError("exactly one YAML document is required")


def _reject_merge_keys(value: Any) -> None:
    if isinstance(value, dict):
        if "<<" in value:
            raise ValueError("YAML merge keys are forbidden")
        for item in value.values():
            _reject_merge_keys(item)
    elif isinstance(value, list):
        for item in value:
            _reject_merge_keys(item)
    elif value is not None and not isinstance(value, str | int | bool):
        raise ValueError(
            "YAML scalars must be JSON-compatible strings, integers, booleans, or null"
        )


def load_yaml_control_pack(text: str) -> ControlPack:
    """Validate one restricted authoring document as a draft portable pack."""

    try:
        _reject_unsafe_yaml(text)
        loaded = _yaml_parser().load(text)
    except YAMLError as exc:
        raise ValueError(f"invalid restricted YAML: {exc}") from exc
    _reject_merge_keys(loaded)
    if not isinstance(loaded, dict):
        raise ValueError("ControlPack authoring input must be a mapping")
    pack = ControlPack.model_validate(loaded, strict=False)
    if pack.status.value != "draft":
        raise ValueError("YAML authoring input may only describe draft ControlPacks")
    supported_non_display = {"riskspec.enterprise.source"}
    unsupported = {
        declaration.key
        for declaration in pack.extension_requirements
        if declaration.classification != "display" and declaration.key not in supported_non_display
    }
    if unsupported:
        raise ValueError("unsupported authority/evidence extension")
    return pack


def compile_yaml_control_pack(text: str) -> bytes:
    """Compile authoring sugar to canonical JSON; JSON is the sole output authority."""

    pack = load_yaml_control_pack(text)
    display_extensions = frozenset(
        item.key for item in pack.extension_requirements if item.classification == "display"
    )
    controls = tuple(
        finalize_object(
            control.model_copy(update={"semantic_digest": None}),
            display_extensions=display_extensions,
        )
        for control in pack.controls
    )
    compiled = pack.model_copy(update={"controls": controls, "semantic_digest": None})
    return canonical_object_bytes(finalize_object(compiled))
