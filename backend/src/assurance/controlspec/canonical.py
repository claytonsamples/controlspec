"""Deterministic ControlSpec v0 JSON, context hashes, and semantic digests."""

from __future__ import annotations

import json
from typing import Any, cast

from assurance.contracts.canonical import canonical_json, sha256_digest
from assurance.controlspec.contracts import Control, ControlPack, ExtensionBearing, HashDigest

CANONICALIZER_ID = "RFC8785-INTEGER-AUTHORITY"
CANONICALIZER_VERSION = "1"
CONTROLSPEC_PROFILE = "controlspec.portable.v0"


def _payload(
    value: ExtensionBearing,
    *,
    include_digest: bool,
    display_extensions: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    payload = value.model_dump(mode="json", by_alias=True, exclude_none=False)
    if not include_digest and value.digest_field:
        payload.pop(value.digest_field, None)
    if not include_digest and isinstance(value, Control | ControlPack):
        payload.pop("title", None)
        payload.pop("description", None)
    if not include_digest:
        extensions = payload.get("extensions")
        if isinstance(extensions, dict):
            payload["extensions"] = {
                key: item for key, item in extensions.items() if key not in display_extensions
            }
    if not include_digest and isinstance(value, ControlPack):
        payload["controls"] = [
            _payload(
                control,
                include_digest=True,
                display_extensions=display_extensions,
            )
            for control in value.controls
        ]
    return payload


def canonical_object_bytes(value: ExtensionBearing, *, include_digest: bool = True) -> bytes:
    return canonical_json(_payload(value, include_digest=include_digest))


def canonical_object_digest(
    value: ExtensionBearing,
    *,
    display_extensions: frozenset[str] | None = None,
) -> HashDigest:
    if display_extensions is None and isinstance(value, ControlPack):
        display_extensions = frozenset(
            item.key for item in value.extension_requirements if item.classification == "display"
        )
    declared_display = display_extensions or frozenset()
    envelope = {
        "canonicalizer": {"id": CANONICALIZER_ID, "version": CANONICALIZER_VERSION},
        "profile": CONTROLSPEC_PROFILE,
        "object": _payload(
            value,
            include_digest=False,
            display_extensions=declared_display,
        ),
    }
    return sha256_digest(canonical_json(envelope))


def finalize_object[ObjectT: ExtensionBearing](
    value: ObjectT,
    *,
    display_extensions: frozenset[str] | None = None,
) -> ObjectT:
    if not value.digest_field:
        return value
    return value.model_copy(
        update={
            value.digest_field: canonical_object_digest(
                value,
                display_extensions=display_extensions,
            )
        }
    )


def verify_object_digest(value: ExtensionBearing) -> bool:
    if not value.digest_field:
        return True
    return cast(bool, getattr(value, value.digest_field) == canonical_object_digest(value))


def canonical_context_hash(context: dict[str, Any]) -> HashDigest:
    return sha256_digest(canonical_json(context))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _signed_integer(value: str) -> int:
    parsed = int(value)
    if parsed < -(2**63) or parsed > 2**63 - 1:
        raise ValueError("integers must fit the signed 64-bit canonical profile")
    return parsed


def _forbid_json_float(value: str) -> None:
    raise ValueError(f"floating-point JSON values are forbidden: {value}")


def load_canonical_json_control_pack(data: bytes | str) -> ControlPack:
    """Load only the exact canonical runtime form of a complete draft pack.

    This is a syntax, shape, and digest check. It deliberately does not publish
    controls or grant runtime authority.
    """

    text = data.decode("utf-8") if isinstance(data, bytes) else data
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_int=_signed_integer,
            parse_float=_forbid_json_float,
            parse_constant=_forbid_json_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid canonical ControlSpec JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("canonical ControlPack JSON must be an object")
    if canonical_json(parsed) != text.encode("utf-8"):
        raise ValueError("runtime JSON must use the exact canonical representation")

    pack = ControlPack.model_validate(parsed, strict=False)
    display_extensions = frozenset(
        item.key for item in pack.extension_requirements if item.classification == "display"
    )
    for control in pack.controls:
        if control.semantic_digest != canonical_object_digest(
            control,
            display_extensions=display_extensions,
        ):
            raise ValueError("Control semantic_digest does not match canonical content")
    if pack.semantic_digest != canonical_object_digest(pack):
        raise ValueError("ControlPack semantic_digest does not match canonical content")
    return pack
