"""RFC 8785 canonical JSON and SHA-256 helpers for authority-bearing data."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from enum import Enum
from typing import Any, cast
from uuid import UUID

import rfc8785
from pydantic import BaseModel

SHA256_PREFIX = "sha256:"
CANONICALIZER_ID = "RFC8785-INTEGER-AUTHORITY"
CANONICALIZER_VERSION = "1"


class CanonicalizationError(ValueError):
    """Input cannot be represented by the authority-bearing JSON profile."""


def _normalize(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _normalize(value.model_dump(mode="python", by_alias=True, exclude_none=False))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, UUID):
        return str(value).lower()
    if isinstance(value, datetime):
        offset = value.utcoffset()
        if value.tzinfo is None or offset is None:
            raise CanonicalizationError("timestamps must be timezone-aware")
        if offset.total_seconds() != 0:
            raise CanonicalizationError("timestamps must use UTC")
        utc_value = value.astimezone(UTC)
        return utc_value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(value, float):
        raise CanonicalizationError("floating-point values are forbidden")
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("JSON object keys must be strings")
            normalized[key] = _normalize(item)
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_normalize(item) for item in value]
    raise CanonicalizationError(f"unsupported authority-bearing value: {type(value).__name__}")


def canonical_set(values: Iterable[Any]) -> list[Any]:
    """Return values sorted by canonical bytes with canonical duplicates removed."""

    keyed: dict[bytes, Any] = {}
    for value in values:
        normalized = _normalize(value)
        try:
            canonical_bytes = rfc8785.dumps(normalized)
        except (UnicodeEncodeError, ValueError, rfc8785.CanonicalizationError) as exc:
            raise CanonicalizationError(str(exc)) from exc
        keyed[canonical_bytes] = value
    return [keyed[key] for key in sorted(keyed)]


def _sort_paths(value: Any, set_paths: frozenset[tuple[str, ...]], path: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        return {
            key: _sort_paths(item, set_paths, (*path, key))
            for key, item in value.items()
        }
    if isinstance(value, list):
        transformed = [_sort_paths(item, set_paths, (*path, "*")) for item in value]
        if path in set_paths:
            return [_normalize(item) for item in canonical_set(transformed)]
        return transformed
    return value


def canonical_json(
    value: Any,
    *,
    set_paths: Iterable[tuple[str, ...]] = (),
) -> bytes:
    """Serialize the restricted authority profile as RFC 8785 canonical bytes.

    Contract fields with set semantics are normalized during Pydantic
    validation. ``set_paths`` exists for raw JSON vectors and database adapters.
    Ordered arrays, including source fragments and event sequences, are never
    sorted unless their path is explicitly supplied.
    """

    normalized = _normalize(value)
    normalized = _sort_paths(normalized, frozenset(set_paths), ())
    try:
        return rfc8785.dumps(normalized)
    except (UnicodeEncodeError, ValueError, rfc8785.CanonicalizationError) as exc:
        raise CanonicalizationError(str(exc)) from exc


def sha256_digest(canonical_bytes: bytes) -> str:
    return f"{SHA256_PREFIX}{hashlib.sha256(canonical_bytes).hexdigest()}"


def canonical_hash(
    *,
    schema: str,
    schema_version: int,
    tenant_id: UUID | str,
    payload: Any,
) -> str:
    envelope = {
        "schema": schema,
        "schema_version": schema_version,
        "tenant_id": tenant_id,
        "payload": payload,
    }
    return sha256_digest(canonical_json(envelope))


def model_canonical_hash(
    model: BaseModel,
    *,
    excluded_fields: Iterable[str],
) -> str:
    """Hash a stored model using its declared schema envelope.

    Hash fields are explicit at every boundary. Callers must name every field
    excluded from that object's hash boundary; no field is silently omitted.
    """

    data = model.model_dump(mode="python", by_alias=True, exclude_none=False)
    schema = data.pop("schema_name")
    schema_version = data.pop("schema_version")
    tenant_id = data.pop("tenant_id")
    for field in excluded_fields:
        data.pop(field)
    return canonical_hash(
        schema=schema,
        schema_version=schema_version,
        tenant_id=tenant_id,
        payload=data,
    )


def verify_model_hash(
    model: BaseModel,
    *,
    hash_field: str,
    excluded_fields: Iterable[str] = (),
) -> bool:
    expected = model_canonical_hash(
        model,
        excluded_fields=(*excluded_fields, hash_field),
    )
    return cast(bool, getattr(model, hash_field) == expected)
