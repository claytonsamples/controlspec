"""Strict reusable contract primitives."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, TypeVar, cast
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    StringConstraints,
    model_validator,
)

from assurance.contracts.canonical import canonical_set
from assurance.domain import (
    CanonicalAction,
    DomainVerb,
    FieldPath,
    PrincipalType,
    ResourceType,
    RouteId,
)


class AssuranceModel(BaseModel):
    """Closed, immutable base for every public contract model."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_default=True,
        str_strip_whitespace=False,
    )


def _utc_only(value: datetime) -> datetime:
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None:
        raise ValueError("timestamp must be timezone-aware")
    if offset.total_seconds() != 0:
        raise ValueError("timestamp must use UTC")
    return value


UtcTimestamp = Annotated[datetime, AfterValidator(_utc_only)]
HashDigest = Annotated[
    str,
    StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$", strict=True),
]
CurrencyCode = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Z]{3}$", strict=True),
]
NonEmptyString = Annotated[str, StringConstraints(min_length=1, strict=True)]
SchemaVersion = Literal[1]
PositiveInt = Annotated[StrictInt, Field(gt=0)]
NonNegativeInt = Annotated[StrictInt, Field(ge=0)]
AuthorityOperation = Literal[
    "DECIDE",
    "PROPOSE",
    "REVIEW",
    "APPROVE",
    "PUBLISH",
    "EXECUTE",
]

T = TypeVar("T")


def _canonical_set_after_validation[T](values: list[T]) -> list[T]:
    return cast(list[T], canonical_set(values))


CanonicalSet = Annotated[list[T], AfterValidator(_canonical_set_after_validation)]


_AUTHORITY_INSTANT_PATTERN = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T"
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{7})Z$"
)
_TICKS_PER_SECOND = 10_000_000
_TICKS_PER_DAY = 86400 * _TICKS_PER_SECOND


def _days_from_civil(year: int, month: int, day: int) -> int:
    adjusted_year = year - (1 if month <= 2 else 0)
    era = adjusted_year // 400
    year_of_era = adjusted_year - era * 400
    month_prime = month + (-3 if month > 2 else 9)
    day_of_year = (153 * month_prime + 2) // 5 + day - 1
    day_of_era = (
        year_of_era * 365
        + year_of_era // 4
        - year_of_era // 100
        + day_of_year
    )
    return era * 146097 + day_of_era - 719468


def _civil_from_days(days_since_epoch: int) -> tuple[int, int, int]:
    shifted = days_since_epoch + 719468
    era = shifted // 146097
    day_of_era = shifted - era * 146097
    year_of_era = (
        day_of_era
        - day_of_era // 1460
        + day_of_era // 36524
        - day_of_era // 146096
    ) // 365
    year = year_of_era + era * 400
    day_of_year = day_of_era - (
        365 * year_of_era + year_of_era // 4 - year_of_era // 100
    )
    month_prime = (5 * day_of_year + 2) // 153
    day = day_of_year - (153 * month_prime + 2) // 5 + 1
    month = month_prime + (3 if month_prime < 10 else -9)
    year += 1 if month <= 2 else 0
    return year, month, day


def _authority_instant_ticks(canonical_rfc3339: str) -> int:
    match = _AUTHORITY_INSTANT_PATTERN.fullmatch(canonical_rfc3339)
    if match is None:
        raise ValueError("authority instant must be UTC Z with seven fractional digits")
    year, month, day, hour, minute, second, fraction = (
        int(value) for value in match.groups()
    )
    if not 1 <= year <= 9999 or not 1 <= month <= 12:
        raise ValueError("authority instant calendar date is invalid")
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    month_lengths = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    if (
        not 1 <= day <= month_lengths[month - 1]
        or not 0 <= hour <= 23
        or not 0 <= minute <= 59
        or not 0 <= second <= 59
    ):
        raise ValueError("authority instant calendar time is invalid")
    seconds = hour * 3600 + minute * 60 + second
    return (
        _days_from_civil(year, month, day) * _TICKS_PER_DAY
        + seconds * _TICKS_PER_SECOND
        + fraction
    )


def _authority_instant_text(ticks: int) -> str:
    days, within_day = divmod(ticks, _TICKS_PER_DAY)
    year, month, day = _civil_from_days(days)
    if not 1 <= year <= 9999:
        raise ValueError("authority instant is outside the canonical year range")
    seconds, fraction = divmod(within_day, _TICKS_PER_SECOND)
    hour, remaining = divmod(seconds, 3600)
    minute, second = divmod(remaining, 60)
    return (
        f"{year:04d}-{month:02d}-{day:02d}T"
        f"{hour:02d}:{minute:02d}:{second:02d}.{fraction:07d}Z"
    )


class AuthorityInstant100ns(AssuranceModel):
    canonical_rfc3339: Annotated[
        str,
        StringConstraints(
            pattern=(
                r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
                r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z$"
            ),
            strict=True,
        ),
    ]
    unix_epoch_100ns_ticks_decimal: Annotated[
        StrictStr,
        StringConstraints(pattern=r"^[0-9]{19}$", strict=True),
    ]

    @model_validator(mode="after")
    def exact_text_tick_pair(self) -> AuthorityInstant100ns:
        ticks = int(self.unix_epoch_100ns_ticks_decimal)
        if (
            ticks > 9_223_372_036_854_775_807
            or f"{ticks:019d}" != self.unix_epoch_100ns_ticks_decimal
            or _authority_instant_ticks(self.canonical_rfc3339) != ticks
            or _authority_instant_text(ticks) != self.canonical_rfc3339
        ):
            raise ValueError("authority instant text and ticks do not match")
        return self


def authority_instant_from_database_time(
    value: datetime,
) -> AuthorityInstant100ns:
    """Convert a trusted microsecond database clock to exact integer ticks."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("trusted database time must be timezone-aware")
    utc_value = value.astimezone(UTC)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = utc_value - epoch
    whole_microseconds = (
        delta.days * 86_400_000_000
        + delta.seconds * 1_000_000
        + delta.microseconds
    )
    ticks = whole_microseconds * 10
    return AuthorityInstant100ns(
        canonical_rfc3339=_authority_instant_text(ticks),
        unix_epoch_100ns_ticks_decimal=f"{ticks:019d}",
    )


class Money(AssuranceModel):
    currency: CurrencyCode
    minor_units: StrictInt


class PrincipalIdentity(AssuranceModel):
    tenant_id: UUID
    principal_id: UUID
    principal_version_id: UUID
    independence_domain_id: UUID
    principal_type: PrincipalType


class ResourceIdentity(AssuranceModel):
    tenant_id: UUID
    resource_type: ResourceType
    resource_id: UUID
    business_id: NonEmptyString


class ObjectHashReference(AssuranceModel):
    tenant_id: UUID
    object_id: UUID
    object_hash: HashDigest


class VersionedSpecReference(AssuranceModel):
    tenant_id: UUID
    spec_version_id: UUID
    module_key: NonEmptyString
    version: PositiveInt
    content_hash: HashDigest
    semantic_hash: HashDigest


class ContentReference(AssuranceModel):
    reference_type: Literal["URI", "DOCUMENT_ID"]
    value: NonEmptyString
    captured_hash: HashDigest


class AnyScopeValue(AssuranceModel):
    kind: Literal["ANY"] = "ANY"


class ExactScopeValue(AssuranceModel):
    kind: Literal["EXACT"] = "EXACT"
    values: Annotated[CanonicalSet[NonEmptyString], Field(min_length=1)]


ScopeValue = Annotated[AnyScopeValue | ExactScopeValue, Field(discriminator="kind")]


class AuthorityScope(AssuranceModel):
    actions: ScopeValue
    resource_types: ScopeValue
    business_objects: ScopeValue
    policy_modules: ScopeValue
    routes: ScopeValue
    operations: ScopeValue
    behalf_of_parties: ScopeValue


class CanonicalActionMapping(AssuranceModel):
    mapping_type: Literal["DOMAIN_VERB_MAPPING"] = "DOMAIN_VERB_MAPPING"
    domain_verb: DomainVerb
    canonical_action: CanonicalAction
    resource_type: ResourceType
    human_decision_ref: ObjectHashReference


class RetryData(AssuranceModel):
    attempt_number: PositiveInt
    semantic_attempt_key: NonEmptyString
    prior_execution_ref: ObjectHashReference | None


class MeterReference(AssuranceModel):
    tenant_id: UUID
    meter_id: UUID
    stream_head_sequence: NonNegativeInt
    stream_head_hash: HashDigest


class BooleanClaim(AssuranceModel):
    value_type: Literal["BOOLEAN"] = "BOOLEAN"
    value: StrictBool


class IntegerClaim(AssuranceModel):
    value_type: Literal["INTEGER"] = "INTEGER"
    value: StrictInt


class StringClaim(AssuranceModel):
    value_type: Literal["STRING"] = "STRING"
    value: NonEmptyString


class IdentifierClaim(AssuranceModel):
    value_type: Literal["IDENTIFIER"] = "IDENTIFIER"
    value: UUID


class TimestampClaim(AssuranceModel):
    value_type: Literal["TIMESTAMP"] = "TIMESTAMP"
    value: UtcTimestamp


class MoneyClaim(AssuranceModel):
    value_type: Literal["MONEY"] = "MONEY"
    value: Money


TypedValue = Annotated[
    BooleanClaim | IntegerClaim | StringClaim | IdentifierClaim | TimestampClaim | MoneyClaim,
    Field(discriminator="value_type"),
]


class ContextClaim(AssuranceModel):
    field_path: FieldPath
    asserted_value: TypedValue
    authoritative_fact_ref: ObjectHashReference | None

    @model_validator(mode="after")
    def client_claim_is_not_implicitly_authoritative(self) -> ContextClaim:
        # This validator deliberately makes no truth claim. The optional fact
        # reference is only a binding for later trusted resolution.
        return self


def reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("floating-point values are forbidden")
    if isinstance(value, dict):
        for item in value.values():
            reject_floats(item)
    elif isinstance(value, list | tuple):
        for item in value:
            reject_floats(item)


class ExactRoute(AssuranceModel):
    route_id: RouteId
