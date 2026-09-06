"""Closed HTTP contracts for the stateless ControlSpec reference API."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BeforeValidator,
    Field,
    StrictBool,
    StringConstraints,
    TypeAdapter,
)

from assurance.controlspec.contracts import (
    ActionIntent,
    CanonicalSet,
    Control,
    ControlPack,
    ControlRef,
    ControlSpecModel,
    Decision,
    EvidenceRef,
    HashDigest,
    NamespacedValue,
    Receipt,
    Route,
    SemVer,
    UtcTimestamp,
    Verdict,
)
from assurance.controlspec.facts import RecheckResult

_SEMVER = TypeAdapter(SemVer)


def _catalog_semver(value: str) -> str:
    _SEMVER.validate_python(value.rsplit("@", maxsplit=1)[1], strict=True)
    return value


CatalogId = Annotated[
    str,
    StringConstraints(
        strict=True,
        max_length=384,
        pattern=(
            r"^[a-z][a-z0-9]*(?:[.-][a-z][a-z0-9_-]*)+:"
            r"[A-Za-z0-9][A-Za-z0-9._-]*@"
            r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
            r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
        ),
    ),
    AfterValidator(_catalog_semver),
]


class ReferenceAuthorityView(ControlSpecModel):
    authority_mode: Literal["non_authoritative_reference"] = (
        "non_authoritative_reference"
    )
    may_authorize_external_effect: Literal[False] = False
    durable: Literal[False] = False
    production_publication: Literal[False] = False


REFERENCE_AUTHORITY = ReferenceAuthorityView()


class CatalogObjectRef(ControlSpecModel):
    catalog_id: CatalogId
    semantic_digest: HashDigest


class PackSelection(ControlSpecModel):
    kind: Literal["pack"] = "pack"
    catalog_id: CatalogId
    semantic_digest: HashDigest


class ControlSelection(ControlSpecModel):
    kind: Literal["controls"] = "controls"
    controls: Annotated[CanonicalSet[CatalogObjectRef], Field(min_length=1)]


type ReferenceSelection = Annotated[
    PackSelection | ControlSelection,
    Field(discriminator="kind"),
]


class EvaluationOptions(ControlSpecModel):
    include_trace: StrictBool = False
    reference_time: UtcTimestamp | None = None


class ReferenceTimeOptions(ControlSpecModel):
    reference_time: UtcTimestamp | None = None


class CatalogBinding(ControlSpecModel):
    catalog_digest: HashDigest
    selection_digest: HashDigest
    fact_fixture_digest: HashDigest
    facts_digest: HashDigest
    semantic_input_digest: HashDigest
    selected_catalog_ids: CanonicalSet[CatalogId]


def _ordered_tuple(value: Any) -> tuple[Any, ...]:
    if not isinstance(value, list | tuple):
        raise ValueError("ordered sequence must be a JSON array")
    return tuple(value)


type OrderedSequence[ItemT] = Annotated[
    tuple[ItemT, ...],
    BeforeValidator(_ordered_tuple),
]


class ReferenceTraceControl(ControlSpecModel):
    control_ref: ControlRef
    selection: Literal["effect", "unknown_failure"]
    predicate_results: OrderedSequence[Literal["true", "false", "unknown"]]
    emitted_code: NamespacedValue


class ReferenceEvaluationTrace(ControlSpecModel):
    snapshot_digest: HashDigest
    facts_digest: HashDigest
    evaluated_controls: CanonicalSet[ReferenceTraceControl]
    final_verdict: Verdict
    final_route: Route
    explanation_codes: CanonicalSet[NamespacedValue]


class DecideRequest(ControlSpecModel):
    schema_name: Literal["controlspec/api/v0/decide-request"] = Field(
        "controlspec/api/v0/decide-request",
        alias="schema",
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    action_intent: ActionIntent
    selection: ReferenceSelection
    options: EvaluationOptions = EvaluationOptions()


class DecideResponse(ControlSpecModel):
    schema_name: Literal["controlspec/api/v0/decide-response"] = Field(
        "controlspec/api/v0/decide-response",
        alias="schema",
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    decision: Decision
    matched_controls: CanonicalSet[ControlRef]
    trace: ReferenceEvaluationTrace | None
    catalog_binding: CatalogBinding
    authority: ReferenceAuthorityView = REFERENCE_AUTHORITY
    time_source: Literal["caller_reference", "server_reference"]
    explanation_codes: CanonicalSet[NamespacedValue]


class ComparisonStatus(StrEnum):
    SAME = "same"
    CHANGED = "changed"
    INVALID = "invalid"


class RecheckComparisons(ControlSpecModel):
    actor: ComparisonStatus
    action: ComparisonStatus
    resource: ComparisonStatus
    context: ComparisonStatus
    controls: ComparisonStatus
    decision_window: ComparisonStatus


class RecheckRequest(ControlSpecModel):
    schema_name: Literal["controlspec/api/v0/recheck-request"] = Field(
        "controlspec/api/v0/recheck-request",
        alias="schema",
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    original_action_intent: ActionIntent
    prior_decision: Decision
    current_action_intent: ActionIntent
    selection: ReferenceSelection
    options: EvaluationOptions = EvaluationOptions()


class RecheckResponse(ControlSpecModel):
    schema_name: Literal["controlspec/api/v0/recheck-response"] = Field(
        "controlspec/api/v0/recheck-response",
        alias="schema",
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    recheck: RecheckResult
    comparisons: RecheckComparisons
    catalog_binding: CatalogBinding
    authority: ReferenceAuthorityView = REFERENCE_AUTHORITY
    explanation_codes: CanonicalSet[NamespacedValue]


class ReferenceReportedExecution(ControlSpecModel):
    actual_route: Route | None
    execution_result: NamespacedValue | None
    evidence_refs: CanonicalSet[EvidenceRef]
    business_outcome: NamespacedValue | None
    occurred_at: UtcTimestamp


class ReceiptAssessmentRequest(ControlSpecModel):
    schema_name: Literal["controlspec/api/v0/receipt-assessment-request"] = Field(
        "controlspec/api/v0/receipt-assessment-request",
        alias="schema",
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    action_intent: ActionIntent
    decision: Decision
    selection: ReferenceSelection
    reported_execution: ReferenceReportedExecution
    options: ReferenceTimeOptions = ReferenceTimeOptions()


class ReceiptAssessmentResponse(ControlSpecModel):
    schema_name: Literal["controlspec/api/v0/receipt-assessment-response"] = Field(
        "controlspec/api/v0/receipt-assessment-response",
        alias="schema",
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    receipt: Receipt
    stored: Literal[False] = False
    durable: Literal[False] = False
    assessment_basis: Literal["caller_report_only"] = "caller_report_only"
    catalog_binding: CatalogBinding
    authority: ReferenceAuthorityView = REFERENCE_AUTHORITY
    explanation_codes: CanonicalSet[NamespacedValue]


class CatalogEntryMetadata(ControlSpecModel):
    example_only: Literal[True] = True
    non_authoritative: Literal[True] = True
    reference_evaluation_enabled: StrictBool
    profile_kind: Literal["portable_core", "riskspec_enterprise"]
    source: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=512)]


class ControlSummary(ControlSpecModel):
    catalog_id: CatalogId
    namespace: str
    control_id: str
    version: SemVer
    semantic_digest: HashDigest
    status: Literal["draft", "published", "retired"]
    title: str
    metadata: CatalogEntryMetadata


class PackSummary(ControlSpecModel):
    catalog_id: CatalogId
    namespace: str
    pack_id: str
    version: SemVer
    semantic_digest: HashDigest
    status: Literal["draft", "published", "retired"]
    title: str
    metadata: CatalogEntryMetadata


class ControlListResponse(ControlSpecModel):
    items: tuple[ControlSummary, ...]
    catalog_digest: HashDigest
    authority: ReferenceAuthorityView = REFERENCE_AUTHORITY


class PackListResponse(ControlSpecModel):
    items: tuple[PackSummary, ...]
    catalog_digest: HashDigest
    authority: ReferenceAuthorityView = REFERENCE_AUTHORITY


class ControlDetailResponse(ControlSpecModel):
    control: Control
    summary: ControlSummary
    containing_pack_catalog_ids: CanonicalSet[CatalogId]
    catalog_digest: HashDigest
    authority: ReferenceAuthorityView = REFERENCE_AUTHORITY


class PackDetailResponse(ControlSpecModel):
    pack: ControlPack
    summary: PackSummary
    control_catalog_ids: CanonicalSet[CatalogId]
    catalog_digest: HashDigest
    authority: ReferenceAuthorityView = REFERENCE_AUTHORITY


class ControlSpecApiErrorCode(StrEnum):
    INVALID_JSON = "CONTROL_SPEC_INVALID_JSON"
    SELECTION_INVALID = "CONTROL_SPEC_SELECTION_INVALID"
    CATALOG_ITEM_NOT_FOUND = "CONTROL_SPEC_CATALOG_ITEM_NOT_FOUND"
    CATALOG_BINDING_MISMATCH = "CONTROL_SPEC_CATALOG_BINDING_MISMATCH"
    INPUT_INVALID = "CONTROL_SPEC_INPUT_INVALID"
    PRIOR_BINDING_INVALID = "CONTROL_SPEC_PRIOR_BINDING_INVALID"
    REFERENCE_CATALOG_UNAVAILABLE = "CONTROL_SPEC_REFERENCE_CATALOG_UNAVAILABLE"
    INTERNAL_FAILURE = "CONTROL_SPEC_INTERNAL_FAILURE"


class ControlSpecValidationIssue(ControlSpecModel):
    loc: tuple[str | int, ...]
    type: str


class ControlSpecApiErrorBody(ControlSpecModel):
    code: ControlSpecApiErrorCode
    detail_code: NamespacedValue | None
    message: str
    issues: tuple[ControlSpecValidationIssue, ...] = ()


class ControlSpecApiErrorResponse(ControlSpecModel):
    error: ControlSpecApiErrorBody
