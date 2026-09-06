"""Canonical protected-workflow contracts for change 0002.

The models are immutable data boundaries only. They do not implement mapping,
selection, readiness, lifecycle transitions, connector behavior, or execution.
"""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, Field, StrictBool, StringConstraints, model_validator

from assurance.contracts.common import (
    AssuranceModel,
    CanonicalSet,
    HashDigest,
    NonEmptyString,
    NonNegativeInt,
    ObjectHashReference,
    PositiveInt,
    PrincipalIdentity,
    TypedValue,
    UtcTimestamp,
    VersionedSpecReference,
)
from assurance.domain import CanonicalAction, FieldPath, ResourceType, RouteId
from assurance.domain.enums import (
    ConnectorHealth,
    ConnectorKind,
    ConnectorOperation,
    DeploymentApprovalKind,
    DeploymentApprovalOutcome,
    EnforcementDisposition,
    EnforcementMode,
    MappingConversion,
    MappingOutputPath,
    MappingPresence,
    MappingSource,
    OutcomeOutputPath,
    ReadinessCode,
    ShadowComparisonCode,
    ShadowDisposition,
    ShadowRunState,
    WorkflowEnvironment,
)

JsonPointer = Annotated[
    str,
    StringConstraints(pattern=r"^(?:/(?:[^~/]|~0|~1)*)*$", strict=True),
]


class WorkflowStoredObject(AssuranceModel):
    tenant_id: UUID
    object_id: UUID
    created_at: UtcTimestamp
    created_by_principal_version_id: UUID

    @model_validator(mode="after")
    def all_nested_tenant_links_match(self) -> WorkflowStoredObject:
        def nested_tenant_ids(value: object) -> list[UUID]:
            if isinstance(value, BaseModel):
                tenant_ids = []
                tenant = getattr(value, "tenant_id", None)
                if isinstance(tenant, UUID):
                    tenant_ids.append(tenant)
                for field_name in type(value).model_fields:
                    if field_name != "tenant_id":
                        tenant_ids.extend(nested_tenant_ids(getattr(value, field_name)))
                return tenant_ids
            if isinstance(value, list | tuple | set | frozenset):
                return [
                    tenant_id
                    for item in value
                    for tenant_id in nested_tenant_ids(item)
                ]
            if isinstance(value, dict):
                return [
                    tenant_id
                    for item in value.values()
                    for tenant_id in nested_tenant_ids(item)
                ]
            return []

        if any(tenant_id != self.tenant_id for tenant_id in nested_tenant_ids(self)):
            raise ValueError("all workflow object links must be tenant-bound")
        return self


class VersionedComponentReference(AssuranceModel):
    tenant_id: UUID
    object_id: UUID
    stream_key: NonEmptyString
    revision: PositiveInt
    content_hash: HashDigest


class StreamHead(AssuranceModel):
    tenant_id: UUID
    stream_id: UUID
    sequence: NonNegativeInt
    event_ref: ObjectHashReference | None
    head_hash: HashDigest


class SecretRef(AssuranceModel):
    provider: Literal["LOCAL_SECRET_STORE"]
    secret_id: NonEmptyString
    version_id: NonEmptyString


class ProtectedActionDeclaration(AssuranceModel):
    operation: Literal["ERP_SUPPLIER_MASTER.ACTIVATE_SUPPLIER"]
    canonical_action: Literal[CanonicalAction.MODIFY]
    resource_type: Literal[ResourceType.SUPPLIER]
    requested_state: Literal["ACTIVE"]
    human_decision_ref: ObjectHashReference


class ProtectedWorkflow(WorkflowStoredObject):
    schema_name: Literal["ProtectedWorkflow"]
    schema_version: Literal[1]
    workflow_key: NonEmptyString
    owner_principal_version_id: UUID
    environment: WorkflowEnvironment
    protected_actions: Annotated[CanonicalSet[ProtectedActionDeclaration], Field(min_length=1)]
    human_decision_refs: Annotated[
        CanonicalSet[ObjectHashReference],
        Field(min_length=1),
    ]
    workflow_hash: HashDigest


class ProtectedTargetRegistryEntry(WorkflowStoredObject):
    schema_name: Literal["ProtectedTargetRegistryEntry"]
    schema_version: Literal[1]
    registry_key: NonEmptyString
    operation: Literal["ERP_SUPPLIER_MASTER.ACTIVATE_SUPPLIER"]
    canonical_action: Literal[CanonicalAction.MODIFY]
    resource_type: Literal[ResourceType.SUPPLIER]
    requested_state: Literal["ACTIVE"]
    environment: WorkflowEnvironment
    target_connector_ref: VersionedComponentReference
    attestation_ref: ObjectHashReference
    attestor_principal_version_id: UUID
    human_decision_refs: Annotated[
        CanonicalSet[ObjectHashReference],
        Field(min_length=1),
    ]
    valid_from: UtcTimestamp
    valid_until: UtcTimestamp
    registry_hash: HashDigest

    @model_validator(mode="after")
    def validity_is_ordered(self) -> ProtectedTargetRegistryEntry:
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self


class WorkflowDeploymentRevision(WorkflowStoredObject):
    schema_name: Literal["WorkflowDeploymentRevision"]
    schema_version: Literal[1]
    workflow_ref: ObjectHashReference
    deployment_key: NonEmptyString
    revision: PositiveInt
    predecessor_ref: ObjectHashReference | None
    source_revision_ref: ObjectHashReference | None
    environment: WorkflowEnvironment
    enforcement_point_ref: VersionedComponentReference
    connector_refs: Annotated[CanonicalSet[VersionedComponentReference], Field(min_length=1)]
    action_mapping_refs: Annotated[
        CanonicalSet[VersionedComponentReference],
        Field(min_length=1),
    ]
    outcome_evidence_mapping_refs: Annotated[
        CanonicalSet[VersionedComponentReference],
        Field(min_length=1),
    ]
    protected_target_registry_ref: ObjectHashReference
    human_decision_refs: Annotated[
        CanonicalSet[ObjectHashReference],
        Field(min_length=1),
    ]
    valid_from: UtcTimestamp
    valid_until: UtcTimestamp
    content_hash: HashDigest

    @model_validator(mode="after")
    def validity_is_ordered(self) -> WorkflowDeploymentRevision:
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self


class FallbackBinding(AssuranceModel):
    condition_code: ReadinessCode
    disposition: EnforcementDisposition
    fallback_route: RouteId | None
    connector_ref: VersionedComponentReference | None
    human_decision_ref: ObjectHashReference


class EnforcementPoint(WorkflowStoredObject):
    schema_name: Literal["EnforcementPoint"]
    schema_version: Literal[1]
    workflow_ref: ObjectHashReference
    enforcement_point_key: NonEmptyString
    revision: PositiveInt
    predecessor_ref: ObjectHashReference | None
    environment: WorkflowEnvironment
    inbound_connector_ref: VersionedComponentReference
    target_connector_ref: VersionedComponentReference
    evidence_connector_refs: CanonicalSet[VersionedComponentReference]
    reporting_connector_refs: CanonicalSet[VersionedComponentReference]
    protected_target_registry_ref: ObjectHashReference
    fallback_bindings: Annotated[CanonicalSet[FallbackBinding], Field(min_length=1)]
    content_hash: HashDigest


class Connector(WorkflowStoredObject):
    schema_name: Literal["Connector"]
    schema_version: Literal[1]
    connector_key: NonEmptyString
    workflow_ref: ObjectHashReference
    stream_id: UUID
    revision: PositiveInt
    predecessor_ref: ObjectHashReference | None
    configuration_sequence: PositiveInt
    configuration_predecessor_ref: ObjectHashReference
    connector_kind: ConnectorKind
    adapter_type: Literal["DETERMINISTIC_SIMULATOR"]
    environment: WorkflowEnvironment
    operations: Annotated[CanonicalSet[ConnectorOperation], Field(min_length=1)]
    secret_ref: SecretRef | None
    deterministic_profile: NonEmptyString
    configuration_hash: HashDigest
    target_registry_key: NonEmptyString | None
    human_decision_refs: CanonicalSet[ObjectHashReference]
    content_hash: HashDigest


class SelectExpression(AssuranceModel):
    expression_type: Literal["SELECT"]
    source: MappingSource
    pointer: JsonPointer
    source_schema_hash: HashDigest


class ConstantExpression(AssuranceModel):
    expression_type: Literal["CONSTANT"]
    registered_constant_id: NonEmptyString
    value: TypedValue
    trace_ref: ObjectHashReference
    configuration_hash: HashDigest


class EnumMapEntry(AssuranceModel):
    input_value: NonEmptyString
    output_value: NonEmptyString


class EnumMapExpression(AssuranceModel):
    expression_type: Literal["ENUM_MAP"]
    source: MappingSource
    pointer: JsonPointer
    source_schema_hash: HashDigest
    entries: Annotated[CanonicalSet[EnumMapEntry], Field(min_length=1)]


class ConvertExpression(AssuranceModel):
    expression_type: Literal["CONVERT"]
    source: MappingSource
    pointer: JsonPointer
    source_schema_hash: HashDigest
    conversion: MappingConversion


ScalarMappingExpression = Annotated[
    SelectExpression | ConstantExpression | EnumMapExpression | ConvertExpression,
    Field(discriminator="expression_type"),
]


class ContextClaimExpression(AssuranceModel):
    expression_type: Literal["CONTEXT_CLAIM"]
    field_path: FieldPath
    value_expression: ScalarMappingExpression


MappingExpression = Annotated[
    SelectExpression
    | ConstantExpression
    | EnumMapExpression
    | ConvertExpression
    | ContextClaimExpression,
    Field(discriminator="expression_type"),
]


class ActionBinding(AssuranceModel):
    output_path: MappingOutputPath
    presence: MappingPresence
    expression: MappingExpression


class OutcomeBinding(AssuranceModel):
    output_path: OutcomeOutputPath
    presence: MappingPresence
    expression: ScalarMappingExpression


class ActionMapping(WorkflowStoredObject):
    schema_name: Literal["ActionMapping"]
    schema_version: Literal[1]
    mapping_key: NonEmptyString
    revision: PositiveInt
    predecessor_ref: ObjectHashReference | None
    environment: WorkflowEnvironment
    source_schema_hash: HashDigest
    target_schema_hash: HashDigest
    bindings: Annotated[CanonicalSet[ActionBinding], Field(min_length=1)]
    accepted_action_decision_ref: ObjectHashReference
    human_decision_refs: Annotated[
        CanonicalSet[ObjectHashReference],
        Field(min_length=1),
    ]
    effective_from: UtcTimestamp
    effective_until: UtcTimestamp
    content_hash: HashDigest

    @model_validator(mode="after")
    def validity_is_ordered(self) -> ActionMapping:
        if self.effective_until <= self.effective_from:
            raise ValueError("effective_until must be after effective_from")
        return self


class OutcomeEvidenceMapping(WorkflowStoredObject):
    schema_name: Literal["OutcomeEvidenceMapping"]
    schema_version: Literal[1]
    mapping_key: NonEmptyString
    revision: PositiveInt
    predecessor_ref: ObjectHashReference | None
    environment: WorkflowEnvironment
    source_schema_hash: HashDigest
    target_schema_hash: HashDigest
    bindings: Annotated[CanonicalSet[OutcomeBinding], Field(min_length=1)]
    accepted_outcome_decision_ref: ObjectHashReference
    human_decision_refs: Annotated[
        CanonicalSet[ObjectHashReference],
        Field(min_length=1),
    ]
    effective_from: UtcTimestamp
    effective_until: UtcTimestamp
    content_hash: HashDigest

    @model_validator(mode="after")
    def validity_is_ordered(self) -> OutcomeEvidenceMapping:
        if self.effective_until <= self.effective_from:
            raise ValueError("effective_until must be after effective_from")
        return self


class ApplicabilityFactBinding(AssuranceModel):
    field_path: FieldPath
    fact_ref: ObjectHashReference


class PolicyCoverageBinding(WorkflowStoredObject):
    schema_name: Literal["PolicyCoverageBinding"]
    schema_version: Literal[1]
    workflow_ref: ObjectHashReference
    deployment_ref: VersionedComponentReference
    action_mapping_ref: VersionedComponentReference
    applicability_facts: CanonicalSet[ApplicabilityFactBinding]
    selected_specs: Annotated[CanonicalSet[VersionedSpecReference], Field(min_length=1)]
    dependency_specs: CanonicalSet[VersionedSpecReference]
    lifecycle_event_refs: CanonicalSet[ObjectHashReference]
    query_head_refs: CanonicalSet[ObjectHashReference]
    catalog_head_ref: ObjectHashReference
    selection_algorithm_version: NonEmptyString
    validated_at: UtcTimestamp
    deployment_expected_head: StreamHead
    selected_set_digest: HashDigest
    coverage_hash: HashDigest


class ShadowPopulationWindow(AssuranceModel):
    starts_at: UtcTimestamp
    ends_at: UtcTimestamp
    start_source_sequence: PositiveInt
    end_source_sequence: PositiveInt
    minimum_event_count: PositiveInt
    population_decision_ref: ObjectHashReference

    @model_validator(mode="after")
    def window_and_sequence_are_ordered(self) -> ShadowPopulationWindow:
        if self.ends_at <= self.starts_at:
            raise ValueError("ends_at must be after starts_at")
        if self.end_source_sequence < self.start_source_sequence:
            raise ValueError("end_source_sequence must not precede start_source_sequence")
        return self


class ShadowModeRun(WorkflowStoredObject):
    schema_name: Literal["ShadowModeRun"]
    schema_version: Literal[1]
    workflow_ref: ObjectHashReference
    deployment_ref: VersionedComponentReference
    action_mapping_ref: VersionedComponentReference
    outcome_mapping_ref: VersionedComponentReference
    source_connector_ref: VersionedComponentReference
    actual_observation_connector_refs: Annotated[
        CanonicalSet[VersionedComponentReference],
        Field(min_length=1),
    ]
    population_window: ShadowPopulationWindow
    expected_population_head: StreamHead
    mode_head: StreamHead
    comparison_version: NonEmptyString
    state: ShadowRunState
    run_hash: HashDigest


class ShadowObservation(WorkflowStoredObject):
    schema_name: Literal["ShadowObservation"]
    schema_version: Literal[1]
    run_ref: ObjectHashReference
    deployment_ref: VersionedComponentReference
    source_event_ref: ObjectHashReference
    source_sequence: PositiveInt
    disposition: ShadowDisposition
    duplicate_of_ref: ObjectHashReference | None
    action_mapping_ref: VersionedComponentReference
    mapped_intent_ref: ObjectHashReference | None
    authoritative_fact_refs: CanonicalSet[ObjectHashReference]
    policy_coverage_ref: ObjectHashReference | None
    evaluation_manifest_ref: ObjectHashReference | None
    counterfactual_decision_ref: ObjectHashReference | None
    actual_route: RouteId | None
    actual_outcome_ref: ObjectHashReference | None
    actual_evidence_refs: CanonicalSet[ObjectHashReference]
    provenance_refs: CanonicalSet[ObjectHashReference]
    mode_head: StreamHead
    comparison_code: ShadowComparisonCode
    counterfactual: Literal[True]
    observation_hash: HashDigest


class EnforcementModeTransition(WorkflowStoredObject):
    schema_name: Literal["EnforcementModeTransition"]
    schema_version: Literal[1]
    workflow_ref: ObjectHashReference
    deployment_ref: VersionedComponentReference
    prior_mode: EnforcementMode
    next_mode: EnforcementMode
    actor: PrincipalIdentity
    authority_grant_ref: ObjectHashReference
    readiness_report_ref: ObjectHashReference | None
    reason_code: NonEmptyString
    occurred_at: UtcTimestamp
    idempotency_key: NonEmptyString
    expected_head: StreamHead
    predecessor_event_ref: ObjectHashReference | None
    disposition: EnforcementDisposition
    event_hash: HashDigest


class ReadinessComponentBinding(AssuranceModel):
    component_type: Literal[
        "CONNECTOR",
        "ENFORCEMENT_POINT",
        "ACTION_MAPPING",
        "OUTCOME_EVIDENCE_MAPPING",
        "PROTECTED_TARGET_INVENTORY",
        "REPRESENTATIVE_TEST",
    ]
    component_ref: ObjectHashReference
    health: ConnectorHealth | None
    validation_ref: ObjectHashReference


class DeploymentReadinessReport(WorkflowStoredObject):
    schema_name: Literal["DeploymentReadinessReport"]
    schema_version: Literal[1]
    workflow_ref: ObjectHashReference
    deployment_ref: VersionedComponentReference
    components: Annotated[CanonicalSet[ReadinessComponentBinding], Field(min_length=1)]
    policy_coverage_ref: ObjectHashReference
    policy_set_digest: HashDigest
    shadow_run_ref: ObjectHashReference
    shadow_population_head: StreamHead
    blocking_gap_refs: CanonicalSet[ObjectHashReference]
    exception_refs: CanonicalSet[ObjectHashReference]
    approval_refs: CanonicalSet[ObjectHashReference]
    unresolved_judgment_ids: CanonicalSet[NonEmptyString]
    mode_head: StreamHead
    deployment_expected_head: StreamHead
    readiness_codes: CanonicalSet[ReadinessCode]
    ready: StrictBool
    validated_at: UtcTimestamp
    expires_at: UtcTimestamp
    toolchain_version: NonEmptyString
    report_hash: HashDigest

    @model_validator(mode="after")
    def readiness_claim_is_internally_consistent(self) -> DeploymentReadinessReport:
        if self.expires_at <= self.validated_at:
            raise ValueError("expires_at must be after validated_at")
        if self.ready and (
            self.readiness_codes
            or self.blocking_gap_refs
            or self.exception_refs
            or self.unresolved_judgment_ids
        ):
            raise ValueError("ready cannot coexist with blocking or unresolved inputs")
        return self


class DeploymentApproval(WorkflowStoredObject):
    schema_name: Literal["DeploymentApproval"]
    schema_version: Literal[1]
    workflow_ref: ObjectHashReference
    deployment_ref: VersionedComponentReference
    readiness_report_ref: ObjectHashReference
    approval_kind: DeploymentApprovalKind
    approver: PrincipalIdentity
    authority_grant_ref: ObjectHashReference
    valid_from: UtcTimestamp
    valid_until: UtcTimestamp
    outcome: DeploymentApprovalOutcome
    predecessor_event_ref: ObjectHashReference | None
    approval_hash: HashDigest

    @model_validator(mode="after")
    def validity_is_ordered(self) -> DeploymentApproval:
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self
