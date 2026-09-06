"""Trusted, immutable inputs to the deterministic policy evaluator.

These models are runtime ports, not public authority contracts.  Callers must
resolve them from authenticated, tenant-bound stores.  Client context is never
read by the evaluator as an authoritative fact.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import StrictBool, model_validator

from assurance.contracts.common import (
    AssuranceModel,
    CanonicalSet,
    HashDigest,
    MeterReference,
    Money,
    NonEmptyString,
    NonNegativeInt,
    ObjectHashReference,
    PrincipalIdentity,
    TypedValue,
    UtcTimestamp,
)
from assurance.contracts.objects import (
    ActionIntent,
    ControlDecision,
    EvaluationInputManifest,
    LifecycleEvent,
    QueryDescriptor,
    RiskSpecContract,
)
from assurance.contracts.workflow import StreamHead, VersionedComponentReference
from assurance.domain import (
    ApprovalOutcome,
    AuthorityRole,
    CanonicalAction,
    Classification,
    DomainVerb,
    EvidenceKind,
    FieldPath,
    ResourceType,
    RouteId,
    SubjectRole,
)
from assurance.domain.enums import (
    EnforcementDisposition,
    EnforcementMode,
    ReadinessCode,
    WorkflowEnvironment,
)


class RuntimeErrorCode(StrEnum):
    MALFORMED_INPUT = "MALFORMED_INPUT"
    INTENT_HASH_INVALID = "INTENT_HASH_INVALID"
    TENANT_MISMATCH = "TENANT_MISMATCH"
    ACTOR_MISMATCH = "ACTOR_MISMATCH"
    POLICY_HASH_INVALID = "POLICY_HASH_INVALID"
    LIFECYCLE_HASH_INVALID = "LIFECYCLE_HASH_INVALID"
    AMBIGUOUS_POLICY_SELECTION = "AMBIGUOUS_POLICY_SELECTION"
    DEPENDENCY_NOT_SELECTED = "DEPENDENCY_NOT_SELECTED"
    MANIFEST_HASH_INVALID = "MANIFEST_HASH_INVALID"
    DECISION_HASH_INVALID = "DECISION_HASH_INVALID"
    EVALUATOR_VERSION_UNKNOWN = "EVALUATOR_VERSION_UNKNOWN"
    REPLAY_INPUT_MISMATCH = "REPLAY_INPUT_MISMATCH"
    REPLAY_SEMANTIC_MISMATCH = "REPLAY_SEMANTIC_MISMATCH"


class RuntimeRejected(RuntimeError):
    """Malformed or untrusted input is rejected without a policy verdict."""

    def __init__(self, code: RuntimeErrorCode, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        message = code.value if not detail else f"{code.value}:{detail}"
        super().__init__(message)


class TrustedFact(AssuranceModel):
    fact_ref: ObjectHashReference
    field_path: FieldPath
    subject_resource_id: UUID
    value: TypedValue
    valid_from: UtcTimestamp
    valid_until: UtcTimestamp


class TrustedEvidence(AssuranceModel):
    evidence_ref: ObjectHashReference
    production_event_ref: ObjectHashReference
    certification_event_ref: ObjectHashReference
    verification_event_ref: ObjectHashReference
    control_key: NonEmptyString
    evidence_kind: EvidenceKind
    subject_business_id: NonEmptyString
    bound_requested_state_change: TypedValue | None
    bound_data_classification: NonEmptyString | None
    classification: Classification
    producer: PrincipalIdentity
    certifier: PrincipalIdentity
    verified_at: UtcTimestamp
    valid_from: UtcTimestamp
    valid_until: UtcTimestamp


class TrustedApproval(AssuranceModel):
    approval_ref: ObjectHashReference
    authority_grant_ref: ObjectHashReference
    control_key: NonEmptyString
    role: AuthorityRole
    scope_key: NonEmptyString
    approver: PrincipalIdentity
    outcome: ApprovalOutcome
    valid_from: UtcTimestamp
    valid_until: UtcTimestamp


class TrustedAuthority(AssuranceModel):
    grant_ref: ObjectHashReference
    principal_version_id: UUID
    role: AuthorityRole
    scope_key: NonEmptyString
    canonical_action: CanonicalAction
    domain_verb: DomainVerb
    resource_type: ResourceType
    business_id: NonEmptyString
    route: RouteId
    behalf_of_party_id: UUID
    valid_from: UtcTimestamp
    valid_until: UtcTimestamp


class TrustedSubject(AssuranceModel):
    subject_role: SubjectRole
    principal: PrincipalIdentity


class TrustedEconomicSnapshot(AssuranceModel):
    meter_refs: CanonicalSet[MeterReference]
    event_refs: CanonicalSet[ObjectHashReference]
    current_attempt_count: NonNegativeInt
    current_cost: Money
    maximum_cost_for_attempt: Money

    @model_validator(mode="after")
    def currencies_match(self) -> TrustedEconomicSnapshot:
        if self.current_cost.currency != self.maximum_cost_for_attempt.currency:
            raise ValueError("current and projected attempt cost currencies must match")
        if self.current_cost.minor_units < 0 or self.maximum_cost_for_attempt.minor_units < 0:
            raise ValueError("trusted economic values cannot be negative")
        return self


class TrustedEvaluationSnapshot(AssuranceModel):
    tenant_id: UUID
    authenticated_principal: PrincipalIdentity
    evaluated_at: UtcTimestamp
    decision_expires_at: UtcTimestamp
    policy_namespace: NonEmptyString | None
    facts: CanonicalSet[TrustedFact]
    evidence: CanonicalSet[TrustedEvidence]
    approvals: CanonicalSet[TrustedApproval]
    authorities: CanonicalSet[TrustedAuthority]
    subjects: CanonicalSet[TrustedSubject]
    economic: TrustedEconomicSnapshot
    query_descriptors: CanonicalSet[QueryDescriptor]
    human_decision_refs: CanonicalSet[ObjectHashReference]
    lineage_membership_refs: CanonicalSet[ObjectHashReference]

    @model_validator(mode="after")
    def validate_trusted_snapshot(self) -> TrustedEvaluationSnapshot:
        if self.authenticated_principal.tenant_id != self.tenant_id:
            raise ValueError("authenticated principal must be tenant-bound")
        if self.decision_expires_at <= self.evaluated_at:
            raise ValueError("decision expiry must be after evaluation")
        references = [
            *self.human_decision_refs,
            *self.lineage_membership_refs,
            *self.economic.event_refs,
            *(fact.fact_ref for fact in self.facts),
            *(
                reference
                for item in self.evidence
                for reference in (
                    item.evidence_ref,
                    item.production_event_ref,
                    item.certification_event_ref,
                    item.verification_event_ref,
                )
            ),
            *(
                reference
                for item in self.approvals
                for reference in (item.approval_ref, item.authority_grant_ref)
            ),
            *(item.grant_ref for item in self.authorities),
        ]
        principals = [
            self.authenticated_principal,
            *(item.producer for item in self.evidence),
            *(item.certifier for item in self.evidence),
            *(item.approver for item in self.approvals),
            *(item.principal for item in self.subjects),
        ]
        if any(reference.tenant_id != self.tenant_id for reference in references):
            raise ValueError("every trusted snapshot reference must be tenant-bound")
        if any(reference.tenant_id != self.tenant_id for reference in self.economic.meter_refs):
            raise ValueError("every trusted meter must be tenant-bound")
        if any(principal.tenant_id != self.tenant_id for principal in principals):
            raise ValueError("every trusted snapshot principal must be tenant-bound")
        if any(
            head.tenant_id != self.tenant_id
            for descriptor in self.query_descriptors
            for head in descriptor.stream_heads
        ):
            raise ValueError("every query stream head must be tenant-bound")
        return self


class WorkflowEvaluationBinding(AssuranceModel):
    """Server-loaded exact workflow state used for evaluation and recheck."""

    tenant_id: UUID
    workflow_ref: ObjectHashReference
    deployment_ref: VersionedComponentReference
    enforcement_point_ref: VersionedComponentReference
    action_mapping_refs: CanonicalSet[VersionedComponentReference]
    outcome_evidence_mapping_refs: CanonicalSet[VersionedComponentReference]
    connector_refs: CanonicalSet[VersionedComponentReference]
    target_connector_ref: VersionedComponentReference
    protected_target_registry_ref: ObjectHashReference
    target_registry_key: NonEmptyString
    target_key_id: NonEmptyString
    environment: WorkflowEnvironment
    mode: EnforcementMode
    mode_transition_ref: ObjectHashReference
    mode_head: StreamHead
    readiness_report_ref: ObjectHashReference
    readiness_eligible: StrictBool
    readiness_codes: CanonicalSet[ReadinessCode]
    policy_coverage_ref: ObjectHashReference
    policy_set_digest: HashDigest
    applicability_query_head_refs: CanonicalSet[ObjectHashReference]
    component_lifecycle_event_refs: CanonicalSet[ObjectHashReference]
    connector_health_event_refs: CanonicalSet[ObjectHashReference]
    deployment_approval_refs: CanonicalSet[ObjectHashReference]
    readiness_exception_refs: CanonicalSet[ObjectHashReference]
    deployment_published: StrictBool
    enforcement_point_active: StrictBool
    mappings_published: StrictBool
    connectors_active_and_current: StrictBool
    protected_inventory_complete: StrictBool
    expected_heads_current: StrictBool
    fallback_condition: ReadinessCode | None
    fallback_disposition: EnforcementDisposition
    fallback_route: RouteId | None

    @model_validator(mode="after")
    def validate_workflow_binding(self) -> WorkflowEvaluationBinding:
        object_refs = [
            self.workflow_ref,
            self.protected_target_registry_ref,
            self.mode_transition_ref,
            self.readiness_report_ref,
            self.policy_coverage_ref,
            *self.applicability_query_head_refs,
            *self.component_lifecycle_event_refs,
            *self.connector_health_event_refs,
            *self.deployment_approval_refs,
            *self.readiness_exception_refs,
        ]
        component_refs = [
            self.deployment_ref,
            self.enforcement_point_ref,
            *self.action_mapping_refs,
            *self.outcome_evidence_mapping_refs,
            *self.connector_refs,
        ]
        if (
            any(item.tenant_id != self.tenant_id for item in object_refs)
            or any(item.tenant_id != self.tenant_id for item in component_refs)
            or self.mode_head.tenant_id != self.tenant_id
            or self.target_connector_ref not in self.connector_refs
        ):
            raise ValueError("workflow evaluation binding is not tenant-complete")
        if self.readiness_eligible and self.readiness_codes:
            raise ValueError("eligible readiness cannot retain blocking codes")
        if (
            self.fallback_disposition is not EnforcementDisposition.USE_APPROVED_FALLBACK
            and self.fallback_route is not None
        ):
            raise ValueError("fallback route requires approved fallback disposition")
        if self.fallback_disposition is EnforcementDisposition.USE_APPROVED_FALLBACK and (
            self.fallback_condition is None or self.fallback_route is None
        ):
            raise ValueError("approved fallback requires an exact condition and route")
        return self


class WorkflowRuntimeState(AssuranceModel):
    tenant_id: UUID
    snapshot: TrustedEvaluationSnapshot
    binding: WorkflowEvaluationBinding

    @model_validator(mode="after")
    def tenant_is_consistent(self) -> WorkflowRuntimeState:
        if self.snapshot.tenant_id != self.tenant_id or self.binding.tenant_id != self.tenant_id:
            raise ValueError("workflow runtime state must remain tenant-bound")
        return self


class PolicyCatalogSnapshot(AssuranceModel):
    versions: CanonicalSet[RiskSpecContract]
    lifecycle_events: CanonicalSet[LifecycleEvent]


class ReplayBundle(AssuranceModel):
    intent: ActionIntent
    trusted_snapshot: TrustedEvaluationSnapshot
    policy_snapshot: PolicyCatalogSnapshot
    original_manifest: EvaluationInputManifest
    original_decision: ControlDecision


class ReplayResult(AssuranceModel):
    succeeded: bool
    code: NonEmptyString
    replayed_manifest: EvaluationInputManifest | None
    replayed_decision: ControlDecision | None


def active_at(*, valid_from: datetime, valid_until: datetime, at: datetime) -> bool:
    return valid_from <= at < valid_until
