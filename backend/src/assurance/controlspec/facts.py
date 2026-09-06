"""Private immutable trust-boundary records for the ControlSpec evaluator."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal, cast

from pydantic import StrictBool, model_validator

from assurance.contracts.canonical import canonical_json, sha256_digest
from assurance.controlspec.contracts import (
    Actor,
    ApprovalRequirement,
    CanonicalSet,
    Control,
    ControlRef,
    ControlSpecModel,
    DecisionRef,
    EvidenceRef,
    EvidenceRequirement,
    HashDigest,
    IntentRef,
    NamespacedValue,
    ObjectRef,
    Route,
    UtcTimestamp,
    Verdict,
)


class SnapshotAuthorityMode(StrEnum):
    HOST_AUTHORIZED = "host_authorized"
    NON_AUTHORITATIVE_CONFORMANCE = "non_authoritative_conformance"


class PublishedControlSnapshot(ControlSpecModel):
    controls: CanonicalSet[Control]
    observed_at: UtcTimestamp
    authority_mode: SnapshotAuthorityMode
    host_authority_refs: CanonicalSet[ObjectRef]
    supported_extensions: CanonicalSet[NamespacedValue]
    display_extensions: CanonicalSet[NamespacedValue]
    supported_verifiers: CanonicalSet[NamespacedValue]
    snapshot_digest: HashDigest | None = None

    @model_validator(mode="after")
    def authority_mode_is_not_relabelable(self) -> PublishedControlSnapshot:
        if self.authority_mode is SnapshotAuthorityMode.HOST_AUTHORIZED:
            if not self.host_authority_refs:
                raise ValueError("host-authorized snapshots require authority references")
            if any(reference.digest is None for reference in self.host_authority_refs):
                raise ValueError("host authority references require exact digests")
        elif self.host_authority_refs:
            raise ValueError("conformance snapshots cannot carry host authority references")
        return self


class ApprovalFact(ControlSpecModel):
    approval_id: str
    intent_ref: IntentRef
    basis_decision_ref: DecisionRef
    requirement_id: str
    scope_digest: HashDigest
    approver: Actor
    authority_ref: ObjectRef
    roles: CanonicalSet[NamespacedValue]
    separated_role_actor_ids: dict[NamespacedValue, CanonicalSet[str]]
    lineage_complete: StrictBool
    approved: StrictBool
    valid_from: UtcTimestamp
    valid_until: UtcTimestamp
    fact_digest: HashDigest | None = None


class VerifiedEvidenceFact(ControlSpecModel):
    evidence_ref: EvidenceRef
    intent_ref: IntentRef
    kind: NamespacedValue
    subject: NamespacedValue
    producer_actor_id: str
    producer_lineage_ids: CanonicalSet[str]
    producer_lineage_complete: StrictBool = False
    certifier_actor_id: str
    certifier_lineage_ids: CanonicalSet[str]
    certifier_lineage_complete: StrictBool = False
    verified_at: UtcTimestamp
    fact_digest: HashDigest | None = None


class ProfileAssessmentStatus(StrEnum):
    SATISFIED = "satisfied"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ProfileAssessmentFact(ControlSpecModel):
    verifier: NamespacedValue
    intent_ref: IntentRef
    control_ref: ControlRef
    snapshot_digest: HashDigest
    status: ProfileAssessmentStatus
    retained_verdict: Verdict
    retained_route: Route
    explanation_code: NamespacedValue
    retained_approval_requirements: CanonicalSet[ApprovalRequirement] = ()
    retained_evidence_requirements: CanonicalSet[EvidenceRequirement] = ()
    fact_digest: HashDigest | None = None


class EvaluationFacts(ControlSpecModel):
    approval_basis_ref: DecisionRef | None
    approvals: CanonicalSet[ApprovalFact]
    evidence: CanonicalSet[VerifiedEvidenceFact]
    profile_assessments: CanonicalSet[ProfileAssessmentFact]


class TraceControl(ControlSpecModel):
    control_ref: ControlRef
    selection: Literal["effect", "unknown_failure"]
    predicate_results: tuple[Literal["true", "false", "unknown"], ...]
    emitted_code: NamespacedValue


class EvaluationTrace(ControlSpecModel):
    snapshot_digest: HashDigest
    facts_digest: HashDigest
    evaluated_controls: CanonicalSet[TraceControl]
    final_verdict: Verdict
    final_route: Route
    explanation_codes: CanonicalSet[NamespacedValue]


class RecheckResult(ControlSpecModel):
    valid: StrictBool
    prior_decision_ref: DecisionRef
    reason_code: NamespacedValue
    current_decision_ref: DecisionRef | None


class TrustedExecutionObservation(ControlSpecModel):
    execution_ref: ObjectRef
    actual_route: Route | None
    execution_outcome: Literal["succeeded", "failed", "aborted", "not_executed"]
    occurred_at: UtcTimestamp
    recorded_at: UtcTimestamp
    observation_digest: HashDigest | None = None


def _digest_payload(value: Any, digest_field: str) -> HashDigest:
    payload = value.model_dump(mode="json", by_alias=True, exclude_none=False)
    payload.pop(digest_field, None)
    return sha256_digest(canonical_json(payload))


def finalize_snapshot(value: PublishedControlSnapshot) -> PublishedControlSnapshot:
    return value.model_copy(update={"snapshot_digest": _digest_payload(value, "snapshot_digest")})


def verify_snapshot(value: PublishedControlSnapshot) -> bool:
    return value.snapshot_digest == _digest_payload(value, "snapshot_digest")


FactT = ApprovalFact | VerifiedEvidenceFact | ProfileAssessmentFact


def finalize_fact[ValueT: FactT](value: ValueT) -> ValueT:
    return cast(
        ValueT,
        value.model_copy(update={"fact_digest": _digest_payload(value, "fact_digest")}),
    )


def verify_fact(value: FactT) -> bool:
    return value.fact_digest == _digest_payload(value, "fact_digest")


def facts_digest(value: EvaluationFacts) -> HashDigest:
    return sha256_digest(canonical_json(value))


def finalize_execution(
    value: TrustedExecutionObservation,
) -> TrustedExecutionObservation:
    return value.model_copy(
        update={"observation_digest": _digest_payload(value, "observation_digest")}
    )


def verify_execution(value: TrustedExecutionObservation) -> bool:
    return value.observation_digest == _digest_payload(value, "observation_digest")
