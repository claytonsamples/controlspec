"""Public assurance object contracts.

These models bind data and provenance. They do not make policy decisions or
derive lifecycle, approval, evidence, execution, or assurance status.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import Field, StrictBool, StringConstraints, field_validator, model_validator

from assurance.contracts.canonical import (
    canonical_hash,
    canonical_json,
    canonical_set,
    sha256_digest,
)
from assurance.contracts.common import (
    AssuranceModel,
    AuthorityInstant100ns,
    AuthorityScope,
    CanonicalActionMapping,
    CanonicalSet,
    ContentReference,
    ContextClaim,
    HashDigest,
    MeterReference,
    Money,
    NonEmptyString,
    NonNegativeInt,
    ObjectHashReference,
    PositiveInt,
    PrincipalIdentity,
    ResourceIdentity,
    RetryData,
    SchemaVersion,
    TypedValue,
    UtcTimestamp,
    VersionedSpecReference,
)
from assurance.contracts.policy import (
    Condition,
    EconomicCap,
    HumanDecisionTrace,
    NonPermissiveEffectSpec,
    PolicyModule,
    PolicyModuleV3,
    Predicate,
    Prohibition,
    Requirement,
    RiskSpecV3Requirement,
    RouteConstraint,
    TraceRef,
)
from assurance.contracts.workflow import (
    SecretRef,
    StreamHead,
    VersionedComponentReference,
)
from assurance.domain import (
    ApprovalOutcome,
    AssuranceStatus,
    AuthorityRole,
    CanonicalAction,
    Classification,
    ConditionStatus,
    DomainVerb,
    EvidenceKind,
    EvidenceVerificationOutcome,
    ExecutionGateResult,
    ExecutionOutcome,
    ExplanationCode,
    LifecycleState,
    PolicyParameterKey,
    PrincipalType,
    QueryType,
    ReceiptKind,
    RequirementStatus,
    ResourceType,
    RouteId,
    StreamType,
    Verdict,
)
from assurance.domain.enums import (
    EnforcementDisposition,
    ReadinessCode,
    TargetDispatchEventKind,
    TargetKeyPurpose,
    WorkflowEnvironment,
)


class StoredObject(AssuranceModel):
    tenant_id: UUID
    object_id: UUID
    created_at: UtcTimestamp
    created_by_principal_version_id: UUID


class SourceFragment(StoredObject):
    schema_name: Literal["SourceFragment"]
    schema_version: SchemaVersion
    source_id: UUID
    locator: NonEmptyString
    exact_text: str
    content_encoding: Literal["UTF-8"]
    classification: Classification
    fragment_hash: HashDigest


class RiskSource(StoredObject):
    schema_name: Literal["RiskSource"]
    schema_version: SchemaVersion
    source_type: Literal["PASTED_NARRATIVE", "STRUCTURED_FORM", "EXTERNAL_REFERENCE"]
    owner_party_id: UUID
    source_version: NonEmptyString
    effective_at: UtcTimestamp
    exact_content: str | None
    external_reference: ContentReference | None
    fragments: list[SourceFragment]
    classification: Classification
    content_hash: HashDigest
    source_hash: HashDigest

    @model_validator(mode="after")
    def exactly_one_content_source_and_consistent_fragments(self) -> RiskSource:
        if (self.exact_content is None) == (self.external_reference is None):
            raise ValueError("exactly one of exact_content or external_reference is required")
        for fragment in self.fragments:
            if fragment.tenant_id != self.tenant_id or fragment.source_id != self.object_id:
                raise ValueError("source fragments must bind this source and tenant")
        return self


class ActionMappingChoice(AssuranceModel):
    domain_verb: DomainVerb
    canonical_action: CanonicalAction
    resource_type: ResourceType


class ActionMappingDecisionSemantics(AssuranceModel):
    decision_type: Literal["ACTION_MAPPING"] = "ACTION_MAPPING"
    mappings: Annotated[CanonicalSet[ActionMappingChoice], Field(min_length=1)]


class PolicyParameterDecisionSemantics(AssuranceModel):
    decision_type: Literal["POLICY_PARAMETER"] = "POLICY_PARAMETER"
    parameter_key: PolicyParameterKey
    chosen_value: TypedValue


class PolicyModuleDecisionSemantics(AssuranceModel):
    decision_type: Literal["POLICY_MODULE"] = "POLICY_MODULE"
    policy_module: PolicyModule


PolicyItemDecisionValueType = (
    Predicate
    | NonPermissiveEffectSpec
    | RiskSpecV3Requirement
    | Prohibition
    | RouteConstraint
    | Condition
    | EconomicCap
    | tuple[TraceRef, ...]
)


@dataclass(frozen=True, slots=True)
class PolicyItemDecisionValue:
    """One closed policy path, its typed value, and its inherited citations."""

    item_path: str
    value: PolicyItemDecisionValueType
    trace_refs: tuple[TraceRef, ...]


def _decision_value_trace_refs(
    trace_refs: list[TraceRef],
    *,
    excluded_decision_id: UUID | None,
) -> tuple[TraceRef, ...]:
    return tuple(
        trace
        for trace in trace_refs
        if not (
            excluded_decision_id is not None
            and isinstance(trace, HumanDecisionTrace)
            and trace.decision_id == excluded_decision_id
        )
    )


def _legacy_policy_item_decision_values(
    policy_module: PolicyModule,
    *,
    excluded_decision_id: UUID | None,
) -> list[PolicyItemDecisionValue]:
    values: list[PolicyItemDecisionValue] = []
    for rule in policy_module.rules:
        prefix = f"rule:{rule.rule_key}"
        rule_traces = tuple(rule.trace_refs)
        compared_rule_traces = _decision_value_trace_refs(
            rule.trace_refs,
            excluded_decision_id=excluded_decision_id,
        )
        values.extend(
            (
                PolicyItemDecisionValue(prefix, compared_rule_traces, rule_traces),
                PolicyItemDecisionValue(
                    f"{prefix}:on_unknown",
                    rule.on_unknown,
                    rule_traces,
                ),
            )
        )
        values.extend(
            PolicyItemDecisionValue(
                f"{prefix}:when:{index}",
                predicate,
                rule_traces,
            )
            for index, predicate in enumerate(rule.when, start=1)
        )
        for requirement in rule.requirements:
            item_path = f"{prefix}:requirement:{requirement.control_key}"
            original_traces = tuple(requirement.trace_refs)
            compared_requirement = requirement.model_copy(
                update={
                    "trace_refs": list(
                        _decision_value_trace_refs(
                            requirement.trace_refs,
                            excluded_decision_id=excluded_decision_id,
                        )
                    )
                }
            )
            values.extend(
                (
                    PolicyItemDecisionValue(
                        item_path,
                        compared_requirement,
                        original_traces,
                    ),
                    PolicyItemDecisionValue(
                        f"{item_path}:failure_effect",
                        requirement.failure_effect,
                        original_traces,
                    ),
                )
            )
        for prohibition in rule.prohibitions:
            item_path = f"{prefix}:prohibition:{prohibition.prohibition_key}"
            original_traces = tuple(prohibition.trace_refs)
            compared_prohibition = prohibition.model_copy(
                update={
                    "trace_refs": list(
                        _decision_value_trace_refs(
                            prohibition.trace_refs,
                            excluded_decision_id=excluded_decision_id,
                        )
                    )
                }
            )
            values.extend(
                (
                    PolicyItemDecisionValue(
                        item_path,
                        compared_prohibition,
                        original_traces,
                    ),
                    PolicyItemDecisionValue(
                        f"{item_path}:on_unknown",
                        prohibition.on_unknown,
                        original_traces,
                    ),
                )
            )
            values.extend(
                PolicyItemDecisionValue(
                    f"{item_path}:when:{index}",
                    predicate,
                    original_traces,
                )
                for index, predicate in enumerate(prohibition.when, start=1)
            )
        values.extend(
            PolicyItemDecisionValue(
                f"{prefix}:route_constraint:{index}",
                constraint.model_copy(
                    update={
                        "trace_refs": list(
                            _decision_value_trace_refs(
                                constraint.trace_refs,
                                excluded_decision_id=excluded_decision_id,
                            )
                        )
                    }
                ),
                tuple(constraint.trace_refs),
            )
            for index, constraint in enumerate(rule.route_constraints, start=1)
        )
        values.extend(
            PolicyItemDecisionValue(
                f"{prefix}:condition:{condition.control_key}",
                condition.model_copy(
                    update={
                        "trace_refs": list(
                            _decision_value_trace_refs(
                                condition.trace_refs,
                                excluded_decision_id=excluded_decision_id,
                            )
                        )
                    }
                ),
                tuple(condition.trace_refs),
            )
            for condition in rule.conditions
        )
        for cap in rule.economic_caps:
            item_path = f"{prefix}:economic_cap:{cap.cap_key}"
            original_traces = tuple(cap.trace_refs)
            compared_cap = cap.model_copy(
                update={
                    "trace_refs": list(
                        _decision_value_trace_refs(
                            cap.trace_refs,
                            excluded_decision_id=excluded_decision_id,
                        )
                    )
                }
            )
            values.extend(
                (
                    PolicyItemDecisionValue(item_path, compared_cap, original_traces),
                    PolicyItemDecisionValue(
                        f"{item_path}:breach_effect",
                        cap.breach_effect,
                        original_traces,
                    ),
                )
            )
    return values


def _schema_v3_policy_item_decision_values(
    policy_module: PolicyModuleV3,
    *,
    excluded_decision_id: UUID | None,
) -> list[PolicyItemDecisionValue]:
    values: list[PolicyItemDecisionValue] = []
    for rule in policy_module.rules:
        if rule.when or rule.prohibitions or rule.economic_caps:
            raise ValueError(
                "schema-v3 decision traversal permits only the closed traced item surface"
            )
        prefix = f"/rules/{rule.rule_key}"
        rule_traces = tuple(rule.trace_refs)
        values.append(
            PolicyItemDecisionValue(
                f"{prefix}/on_unknown",
                rule.on_unknown,
                rule_traces,
            )
        )
        for requirement in rule.requirements:
            item_path = f"{prefix}/requirements/{requirement.control_key}"
            original_traces = tuple(requirement.trace_refs)
            compared_requirement = requirement.model_copy(
                update={
                    "trace_refs": list(
                        _decision_value_trace_refs(
                            requirement.trace_refs,
                            excluded_decision_id=excluded_decision_id,
                        )
                    )
                }
            )
            values.extend(
                (
                    PolicyItemDecisionValue(
                        item_path,
                        compared_requirement,
                        original_traces,
                    ),
                    PolicyItemDecisionValue(
                        f"{item_path}/failure_effect",
                        requirement.failure_effect,
                        original_traces,
                    ),
                )
            )
        for constraint in rule.route_constraints:
            if len(constraint.routes) != 1:
                raise ValueError("schema-v3 route constraints require one exact route")
            route_key = constraint.routes[0].value.lower().replace("_", "-")
            values.append(
                PolicyItemDecisionValue(
                    f"{prefix}/route_constraints/{route_key}-only",
                    constraint.model_copy(
                        update={
                            "trace_refs": list(
                                _decision_value_trace_refs(
                                    constraint.trace_refs,
                                    excluded_decision_id=excluded_decision_id,
                                )
                            )
                        }
                    ),
                    tuple(constraint.trace_refs),
                )
            )
        values.extend(
            PolicyItemDecisionValue(
                f"{prefix}/conditions/{condition.control_key}",
                condition.model_copy(
                    update={
                        "trace_refs": list(
                            _decision_value_trace_refs(
                                condition.trace_refs,
                                excluded_decision_id=excluded_decision_id,
                            )
                        )
                    }
                ),
                tuple(condition.trace_refs),
            )
            for condition in rule.conditions
        )
        values.append(
            PolicyItemDecisionValue(
                f"{prefix}/trace_refs",
                _decision_value_trace_refs(
                    rule.trace_refs,
                    excluded_decision_id=excluded_decision_id,
                ),
                rule_traces,
            )
        )
    return values


def policy_module_decision_item_values(
    policy_module: PolicyModule | PolicyModuleV3,
    *,
    excluded_decision_id: UUID | None = None,
) -> tuple[PolicyItemDecisionValue, ...]:
    """Traverse only the two approved typed module grammars in canonical order."""

    values = (
        _schema_v3_policy_item_decision_values(
            policy_module,
            excluded_decision_id=excluded_decision_id,
        )
        if isinstance(policy_module, PolicyModuleV3)
        else _legacy_policy_item_decision_values(
            policy_module,
            excluded_decision_id=excluded_decision_id,
        )
    )
    ordered = tuple(sorted(values, key=lambda item: item.item_path))
    paths = tuple(item.item_path for item in ordered)
    if len(paths) != len(set(paths)):
        raise ValueError("policy item traversal paths must be unique")
    return ordered


class PolicyItemDecisionSelection(AssuranceModel):
    spec_key: NonEmptyString
    module_key: NonEmptyString
    policy_module: PolicyModule | PolicyModuleV3
    item_paths: Annotated[CanonicalSet[NonEmptyString], Field(min_length=1)]

    @field_validator("item_paths", mode="before")
    @classmethod
    def item_paths_are_unique_before_canonicalization(cls, value: object) -> object:
        if isinstance(value, list) and len(canonical_set(value)) != len(value):
            raise ValueError("policy item decision paths must be unique")
        return value

    @model_validator(mode="after")
    def paths_belong_to_the_typed_module(self) -> PolicyItemDecisionSelection:
        if self.policy_module.module_key != self.module_key:
            raise ValueError("selection module_key must match policy_module.module_key")
        available_paths = {
            item.item_path for item in policy_module_decision_item_values(self.policy_module)
        }
        if not set(self.item_paths) <= available_paths:
            raise ValueError("selection item_paths must come from the closed typed traversal")
        return self


class PolicyItemDecisionSemantics(AssuranceModel):
    decision_type: Literal["POLICY_ITEMS"] = "POLICY_ITEMS"
    selections: Annotated[
        CanonicalSet[PolicyItemDecisionSelection],
        Field(min_length=1),
    ]

    @field_validator("selections", mode="before")
    @classmethod
    def selections_are_unique_before_canonicalization(cls, value: object) -> object:
        if isinstance(value, list) and len(canonical_set(value)) != len(value):
            raise ValueError("policy item decision selections must be unique")
        return value

    @model_validator(mode="after")
    def one_selection_per_spec_module(self) -> PolicyItemDecisionSemantics:
        keys = [(selection.spec_key, selection.module_key) for selection in self.selections]
        if len(keys) != len(set(keys)):
            raise ValueError("policy item decisions permit one selection per spec/module")
        return self


class LineageAssignmentDecisionSemantics(AssuranceModel):
    decision_type: Literal["LINEAGE_ASSIGNMENT"] = "LINEAGE_ASSIGNMENT"
    principal_version_id: UUID
    independence_domain_id: UUID


REVIEW_ADVANCEMENT_TENANT_ID = UUID("10000000-0000-4000-8000-000000000001")
REVIEW_ADVANCEMENT_DECIDED_AT = AuthorityInstant100ns(
    canonical_rfc3339="2026-07-28T21:00:25.4829517Z",
    unix_epoch_100ns_ticks_decimal="0017852724254829517",
)
REVIEW_ADVANCEMENT_VALID_UNTIL = AuthorityInstant100ns(
    canonical_rfc3339="2026-08-04T00:00:00.0000000Z",
    unix_epoch_100ns_ticks_decimal="0017858016000000000",
)
REVIEW_ADVANCEMENT_DECISION_NAMESPACE = uuid5(
    NAMESPACE_URL,
    "urn:riskspec:authority:risk-spec-draft-review-advancement-decision:v1",
)
REVIEW_ADVANCEMENT_PERMIT_NAMESPACE = uuid5(
    NAMESPACE_URL,
    "urn:riskspec:authority:risk-spec-lifecycle-advancement-permit:v1",
)
REVIEW_ADVANCEMENT_GATE_NAMESPACE = uuid5(
    NAMESPACE_URL,
    "urn:riskspec:authority:risk-spec-lifecycle-advancement-verification-gate:v1",
)
REVIEW_ADVANCEMENT_CONSUMPTION_NAMESPACE = uuid5(
    NAMESPACE_URL,
    "urn:riskspec:evidence:risk-spec-lifecycle-advancement-consumption:v1",
)
REVIEW_ADVANCEMENT_VERIFIER_ARTIFACT_NAMESPACE = uuid5(
    NAMESPACE_URL,
    "urn:riskspec:evidence:lifecycle-advancement-verifier-artifact:v1",
)
REVIEW_ADVANCEMENT_VERIFIER_REPORT_NAMESPACE = uuid5(
    NAMESPACE_URL,
    "urn:riskspec:evidence:lifecycle-advancement-verifier-report:v1",
)
REVIEW_ADVANCEMENT_VERIFIER_EVIDENCE_NAMESPACE = uuid5(
    NAMESPACE_URL,
    "urn:riskspec:evidence:lifecycle-advancement-verifier-evidence:v1",
)

REVIEWER_PRINCIPAL_ID = UUID("20000000-0000-4000-8000-000000000004")
REVIEWER_PRINCIPAL_VERSION_ID = UUID("21000000-0000-4000-8000-000000000004")
REVIEWER_PRINCIPAL_VERSION_HASH = (
    "sha256:7d92ae66b69da68c1904bb8dbcfbd600ba50d0577d4e2f4273cbf27690d80e2d"
)
REVIEWER_INDEPENDENCE_DOMAIN_ID = UUID("22000000-0000-4000-8000-000000000004")
REVIEWER_INDEPENDENCE_DOMAIN_KEY = "domain-reviewer"
REVIEWER_LINEAGE_HEAD_ID = UUID("a09ff83b-66c8-5d94-b3a0-572dee7bea9a")
REVIEWER_LINEAGE_HEAD_HASH = (
    "sha256:a3f3ccfefbd046fb46d47bc644af34759986a9bc73e469c85efcb78907bda8c0"
)
REVIEWER_GRANT_ID = UUID("23000000-0000-4000-8000-000000000004")
REVIEWER_GRANT_HASH = "sha256:a964e7ff6ff6f67724401b225c9cd472ac26289d6e7574979dd0b41ed92f5789"
REVIEWER_GRANT_VALID_FROM = datetime(2026, 1, 1, tzinfo=UTC)
REVIEWER_GRANT_VALID_UNTIL = datetime(2030, 1, 1, tzinfo=UTC)
GOVERNING_CORRECTION_DECISION_ID = UUID("79af57a3-f67d-50a8-8958-ebb3d74050bc")
GOVERNING_CORRECTION_DECISION_HASH = (
    "sha256:bdd982bdc7670b6be378e0b1dcc6882ed845c17f5c87cdd639fb0e0bb316b6ed"
)
REVIEW_ADVANCEMENT_DECISION_ID = UUID("ad4b9d2a-cde9-5a45-b87f-75b942dca121")
REVIEW_ADVANCEMENT_DECISION_HASH = (
    "sha256:cefd5958bdfe4d09b48ea3f79b0444fa28776b56d1976763f7b1e5e9ca1fcbe9"
)
ADMINISTRATION_VALID_UNTIL = REVIEW_ADVANCEMENT_VALID_UNTIL
ADMINISTRATION_DECISION_NAMESPACE = uuid5(
    NAMESPACE_URL,
    "urn:riskspec:authority:lifecycle-administration-decision:v1",
)


AdministrationOperation = Literal[
    "RECORD_LIFECYCLE_ADVANCEMENT_VERIFIER_ARTIFACT",
    "RECORD_RISK_SPEC_LIFECYCLE_ADVANCEMENT_VERIFICATION_GATE",
    "ISSUE_RISK_SPEC_LIFECYCLE_ADVANCEMENT_PERMIT",
]


class AdministrationStreamModuleBinding(AssuranceModel):
    business_object: NonEmptyString
    policy_module: NonEmptyString

    @model_validator(mode="after")
    def accepted_pair(self) -> AdministrationStreamModuleBinding:
        expected = {
            (
                "supplier:third-party-base:activate:correction-002",
                "third-party-base",
            ),
            (
                "supplier:restricted-data:activate:correction-002",
                "restricted-data",
            ),
            (
                "supplier:agent-authority:activate:correction-002",
                "agent-authority",
            ),
            ("supplier:economic:activate:correction-002", "economic"),
        }
        if (self.business_object, self.policy_module) not in expected:
            raise ValueError("administration stream/module pair is not accepted")
        return self


class AdministrationActorAssignment(AssuranceModel):
    principal_key: NonEmptyString
    principal: PrincipalIdentity
    principal_version_hash: HashDigest
    independence_domain_key: NonEmptyString
    base_grant_ref: ObjectHashReference
    base_grant_role: AuthorityRole
    base_grant_sequence: Literal[1]
    grant_decision_ref: ObjectHashReference
    lineage_head_ref: ObjectHashReference
    operation: AdministrationOperation

    @model_validator(mode="after")
    def exact_actor_operation_assignment(self) -> AdministrationActorAssignment:
        expected = {
            "RECORD_LIFECYCLE_ADVANCEMENT_VERIFIER_ARTIFACT": (
                "independent-assessor-1",
                "20000000-0000-4000-8000-000000000008",
                "21000000-0000-4000-8000-000000000008",
                "sha256:7eb5fd29b1f2b79773c869a2e8ae670636cc3d1ac3dd3bd22fa19ff893d19b2a",
                "22000000-0000-4000-8000-000000000008",
                "domain-independent-assessor",
                "23000000-0000-4000-8000-000000000008",
                "sha256:426c7764b4ff9c1d151ae50ea81fe2140ad313f26bfc2dd16f459c4e57ac37d4",
                AuthorityRole.INDEPENDENT_ASSESSOR,
                "24000000-0000-4000-8000-000000000008",
                "sha256:e4f8afe0bc55738f7d435749098d6470fcc659419db56ff7c622a5dc0b2d220c",
                "7c46883e-7e71-546e-b8fb-52640ac6555f",
                "sha256:02529065e2e7c15da17752a510a49780f8a4704e97fa2364118a0c2d959fb011",
            ),
            "RECORD_RISK_SPEC_LIFECYCLE_ADVANCEMENT_VERIFICATION_GATE": (
                "policy-approver-1",
                "20000000-0000-4000-8000-000000000002",
                "21000000-0000-4000-8000-000000000002",
                "sha256:39a504bfcf8d555f193430836b3418c51da4a1ad7b23531b47dcb1c4398ac414",
                "22000000-0000-4000-8000-000000000002",
                "domain-policy-approver",
                "23000000-0000-4000-8000-000000000002",
                "sha256:e9ebb5b1c8b815d7b49a1640386b8e60938a095a8c921088db5c01d2e1879d80",
                AuthorityRole.POLICY_APPROVER,
                "24000000-0000-4000-8000-000000000002",
                "sha256:acbca5da8fb2a207e92bcec3aa53509399ed289d54b6878d48b6c6d4f66132ec",
                "8299a80f-8775-501b-b896-62aad0535e9e",
                "sha256:b361b5daca450090b86eb3488dce15546af7e47d474dabaa000edd29fd1feda6",
            ),
            "ISSUE_RISK_SPEC_LIFECYCLE_ADVANCEMENT_PERMIT": (
                "advancement-approver-1",
                "20000000-0000-4000-8000-000000000006",
                "21000000-0000-4000-8000-000000000006",
                "sha256:027135973c798a6c6daa0f41ec8ef8c6495c7215f96aead9060ef8dd1e927d28",
                "22000000-0000-4000-8000-000000000006",
                "domain-advancement-approver",
                "23000000-0000-4000-8000-000000000006",
                "sha256:69987602191fd77c04c25c6a20eb2babee33b95c48e114ca2c5372eaf9107f60",
                AuthorityRole.ADVANCEMENT_APPROVER,
                "24000000-0000-4000-8000-000000000006",
                "sha256:ccb2671b0c241d87ee04026e76be649b6c5210b9ce744b3447a5e89134b391f0",
                "601e31b0-b523-5d37-88c8-b5d726dc5307",
                "sha256:869546bb4a42e0954a46fe8e3b5b172291f5db366504123ef5f739e1cb123c55",
            ),
        }[self.operation]
        actual = (
            self.principal_key,
            str(self.principal.principal_id),
            str(self.principal.principal_version_id),
            self.principal_version_hash,
            str(self.principal.independence_domain_id),
            self.independence_domain_key,
            str(self.base_grant_ref.object_id),
            self.base_grant_ref.object_hash,
            self.base_grant_role,
            str(self.grant_decision_ref.object_id),
            self.grant_decision_ref.object_hash,
            str(self.lineage_head_ref.object_id),
            self.lineage_head_ref.object_hash,
        )
        if (
            self.principal.tenant_id != REVIEW_ADVANCEMENT_TENANT_ID
            or self.principal.principal_type is not PrincipalType.HUMAN
            or self.base_grant_ref.tenant_id != REVIEW_ADVANCEMENT_TENANT_ID
            or self.grant_decision_ref.tenant_id != REVIEW_ADVANCEMENT_TENANT_ID
            or self.lineage_head_ref.tenant_id != REVIEW_ADVANCEMENT_TENANT_ID
            or actual != expected
        ):
            raise ValueError("administration actor assignment is not accepted")
        return self


class LifecycleAdministrationDecisionSemantics(AssuranceModel):
    decision_type: Literal["LIFECYCLE_ADMINISTRATION"] = "LIFECYCLE_ADMINISTRATION"
    response: Literal["approved"]
    valid_until: AuthorityInstant100ns
    review_decision_ref: ObjectHashReference
    governing_decision_ref: ObjectHashReference
    environments: Annotated[
        CanonicalSet[WorkflowEnvironment],
        Field(min_length=2, max_length=2),
    ]
    canonical_action: Literal[CanonicalAction.MODIFY]
    resource_type: Literal[ResourceType.SUPPLIER]
    route: Literal["NONE"]
    behalf_of: Literal["NONE"]
    stream_module_pairs: Annotated[
        CanonicalSet[AdministrationStreamModuleBinding],
        Field(min_length=4, max_length=4),
    ]
    actor_assignments: Annotated[
        CanonicalSet[AdministrationActorAssignment],
        Field(min_length=3, max_length=3),
    ]

    @model_validator(mode="after")
    def exact_admin_001_scope(self) -> LifecycleAdministrationDecisionSemantics:
        expected_pairs = {
            (
                "supplier:third-party-base:activate:correction-002",
                "third-party-base",
            ),
            (
                "supplier:restricted-data:activate:correction-002",
                "restricted-data",
            ),
            (
                "supplier:agent-authority:activate:correction-002",
                "agent-authority",
            ),
            ("supplier:economic:activate:correction-002", "economic"),
        }
        expected_operations = {
            "RECORD_LIFECYCLE_ADVANCEMENT_VERIFIER_ARTIFACT",
            "RECORD_RISK_SPEC_LIFECYCLE_ADVANCEMENT_VERIFICATION_GATE",
            "ISSUE_RISK_SPEC_LIFECYCLE_ADVANCEMENT_PERMIT",
        }
        if (
            self.valid_until != ADMINISTRATION_VALID_UNTIL
            or self.review_decision_ref
            != ObjectHashReference(
                tenant_id=REVIEW_ADVANCEMENT_TENANT_ID,
                object_id=REVIEW_ADVANCEMENT_DECISION_ID,
                object_hash=REVIEW_ADVANCEMENT_DECISION_HASH,
            )
            or self.governing_decision_ref
            != ObjectHashReference(
                tenant_id=REVIEW_ADVANCEMENT_TENANT_ID,
                object_id=GOVERNING_CORRECTION_DECISION_ID,
                object_hash=GOVERNING_CORRECTION_DECISION_HASH,
            )
            or set(self.environments)
            != {WorkflowEnvironment.LOCAL_TEST, WorkflowEnvironment.LOCAL_DEMO}
            or {(item.business_object, item.policy_module) for item in self.stream_module_pairs}
            != expected_pairs
            or {item.operation for item in self.actor_assignments} != expected_operations
            or len(
                {item.principal.independence_domain_id for item in self.actor_assignments}
                | {REVIEWER_INDEPENDENCE_DOMAIN_ID}
            )
            != 4
        ):
            raise ValueError("ADMIN-001 scope is not the exact accepted scope")
        return self


def lifecycle_administration_decision_id(
    *,
    tenant_id: UUID,
    decided_at: AuthorityInstant100ns,
) -> UUID:
    return uuid5(
        ADMINISTRATION_DECISION_NAMESPACE,
        (
            f"{str(tenant_id).lower()}:"
            "md-dw-015a-correction-002-review-001-admin-001:"
            f"{decided_at.canonical_rfc3339}"
        ),
    )


class AdministrationDecisionBinding(AssuranceModel):
    tenant_id: UUID
    admin_decision_ref: ObjectHashReference
    decided_at: AuthorityInstant100ns
    valid_until: AuthorityInstant100ns
    review_decision_ref: ObjectHashReference
    governing_decision_ref: ObjectHashReference
    environments: Annotated[
        CanonicalSet[WorkflowEnvironment],
        Field(min_length=2, max_length=2),
    ]
    canonical_action: Literal[CanonicalAction.MODIFY]
    resource_type: Literal[ResourceType.SUPPLIER]
    route: Literal["NONE"]
    behalf_of: Literal["NONE"]
    stream_module_pairs: Annotated[
        CanonicalSet[AdministrationStreamModuleBinding],
        Field(min_length=4, max_length=4),
    ]
    actor_assignments: Annotated[
        CanonicalSet[AdministrationActorAssignment],
        Field(min_length=3, max_length=3),
    ]

    @model_validator(mode="after")
    def authority_time_is_half_open(self) -> AdministrationDecisionBinding:
        if (
            self.tenant_id != REVIEW_ADVANCEMENT_TENANT_ID
            or self.admin_decision_ref.tenant_id != self.tenant_id
            or self.decided_at.unix_epoch_100ns_ticks_decimal
            >= self.valid_until.unix_epoch_100ns_ticks_decimal
            or self.valid_until != ADMINISTRATION_VALID_UNTIL
        ):
            raise ValueError("administration decision binding is invalid")
        LifecycleAdministrationDecisionSemantics(
            response="approved",
            valid_until=self.valid_until,
            review_decision_ref=self.review_decision_ref,
            governing_decision_ref=self.governing_decision_ref,
            environments=self.environments,
            canonical_action=self.canonical_action,
            resource_type=self.resource_type,
            route=self.route,
            behalf_of=self.behalf_of,
            stream_module_pairs=self.stream_module_pairs,
            actor_assignments=self.actor_assignments,
        )
        return self


@dataclass(frozen=True, slots=True)
class RiskSpecDraftReviewAuthorizationExpectation:
    spec_key: str
    spec_version_id: UUID
    module_key: str
    content_hash: str
    semantic_hash: str
    draft_head_event_id: UUID
    draft_head_event_hash: str
    restriction_id: UUID
    restriction_hash: str
    nonce: UUID


RISK_SPEC_DRAFT_REVIEW_AUTHORIZATION_EXPECTATIONS = {
    item.spec_key: item
    for item in (
        RiskSpecDraftReviewAuthorizationExpectation(
            spec_key="supplier:third-party-base:activate:correction-002",
            spec_version_id=UUID("fa6fe938-e75e-587c-9b52-0a2c4fbc36ef"),
            module_key="third-party-base",
            content_hash=(
                "sha256:945276f0fd84cdea94f280a77d4eec2fc79079ade792f394ca332d124360fc0d"
            ),
            semantic_hash=(
                "sha256:ca7733c8e99a5916e8c430ce3210ef39f27e866753a57ca3547a010877e76b82"
            ),
            draft_head_event_id=UUID("67af30a8-e2a3-5213-8196-a5bd5a0524ba"),
            draft_head_event_hash=(
                "sha256:b36eab885a257fdddd808bc41551bafbcd6115f09e51328456ef4b4e9cb83e5d"
            ),
            restriction_id=UUID("0ccd559b-02f5-5263-97e7-3713b064e38e"),
            restriction_hash=(
                "sha256:b5338482fd3c129114fc90240b2ac4ad03c5251313566a6324dd22ca57bd9c6a"
            ),
            nonce=UUID("4865af5a-f5dd-43e2-95e3-db39d6cb9795"),
        ),
        RiskSpecDraftReviewAuthorizationExpectation(
            spec_key="supplier:restricted-data:activate:correction-002",
            spec_version_id=UUID("14e6bade-3b7b-5f3f-9a6c-d32ab7b0d12e"),
            module_key="restricted-data",
            content_hash=(
                "sha256:bf6f21617faf2b566cd51d8870fd04bd36dc8050b60bc0fc9fe3364a7854ace7"
            ),
            semantic_hash=(
                "sha256:4ffa54610bcb5b73deca73e3d7cfa52017cfe137d47cbf44385c90f614a5be28"
            ),
            draft_head_event_id=UUID("657d398a-ee75-584f-b98e-c1c834917f0b"),
            draft_head_event_hash=(
                "sha256:d45165016df5421b9c60ddefc2fc42a5313dfab692b78ce3496927f57c2514b1"
            ),
            restriction_id=UUID("abf3fc23-2064-5392-bfc9-a7676407e868"),
            restriction_hash=(
                "sha256:51ca3935380fde2017b52a94c12ba40adef6296bc08b4eb2c01f1e0db80627fd"
            ),
            nonce=UUID("7dfc0f00-c1e3-41f5-a00b-93553a16b63e"),
        ),
        RiskSpecDraftReviewAuthorizationExpectation(
            spec_key="supplier:agent-authority:activate:correction-002",
            spec_version_id=UUID("62fe79ba-fff3-59bb-a15f-50d9c877d63d"),
            module_key="agent-authority",
            content_hash=(
                "sha256:26ffcc02c5d93cca486f2bd37e524f5dcdee4cc7a41dece24eb162ee75fd507d"
            ),
            semantic_hash=(
                "sha256:5dcf7af1a0aa53de2cfe6e25f4c7af6f901ead0833a5b69f16fea416265e84ca"
            ),
            draft_head_event_id=UUID("903f0009-f9e1-59a3-a92c-b769ecc7e487"),
            draft_head_event_hash=(
                "sha256:09888a932ff84dea826d2007eb3da0a50e80c89baa720f0ebfc561aa3561b447"
            ),
            restriction_id=UUID("0ba36d38-836a-552b-8628-675155fcd714"),
            restriction_hash=(
                "sha256:5f1442f57bd53a55f72c99faf5f80d801b4378c82040d88bc7f9be4c1ebffb21"
            ),
            nonce=UUID("d6715f3f-fa53-42be-808e-ac3c2fd5a154"),
        ),
        RiskSpecDraftReviewAuthorizationExpectation(
            spec_key="supplier:economic:activate:correction-002",
            spec_version_id=UUID("f47c867f-351c-5c19-b0b3-5e8e505f7cb5"),
            module_key="economic",
            content_hash=(
                "sha256:265890af3fe7a904f8a4c00fe9845517ecf82646532c8e0aaf27f3b9e71f1043"
            ),
            semantic_hash=(
                "sha256:b80a5bf20824246cde588b7b5700eeedbc41194e85d45a00398fecd390e87fc0"
            ),
            draft_head_event_id=UUID("023cc1e8-cebd-5cb7-b90b-df060f3befa0"),
            draft_head_event_hash=(
                "sha256:65debaa0fdb6469d0c65ffda002d14801c843d6b3b885702bc073ed79518cbc5"
            ),
            restriction_id=UUID("d47cbe6e-0220-5111-999a-a21e84008b04"),
            restriction_hash=(
                "sha256:d5f38f02aa437d2b18c396a46e66c8d88b09fe81c1f49145dbbd00760af52784"
            ),
            nonce=UUID("d66029b7-76a8-4b11-a16d-b2b01b9a91c7"),
        ),
    )
}


class LifecycleReviewAuthorityTuple(AssuranceModel):
    domain_verb: Literal[DomainVerb.ACTIVATE_SUPPLIER]
    canonical_action: Literal[CanonicalAction.MODIFY]
    resource_type: Literal[ResourceType.SUPPLIER]
    business_object: NonEmptyString
    policy_module: NonEmptyString
    route: Literal["NONE"]
    operation: Literal["REVIEW"]
    behalf_of_party: Literal["NONE"]


class RiskSpecDraftReviewAuthorizationItem(AssuranceModel):
    spec_key: NonEmptyString
    spec_version_ref: VersionedSpecReference
    draft_head_ref: ObjectHashReference
    restriction_ref: ObjectHashReference
    governing_decision_ref: ObjectHashReference
    from_state: Literal[LifecycleState.DRAFT]
    to_state: Literal[LifecycleState.REVIEWED]
    reviewer: PrincipalIdentity
    reviewer_principal_version_hash: HashDigest
    reviewer_independence_domain_key: Literal["domain-reviewer"]
    reviewer_lineage_head_ref: ObjectHashReference
    reviewer_grant_ref: ObjectHashReference
    reviewer_grant_role: Literal[AuthorityRole.REVIEWER]
    reviewer_grant_sequence: Literal[1]
    reviewer_grant_scope: AuthorityScope
    reviewer_grant_valid_from: UtcTimestamp
    reviewer_grant_valid_until: UtcTimestamp
    authority: LifecycleReviewAuthorityTuple
    valid_from: AuthorityInstant100ns
    valid_until: AuthorityInstant100ns
    nonce: UUID

    @model_validator(mode="after")
    def exact_closed_review_item(self) -> RiskSpecDraftReviewAuthorizationItem:
        expected = RISK_SPEC_DRAFT_REVIEW_AUTHORIZATION_EXPECTATIONS.get(self.spec_key)
        any_scope = {
            "actions": {"kind": "ANY"},
            "resource_types": {"kind": "ANY"},
            "business_objects": {"kind": "ANY"},
            "policy_modules": {"kind": "ANY"},
            "routes": {"kind": "ANY"},
            "operations": {"kind": "ANY"},
            "behalf_of_parties": {"kind": "ANY"},
        }
        if expected is None or (
            self.spec_version_ref.tenant_id,
            self.spec_version_ref.spec_version_id,
            self.spec_version_ref.module_key,
            self.spec_version_ref.version,
            self.spec_version_ref.content_hash,
            self.spec_version_ref.semantic_hash,
            self.draft_head_ref.tenant_id,
            self.draft_head_ref.object_id,
            self.draft_head_ref.object_hash,
            self.restriction_ref.tenant_id,
            self.restriction_ref.object_id,
            self.restriction_ref.object_hash,
            self.governing_decision_ref.tenant_id,
            self.governing_decision_ref.object_id,
            self.governing_decision_ref.object_hash,
            self.reviewer.tenant_id,
            self.reviewer.principal_id,
            self.reviewer.principal_version_id,
            self.reviewer.independence_domain_id,
            self.reviewer.principal_type,
            self.reviewer_principal_version_hash,
            self.reviewer_lineage_head_ref.tenant_id,
            self.reviewer_lineage_head_ref.object_id,
            self.reviewer_lineage_head_ref.object_hash,
            self.reviewer_grant_ref.tenant_id,
            self.reviewer_grant_ref.object_id,
            self.reviewer_grant_ref.object_hash,
            self.reviewer_grant_valid_from,
            self.reviewer_grant_valid_until,
            self.authority.business_object,
            self.authority.policy_module,
            self.valid_from,
            self.valid_until,
            self.nonce,
        ) != (
            REVIEW_ADVANCEMENT_TENANT_ID,
            expected.spec_version_id,
            expected.module_key,
            1,
            expected.content_hash,
            expected.semantic_hash,
            REVIEW_ADVANCEMENT_TENANT_ID,
            expected.draft_head_event_id,
            expected.draft_head_event_hash,
            REVIEW_ADVANCEMENT_TENANT_ID,
            expected.restriction_id,
            expected.restriction_hash,
            REVIEW_ADVANCEMENT_TENANT_ID,
            GOVERNING_CORRECTION_DECISION_ID,
            GOVERNING_CORRECTION_DECISION_HASH,
            REVIEW_ADVANCEMENT_TENANT_ID,
            REVIEWER_PRINCIPAL_ID,
            REVIEWER_PRINCIPAL_VERSION_ID,
            REVIEWER_INDEPENDENCE_DOMAIN_ID,
            PrincipalType.HUMAN,
            REVIEWER_PRINCIPAL_VERSION_HASH,
            REVIEW_ADVANCEMENT_TENANT_ID,
            REVIEWER_LINEAGE_HEAD_ID,
            REVIEWER_LINEAGE_HEAD_HASH,
            REVIEW_ADVANCEMENT_TENANT_ID,
            REVIEWER_GRANT_ID,
            REVIEWER_GRANT_HASH,
            REVIEWER_GRANT_VALID_FROM,
            REVIEWER_GRANT_VALID_UNTIL,
            expected.spec_key,
            expected.module_key,
            REVIEW_ADVANCEMENT_DECIDED_AT,
            REVIEW_ADVANCEMENT_VALID_UNTIL,
            expected.nonce,
        ):
            raise ValueError("review authorization item is not one exact accepted item")
        if self.reviewer_grant_scope.model_dump(mode="json") != any_scope:
            raise ValueError("reviewer grant scope must be the exact current broad scope")
        return self


class RiskSpecDraftReviewAdvancementDecisionSemantics(AssuranceModel):
    decision_type: Literal["RISK_SPEC_DRAFT_REVIEW_ADVANCEMENT"] = (
        "RISK_SPEC_DRAFT_REVIEW_ADVANCEMENT"
    )
    authorization_items: Annotated[
        CanonicalSet[RiskSpecDraftReviewAuthorizationItem],
        Field(min_length=4, max_length=4),
    ]

    @model_validator(mode="after")
    def complete_exact_authorization_set(
        self,
    ) -> RiskSpecDraftReviewAdvancementDecisionSemantics:
        if {item.spec_key for item in self.authorization_items} != set(
            RISK_SPEC_DRAFT_REVIEW_AUTHORIZATION_EXPECTATIONS
        ):
            raise ValueError("review advancement decision requires the exact four items")
        return self


HumanDecisionSemantics = Annotated[
    ActionMappingDecisionSemantics
    | PolicyParameterDecisionSemantics
    | PolicyModuleDecisionSemantics
    | LineageAssignmentDecisionSemantics
    | RiskSpecDraftReviewAdvancementDecisionSemantics
    | LifecycleAdministrationDecisionSemantics,
    Field(discriminator="decision_type"),
]


def risk_spec_review_advancement_decision_id(
    *,
    tenant_id: UUID,
    decided_at: AuthorityInstant100ns,
) -> UUID:
    return uuid5(
        REVIEW_ADVANCEMENT_DECISION_NAMESPACE,
        (
            f"{str(tenant_id).lower()}:"
            "md-dw-015a-correction-002-review-001:"
            f"{decided_at.canonical_rfc3339}"
        ),
    )


class HumanDecision(StoredObject):
    schema_name: Literal["HumanDecision"]
    schema_version: Literal[1, 2]
    judgment_id: NonEmptyString
    proposal: NonEmptyString
    proposer: PrincipalIdentity
    resolver: PrincipalIdentity
    resolver_authority_grant_ref: ObjectHashReference
    decided_at: UtcTimestamp | AuthorityInstant100ns
    chosen_semantics: HumanDecisionSemantics
    scope: AuthorityScope
    source_refs: Annotated[CanonicalSet[ObjectHashReference], Field(min_length=1)]
    classification: Classification
    decision_hash: HashDigest

    @model_validator(mode="after")
    def resolver_is_a_same_tenant_human(self) -> HumanDecision:
        if self.resolver.principal_type is not PrincipalType.HUMAN:
            raise ValueError("human decisions require a HUMAN resolver")
        nested_tenants = {
            self.proposer.tenant_id,
            self.resolver.tenant_id,
            self.resolver_authority_grant_ref.tenant_id,
            *(reference.tenant_id for reference in self.source_refs),
        }
        if nested_tenants != {self.tenant_id}:
            raise ValueError("all human-decision links must be tenant-bound")
        if isinstance(
            self.chosen_semantics,
            RiskSpecDraftReviewAdvancementDecisionSemantics,
        ) and (
            self.schema_version != 2
            or self.tenant_id != REVIEW_ADVANCEMENT_TENANT_ID
            or self.judgment_id != "MD-DW-015A-CORRECTION-002-REVIEW-001"
            or not isinstance(self.decided_at, AuthorityInstant100ns)
            or self.decided_at != REVIEW_ADVANCEMENT_DECIDED_AT
            or self.object_id
            != risk_spec_review_advancement_decision_id(
                tenant_id=self.tenant_id,
                decided_at=self.decided_at,
            )
        ):
            raise ValueError("review advancement decision identity is not the accepted decision")
        if isinstance(
            self.chosen_semantics,
            LifecycleAdministrationDecisionSemantics,
        ) and (
            self.schema_version != 2
            or self.tenant_id != REVIEW_ADVANCEMENT_TENANT_ID
            or self.judgment_id != "MD-DW-015A-CORRECTION-002-REVIEW-001-ADMIN-001"
            or not isinstance(self.decided_at, AuthorityInstant100ns)
            or self.decided_at.unix_epoch_100ns_ticks_decimal
            >= ADMINISTRATION_VALID_UNTIL.unix_epoch_100ns_ticks_decimal
            or self.object_id
            != lifecycle_administration_decision_id(
                tenant_id=self.tenant_id,
                decided_at=self.decided_at,
            )
        ):
            raise ValueError("ADMIN-001 decision identity is not the accepted decision")
        return self


class HumanDecisionV3(HumanDecision):
    """Additive exact policy-item decision; legacy HumanDecision stays unchanged."""

    schema_version: Literal[3]  # type: ignore[assignment]
    chosen_semantics: PolicyItemDecisionSemantics  # type: ignore[assignment]

    @model_validator(mode="after")
    def chosen_snapshot_excludes_its_own_trace(self) -> HumanDecisionV3:
        for selection in self.chosen_semantics.selections:
            for item in policy_module_decision_item_values(selection.policy_module):
                if any(
                    isinstance(trace, HumanDecisionTrace)
                    and trace.decision_id == self.object_id
                    for trace in item.trace_refs
                ):
                    raise ValueError(
                        "policy item decision snapshots cannot contain their own decision trace"
                    )
        return self


HumanDecisionContract = Annotated[
    HumanDecision | HumanDecisionV3,
    Field(discriminator="schema_version"),
]


def policy_item_decision_semantics_match(
    decision: HumanDecisionV3,
    policy_modules: Mapping[
        tuple[str, str],
        PolicyModule | PolicyModuleV3,
    ],
) -> bool:
    """Compare selected snapshots and cited executable values in both directions."""

    selections = {
        (selection.spec_key, selection.module_key): selection
        for selection in decision.chosen_semantics.selections
    }
    if not set(selections) <= set(policy_modules):
        return False

    for key, policy_module in policy_modules.items():
        if policy_module.module_key != key[1]:
            return False
        selection = selections.get(key)
        try:
            actual_items = {
                item.item_path: item
                for item in policy_module_decision_item_values(
                    policy_module,
                    excluded_decision_id=decision.object_id,
                )
            }
        except ValueError:
            return False

        cited_paths: set[str] = set()
        for item in actual_items.values():
            matching_identity = [
                trace
                for trace in item.trace_refs
                if isinstance(trace, HumanDecisionTrace)
                and trace.decision_id == decision.object_id
            ]
            if any(trace.decision_hash != decision.decision_hash for trace in matching_identity):
                return False
            if any(trace.decision_hash == decision.decision_hash for trace in matching_identity):
                cited_paths.add(item.item_path)

        if selection is None:
            if cited_paths:
                return False
            continue

        try:
            selected_items = {
                item.item_path: item
                for item in policy_module_decision_item_values(selection.policy_module)
            }
        except ValueError:
            return False
        selected_paths = set(selection.item_paths)
        if selected_paths != cited_paths:
            return False
        for item_path in selected_paths:
            actual_item = actual_items.get(item_path)
            selected_item = selected_items.get(item_path)
            if (
                actual_item is None
                or selected_item is None
                or actual_item.value != selected_item.value
            ):
                return False
    return True


class RiskSpecProseMetadata(AssuranceModel):
    title: NonEmptyString
    summary: str
    generated_test_keys: CanonicalSet[NonEmptyString]


class RiskSpecVersion(StoredObject):
    schema_name: Literal["RiskSpecVersion"]
    schema_version: SchemaVersion
    spec_key: NonEmptyString
    module_key: NonEmptyString
    version: PositiveInt
    predecessor: VersionedSpecReference | None
    owner_principal_version_id: UUID
    coverage_key: NonEmptyString
    policy_module: PolicyModule
    unresolved_judgment_ids: CanonicalSet[NonEmptyString]
    trace_refs: Annotated[CanonicalSet[TraceRef], Field(min_length=1)]
    dependencies: CanonicalSet[VersionedSpecReference]
    overlays: CanonicalSet[VersionedSpecReference]
    effective_from: UtcTimestamp | None
    effective_until: UtcTimestamp | None
    prose_metadata: RiskSpecProseMetadata
    classification: Classification
    content_hash: HashDigest
    semantic_hash: HashDigest

    @model_validator(mode="after")
    def validate_spec_bindings(self) -> RiskSpecVersion:
        if self.policy_module.module_key != self.module_key:
            raise ValueError("policy_module.module_key must match module_key")
        if (
            self.effective_from is not None
            and self.effective_until is not None
            and self.effective_until <= self.effective_from
        ):
            raise ValueError("effective_until must be after effective_from")
        links = [*self.dependencies, *self.overlays]
        if self.predecessor is not None:
            links.append(self.predecessor)
        if any(link.tenant_id != self.tenant_id for link in links):
            raise ValueError("all RiskSpecVersion links must be tenant-bound")
        return self


class PolicyItemTrace(AssuranceModel):
    """Hash-bound provenance for a precise policy AST item or effect."""

    item_path: NonEmptyString
    trace_refs: Annotated[CanonicalSet[TraceRef], Field(min_length=1)]


class ActivationApprovalInterpretation(AssuranceModel):
    """Closed interpretation of the existing approval engine token."""

    control_key: NonEmptyString
    approval_semantics: Literal["SUPPLIER_ACTIVATION_APPROVAL"]
    approver_principal_key: Literal["activation-approver-1"]
    engine_role: Literal[AuthorityRole.ADVANCEMENT_APPROVER]
    scope_key: Literal["supplier:activate"]
    independent_from: Annotated[
        CanonicalSet[
            Literal[
                "PROPOSER",
                "OPERATOR",
                "EVIDENCE_PRODUCER",
                "EVIDENCE_CERTIFIER",
                "WORKFLOW_OWNER",
                "INTEGRATION_OWNER",
            ]
        ],
        Field(min_length=6, max_length=6),
    ]


class RiskSpecCorrection(RiskSpecVersion):
    """Schema-v2 environment-scoped immutable RiskSpec correction."""

    schema_version: Literal[2]  # type: ignore[assignment]
    environments: Annotated[
        CanonicalSet[WorkflowEnvironment],
        Field(min_length=1),
    ]
    approval_interpretations: CanonicalSet[ActivationApprovalInterpretation]
    item_traces: Annotated[
        CanonicalSet[PolicyItemTrace],
        Field(min_length=1),
    ]
    effective_from: UtcTimestamp
    effective_until: UtcTimestamp

    @model_validator(mode="after")
    def item_trace_paths_are_unique(self) -> RiskSpecCorrection:
        paths = [item.item_path for item in self.item_traces]
        if len(paths) != len(set(paths)):
            raise ValueError("RiskSpecCorrection item trace paths must be unique")
        return self


def _schema_v3_policy_item_paths(policy_module: PolicyModuleV3) -> tuple[str, ...]:
    """Derive the closed schema-v3 trace surface without changing v1/v2 paths."""

    return tuple(
        item.item_path for item in policy_module_decision_item_values(policy_module)
    )


class RiskSpecVersionV3(RiskSpecVersion):
    """Additive RiskSpecVersion form with exact item-level trace closure."""

    schema_version: Literal[3]  # type: ignore[assignment]
    policy_module: PolicyModuleV3  # type: ignore[assignment]
    item_traces: Annotated[
        CanonicalSet[PolicyItemTrace],
        Field(min_length=1),
    ]

    @model_validator(mode="after")
    def schema_v3_item_traces_are_complete(self) -> RiskSpecVersionV3:
        paths = tuple(sorted(item.item_path for item in self.item_traces))
        if len(paths) != len(set(paths)):
            raise ValueError("RiskSpecVersionV3 item trace paths must be unique")
        if paths != _schema_v3_policy_item_paths(self.policy_module):
            raise ValueError("RiskSpecVersionV3 item trace paths must close the executable AST")

        expected_trace_refs = tuple(self.trace_refs)
        expected_types = {trace.trace_type for trace in expected_trace_refs}
        if expected_types != {"SOURCE_FRAGMENT", "HUMAN_DECISION"}:
            raise ValueError("RiskSpecVersionV3 requires source and human-decision traces")
        for item in self.item_traces:
            if tuple(item.trace_refs) != expected_trace_refs:
                raise ValueError("every RiskSpecVersionV3 item must bind the exact spec traces")
        for rule in self.policy_module.rules:
            trace_sets = [
                tuple(rule.trace_refs),
                *(tuple(requirement.trace_refs) for requirement in rule.requirements),
                *(tuple(constraint.trace_refs) for constraint in rule.route_constraints),
                *(tuple(condition.trace_refs) for condition in rule.conditions),
            ]
            if any(trace_refs != expected_trace_refs for trace_refs in trace_sets):
                raise ValueError("every executable schema-v3 policy item must bind exact traces")
        return self


RISK_SPEC_LIFECYCLE_RESTRICTION_NAMESPACE = uuid5(
    NAMESPACE_URL,
    "urn:riskspec:authority:risk-spec-lifecycle-restriction:v1",
)
LifecycleRestrictionKind = Literal["PERMANENT_FREEZE", "EXACT_DECISION_HOLD"]
LifecycleRestrictionReleaseRule = Literal[
    "NEVER",
    "FUTURE_EXACT_HUMAN_DECISION",
]
LifecycleRestrictionReasonCode = Literal[
    "MD-DW-015A-CORRECTION-002_DEFECTIVE_DRAFT_PERMANENT_FREEZE",
    "MD-DW-015A-CORRECTION-002_CORRECTED_DRAFT_EXACT_DECISION_HOLD",
]


@dataclass(frozen=True, slots=True)
class RiskSpecLifecycleRestrictionExpectation:
    tenant_id: UUID
    spec_key: str
    spec_version_id: UUID
    module_key: str
    version: int
    content_hash: str
    semantic_hash: str
    kind: LifecycleRestrictionKind
    release_rule: LifecycleRestrictionReleaseRule
    reason_code: LifecycleRestrictionReasonCode


_CORRECTION_TENANT_ID = UUID("10000000-0000-4000-8000-000000000001")
RISK_SPEC_LIFECYCLE_RESTRICTION_EXPECTATIONS = {
    expectation.spec_key: expectation
    for expectation in (
        RiskSpecLifecycleRestrictionExpectation(
            tenant_id=_CORRECTION_TENANT_ID,
            spec_key="supplier:third-party-base:activate",
            spec_version_id=UUID("f96d6bb2-c6ea-5708-aaa0-b2a5139e1b21"),
            module_key="third-party-base",
            version=1,
            content_hash=(
                "sha256:7712119c0e302e595fdde82e2f45911cc16d24c4b6991debff0242673d36c34c"
            ),
            semantic_hash=(
                "sha256:ae0abc7cf244928f18717e95666467577c785d0be630a75c3a7cb6cf08822c67"
            ),
            kind="PERMANENT_FREEZE",
            release_rule="NEVER",
            reason_code=("MD-DW-015A-CORRECTION-002_DEFECTIVE_DRAFT_PERMANENT_FREEZE"),
        ),
        RiskSpecLifecycleRestrictionExpectation(
            tenant_id=_CORRECTION_TENANT_ID,
            spec_key="supplier:restricted-data:activate",
            spec_version_id=UUID("4147a35f-7ecb-5b13-a0fd-c40a652bc7a0"),
            module_key="restricted-data",
            version=1,
            content_hash=(
                "sha256:a150b270b6676f7640cac092902e99fe5c87e69a017245858b7e5f7f20cbd403"
            ),
            semantic_hash=(
                "sha256:66ab5122e81e583053a701d579ca8f015ebf81baafb1b12b3e50998ec40fdb59"
            ),
            kind="PERMANENT_FREEZE",
            release_rule="NEVER",
            reason_code=("MD-DW-015A-CORRECTION-002_DEFECTIVE_DRAFT_PERMANENT_FREEZE"),
        ),
        RiskSpecLifecycleRestrictionExpectation(
            tenant_id=_CORRECTION_TENANT_ID,
            spec_key="supplier:agent-authority:activate",
            spec_version_id=UUID("5a6aa3cc-4d57-5cc3-bb29-2fdcc08ca52d"),
            module_key="agent-authority",
            version=1,
            content_hash=(
                "sha256:32406c7c50d66416a806845f2f1c72780ad1f7b69c8155b2251f1414e7921724"
            ),
            semantic_hash=(
                "sha256:063625632cc285f70dcc75dd994e35852692c52458e6c108f6b0025aeb7ca724"
            ),
            kind="PERMANENT_FREEZE",
            release_rule="NEVER",
            reason_code=("MD-DW-015A-CORRECTION-002_DEFECTIVE_DRAFT_PERMANENT_FREEZE"),
        ),
        RiskSpecLifecycleRestrictionExpectation(
            tenant_id=_CORRECTION_TENANT_ID,
            spec_key="supplier:economic:activate",
            spec_version_id=UUID("593e81c7-10d1-52ca-b675-0969e73aa3f0"),
            module_key="economic",
            version=1,
            content_hash=(
                "sha256:b3bade986ebaf2e21f3c3d021fc089ee732655dbd35eb4434ad57ebada8ec174"
            ),
            semantic_hash=(
                "sha256:3523873fd94511e5817b0e0420b71d5b3f7477c57f5e6d805a60c06f66d8d974"
            ),
            kind="PERMANENT_FREEZE",
            release_rule="NEVER",
            reason_code=("MD-DW-015A-CORRECTION-002_DEFECTIVE_DRAFT_PERMANENT_FREEZE"),
        ),
        RiskSpecLifecycleRestrictionExpectation(
            tenant_id=_CORRECTION_TENANT_ID,
            spec_key="supplier:third-party-base:activate:correction-002",
            spec_version_id=UUID("fa6fe938-e75e-587c-9b52-0a2c4fbc36ef"),
            module_key="third-party-base",
            version=1,
            content_hash=(
                "sha256:945276f0fd84cdea94f280a77d4eec2fc79079ade792f394ca332d124360fc0d"
            ),
            semantic_hash=(
                "sha256:ca7733c8e99a5916e8c430ce3210ef39f27e866753a57ca3547a010877e76b82"
            ),
            kind="EXACT_DECISION_HOLD",
            release_rule="FUTURE_EXACT_HUMAN_DECISION",
            reason_code=("MD-DW-015A-CORRECTION-002_CORRECTED_DRAFT_EXACT_DECISION_HOLD"),
        ),
        RiskSpecLifecycleRestrictionExpectation(
            tenant_id=_CORRECTION_TENANT_ID,
            spec_key="supplier:restricted-data:activate:correction-002",
            spec_version_id=UUID("14e6bade-3b7b-5f3f-9a6c-d32ab7b0d12e"),
            module_key="restricted-data",
            version=1,
            content_hash=(
                "sha256:bf6f21617faf2b566cd51d8870fd04bd36dc8050b60bc0fc9fe3364a7854ace7"
            ),
            semantic_hash=(
                "sha256:4ffa54610bcb5b73deca73e3d7cfa52017cfe137d47cbf44385c90f614a5be28"
            ),
            kind="EXACT_DECISION_HOLD",
            release_rule="FUTURE_EXACT_HUMAN_DECISION",
            reason_code=("MD-DW-015A-CORRECTION-002_CORRECTED_DRAFT_EXACT_DECISION_HOLD"),
        ),
        RiskSpecLifecycleRestrictionExpectation(
            tenant_id=_CORRECTION_TENANT_ID,
            spec_key="supplier:agent-authority:activate:correction-002",
            spec_version_id=UUID("62fe79ba-fff3-59bb-a15f-50d9c877d63d"),
            module_key="agent-authority",
            version=1,
            content_hash=(
                "sha256:26ffcc02c5d93cca486f2bd37e524f5dcdee4cc7a41dece24eb162ee75fd507d"
            ),
            semantic_hash=(
                "sha256:5dcf7af1a0aa53de2cfe6e25f4c7af6f901ead0833a5b69f16fea416265e84ca"
            ),
            kind="EXACT_DECISION_HOLD",
            release_rule="FUTURE_EXACT_HUMAN_DECISION",
            reason_code=("MD-DW-015A-CORRECTION-002_CORRECTED_DRAFT_EXACT_DECISION_HOLD"),
        ),
        RiskSpecLifecycleRestrictionExpectation(
            tenant_id=_CORRECTION_TENANT_ID,
            spec_key="supplier:economic:activate:correction-002",
            spec_version_id=UUID("f47c867f-351c-5c19-b0b3-5e8e505f7cb5"),
            module_key="economic",
            version=1,
            content_hash=(
                "sha256:265890af3fe7a904f8a4c00fe9845517ecf82646532c8e0aaf27f3b9e71f1043"
            ),
            semantic_hash=(
                "sha256:b80a5bf20824246cde588b7b5700eeedbc41194e85d45a00398fecd390e87fc0"
            ),
            kind="EXACT_DECISION_HOLD",
            release_rule="FUTURE_EXACT_HUMAN_DECISION",
            reason_code=("MD-DW-015A-CORRECTION-002_CORRECTED_DRAFT_EXACT_DECISION_HOLD"),
        ),
    )
}


def risk_spec_lifecycle_restriction_expectation(
    *,
    tenant_id: UUID,
    spec_key: str,
    spec_version_id: UUID,
) -> RiskSpecLifecycleRestrictionExpectation | None:
    expectation = RISK_SPEC_LIFECYCLE_RESTRICTION_EXPECTATIONS.get(spec_key)
    if (
        expectation is None
        or expectation.tenant_id != tenant_id
        or expectation.spec_version_id != spec_version_id
    ):
        return None
    return expectation


def risk_spec_lifecycle_restriction_id(
    *,
    tenant_id: UUID,
    spec_version_id: UUID,
) -> UUID:
    """Derive the immutable tenant/version restriction identity."""

    return uuid5(
        RISK_SPEC_LIFECYCLE_RESTRICTION_NAMESPACE,
        f"{str(tenant_id).lower()}:{str(spec_version_id).lower()}",
    )


class RiskSpecLifecycleRestriction(StoredObject):
    """Append-only lifecycle lock for one exact immutable RiskSpec version."""

    schema_name: Literal["RiskSpecLifecycleRestriction"]
    schema_version: SchemaVersion
    spec_key: NonEmptyString
    spec_version_ref: VersionedSpecReference
    head_event_ref: ObjectHashReference
    governing_decision_ref: ObjectHashReference
    kind: LifecycleRestrictionKind
    release_rule: LifecycleRestrictionReleaseRule
    reason_code: LifecycleRestrictionReasonCode
    restriction_hash: HashDigest

    @model_validator(mode="after")
    def validate_restriction_identity_and_pair(
        self,
    ) -> RiskSpecLifecycleRestriction:
        if {
            self.spec_version_ref.tenant_id,
            self.head_event_ref.tenant_id,
            self.governing_decision_ref.tenant_id,
        } != {self.tenant_id}:
            raise ValueError("all lifecycle restriction references must be tenant-bound")
        if self.object_id != risk_spec_lifecycle_restriction_id(
            tenant_id=self.tenant_id,
            spec_version_id=self.spec_version_ref.spec_version_id,
        ):
            raise ValueError("lifecycle restriction identifier is not deterministic")
        expected = {
            "PERMANENT_FREEZE": (
                "NEVER",
                "MD-DW-015A-CORRECTION-002_DEFECTIVE_DRAFT_PERMANENT_FREEZE",
            ),
            "EXACT_DECISION_HOLD": (
                "FUTURE_EXACT_HUMAN_DECISION",
                "MD-DW-015A-CORRECTION-002_CORRECTED_DRAFT_EXACT_DECISION_HOLD",
            ),
        }
        if (self.release_rule, self.reason_code) != expected[self.kind]:
            raise ValueError("lifecycle restriction kind/release/reason pair is invalid")
        stream_expectation = risk_spec_lifecycle_restriction_expectation(
            tenant_id=self.tenant_id,
            spec_key=self.spec_key,
            spec_version_id=self.spec_version_ref.spec_version_id,
        )
        if stream_expectation is None or (
            self.spec_version_ref.module_key,
            self.spec_version_ref.version,
            self.spec_version_ref.content_hash,
            self.spec_version_ref.semantic_hash,
            self.kind,
            self.release_rule,
            self.reason_code,
        ) != (
            stream_expectation.module_key,
            stream_expectation.version,
            stream_expectation.content_hash,
            stream_expectation.semantic_hash,
            stream_expectation.kind,
            stream_expectation.release_rule,
            stream_expectation.reason_code,
        ):
            raise ValueError("lifecycle restriction does not match an exact closed stream")
        return self


PHASE_A_PRODUCTION_ARTIFACT_PATHS = (
    "backend/migrations/versions/0009_risk_spec_lifecycle_advancement_permits.py",
    "backend/migrations/versions/0010_lifecycle_advancement_trust_boundaries.py",
    "backend/migrations/versions/0011_admin_001_disposable_administration.py",
    "backend/src/assurance/api/app.py",
    "backend/src/assurance/api/models.py",
    "backend/src/assurance/api/postgres_state.py",
    "backend/src/assurance/api/state.py",
    "backend/src/assurance/api/workflows.py",
    "backend/src/assurance/contracts/common.py",
    "backend/src/assurance/contracts/export.py",
    "backend/src/assurance/contracts/objects.py",
    "backend/src/assurance/identity/models.py",
    "backend/src/assurance/identity/service.py",
    "backend/src/assurance/ledger/replay.py",
    "backend/src/assurance/lifecycle/interfaces.py",
    "backend/src/assurance/lifecycle/memory.py",
    "backend/src/assurance/lifecycle/models.py",
    "backend/src/assurance/lifecycle/service.py",
    "backend/src/assurance/persistence/durable.py",
    "backend/src/assurance/persistence/models.py",
    "backend/src/assurance/persistence/postgres_adapters.py",
    "backend/src/assurance/persistence/session.py",
    "backend/src/assurance/runtime/evaluator.py",
    "backend/src/assurance/verification/__init__.py",
    "backend/src/assurance/verification/independent_verifier.py",
    "backend/src/assurance/verification/manifest_observer.py",
    "backend/src/assurance/verification/signatures.py",
    "backend/pyproject.toml",
    "backend/uv.lock",
    "backend/tests/api/test_postgres_public_api.py",
    "backend/tests/verification/test_independent_verifier.py",
    "backend/tests/verification/test_manifest_observer.py",
    "scripts/provision_fixtures.py",
)
PHASE_A_GENERATED_ARTIFACT_PATHS = (
    "changes/0001-assurance-runtime-vertical-slice/evidence/t10-openapi.json",
    "contracts/jsonschema/HumanDecision.schema.json",
    "contracts/jsonschema/LifecycleAdvancementVerifierArtifact.schema.json",
    ("contracts/jsonschema/RiskSpecLifecycleAdvancementConsumption.schema.json"),
    "contracts/jsonschema/RiskSpecLifecycleAdvancementPermit.schema.json",
    ("contracts/jsonschema/RiskSpecLifecycleAdvancementVerificationGate.schema.json"),
    "contracts/openapi-components.json",
    "contracts/schema-inventory.json",
    "frontend/src/api/schema.ts",
)
PHASE_A_COMPLETE_ARTIFACT_PATHS = frozenset(
    (*PHASE_A_PRODUCTION_ARTIFACT_PATHS, *PHASE_A_GENERATED_ARTIFACT_PATHS)
)
PHASE_A_ALEMBIC_REVISION = "0011_admin_001_disposable_administration"


class ImplementationArtifactDigest(AssuranceModel):
    path: NonEmptyString
    digest: HashDigest


LIFECYCLE_ADMINISTRATION_REALM_NAMESPACE = uuid5(
    NAMESPACE_URL,
    "urn:riskspec:authority:lifecycle-administration-execution-realm:v1",
)
LIFECYCLE_MANIFEST_OBSERVATION_NAMESPACE = uuid5(
    NAMESPACE_URL,
    "urn:riskspec:evidence:lifecycle-filesystem-manifest-observation:v1",
)


def lifecycle_administration_execution_realm_id(
    *,
    tenant_id: UUID,
    store_instance_id: UUID,
    admin_decision_id: UUID,
) -> UUID:
    return uuid5(
        LIFECYCLE_ADMINISTRATION_REALM_NAMESPACE,
        (
            f"{str(tenant_id).lower()}:"
            f"{str(store_instance_id).lower()}:"
            f"{str(admin_decision_id).lower()}"
        ),
    )


class LifecycleAdministrationExecutionRealm(StoredObject):
    schema_name: Literal["LifecycleAdministrationExecutionRealm"]
    schema_version: SchemaVersion
    store_instance_id: UUID
    mode: Literal["DISPOSABLE_PHASE_A"]
    retained_authority_enabled: Literal[False]
    allowed_environments: Annotated[
        CanonicalSet[WorkflowEnvironment],
        Field(min_length=2, max_length=2),
    ]
    store_attestation_hash: HashDigest
    admin_decision_ref: ObjectHashReference
    realm_hash: HashDigest

    @model_validator(mode="after")
    def exact_disposable_realm(self) -> LifecycleAdministrationExecutionRealm:
        if (
            self.tenant_id != REVIEW_ADVANCEMENT_TENANT_ID
            or self.admin_decision_ref.tenant_id != self.tenant_id
            or set(self.allowed_environments)
            != {WorkflowEnvironment.LOCAL_TEST, WorkflowEnvironment.LOCAL_DEMO}
            or self.object_id
            != lifecycle_administration_execution_realm_id(
                tenant_id=self.tenant_id,
                store_instance_id=self.store_instance_id,
                admin_decision_id=self.admin_decision_ref.object_id,
            )
        ):
            raise ValueError("lifecycle administration realm is not disposable")
        return self


class LifecycleManifestObservedArtifact(AssuranceModel):
    path: NonEmptyString
    byte_length: NonNegativeInt
    digest: HashDigest


def lifecycle_manifest_observation_id(
    *,
    tenant_id: UUID,
    store_instance_id: UUID,
    manifest_hash: str,
    snapshot_content_id: str,
    observed_at: AuthorityInstant100ns,
    observation_nonce: UUID,
) -> UUID:
    return uuid5(
        LIFECYCLE_MANIFEST_OBSERVATION_NAMESPACE,
        (
            f"{str(tenant_id).lower()}:"
            f"{str(store_instance_id).lower()}:"
            f"{manifest_hash}:"
            f"{snapshot_content_id}:"
            f"{observed_at.canonical_rfc3339}:"
            f"{str(observation_nonce).lower()}"
        ),
    )


class LifecycleFilesystemManifestObservation(StoredObject):
    schema_name: Literal["LifecycleFilesystemManifestObservation"]
    schema_version: SchemaVersion
    store_instance_id: UUID
    realm_ref: ObjectHashReference
    admin_decision_ref: ObjectHashReference
    review_decision_ref: ObjectHashReference
    observation_nonce: UUID
    snapshot_format: Literal["RISKSPEC_CANONICAL_SNAPSHOT_V1"]
    snapshot_content_id: HashDigest
    observed_artifacts: Annotated[
        CanonicalSet[LifecycleManifestObservedArtifact],
        Field(
            min_length=len(PHASE_A_COMPLETE_ARTIFACT_PATHS),
            max_length=len(PHASE_A_COMPLETE_ARTIFACT_PATHS),
        ),
    ]
    alembic_revision: Literal["0011_admin_001_disposable_administration"]
    observer_tool_id: Literal["riskspec-manifest-observer"]
    observer_tool_version: Literal["2"]
    observed_at: AuthorityInstant100ns
    manifest_hash: HashDigest
    observation_hash: HashDigest

    @model_validator(mode="after")
    def exact_closed_observation(self) -> LifecycleFilesystemManifestObservation:
        paths = [item.path for item in self.observed_artifacts]
        expected_manifest_hash = lifecycle_advancement_artifact_manifest_hash(
            tenant_id=self.tenant_id,
            artifacts=[
                ImplementationArtifactDigest(path=item.path, digest=item.digest)
                for item in self.observed_artifacts
            ],
            alembic_revision=self.alembic_revision,
        )
        if (
            self.tenant_id != REVIEW_ADVANCEMENT_TENANT_ID
            or any(
                reference.tenant_id != self.tenant_id
                for reference in (
                    self.realm_ref,
                    self.admin_decision_ref,
                    self.review_decision_ref,
                )
            )
            or self.review_decision_ref
            != ObjectHashReference(
                tenant_id=self.tenant_id,
                object_id=REVIEW_ADVANCEMENT_DECISION_ID,
                object_hash=REVIEW_ADVANCEMENT_DECISION_HASH,
            )
            or len(paths) != len(set(paths))
            or set(paths) != PHASE_A_COMPLETE_ARTIFACT_PATHS
            or any(item.byte_length <= 0 for item in self.observed_artifacts)
            or self.manifest_hash != expected_manifest_hash
            or self.object_id
            != lifecycle_manifest_observation_id(
                tenant_id=self.tenant_id,
                store_instance_id=self.store_instance_id,
                manifest_hash=self.manifest_hash,
                snapshot_content_id=self.snapshot_content_id,
                observed_at=self.observed_at,
                observation_nonce=self.observation_nonce,
            )
        ):
            raise ValueError("filesystem manifest observation is not exact")
        return self


class SignedLifecycleFilesystemManifestObservation(AssuranceModel):
    observation: LifecycleFilesystemManifestObservation
    snapshot_archive_base64: NonEmptyString
    purpose: Literal["LIFECYCLE_VERIFICATION_OBSERVER"]
    key_id: NonEmptyString
    key_version: PositiveInt
    public_key_fingerprint: HashDigest
    payload_hash: HashDigest
    signature_base64: NonEmptyString

    @model_validator(mode="after")
    def exact_snapshot_archive(
        self,
    ) -> SignedLifecycleFilesystemManifestObservation:
        try:
            snapshot_archive = base64.b64decode(
                self.snapshot_archive_base64,
                validate=True,
            )
        except (binascii.Error, ValueError) as error:
            raise ValueError("snapshot archive encoding is invalid") from error
        snapshot_hash = f"sha256:{hashlib.sha256(snapshot_archive).hexdigest()}"
        if not snapshot_archive or snapshot_hash != self.observation.snapshot_content_id:
            raise ValueError("snapshot archive identity is invalid")
        return self


def lifecycle_advancement_artifact_manifest_hash(
    *,
    tenant_id: UUID,
    artifacts: list[ImplementationArtifactDigest],
    alembic_revision: str,
) -> str:
    return canonical_hash(
        schema="RiskSpecLifecycleAdvancementArtifactManifest",
        schema_version=1,
        tenant_id=tenant_id,
        payload={
            "alembic_revision": alembic_revision,
            "artifacts": canonical_set(artifacts),
        },
    )


class LifecycleAdvancementArtifactManifest(AssuranceModel):
    alembic_revision: Literal["0011_admin_001_disposable_administration"]
    artifacts: Annotated[
        CanonicalSet[ImplementationArtifactDigest],
        Field(
            min_length=len(PHASE_A_COMPLETE_ARTIFACT_PATHS),
            max_length=len(PHASE_A_COMPLETE_ARTIFACT_PATHS),
        ),
    ]
    manifest_hash: HashDigest

    @model_validator(mode="after")
    def complete_sorted_manifest(self) -> LifecycleAdvancementArtifactManifest:
        paths = [item.path for item in self.artifacts]
        if len(paths) != len(set(paths)) or set(paths) != PHASE_A_COMPLETE_ARTIFACT_PATHS:
            raise ValueError("artifact manifest must contain the complete exact path set")
        return self


class LifecyclePrincipalLineageBinding(AssuranceModel):
    binding_role: Literal[
        "BUILDER",
        "SPEC_CREATOR",
        "DRAFT_HEAD_ACTOR",
        "GOVERNING_DECISION_PROPOSER",
        "GOVERNING_DECISION_RESOLVER",
        "REVIEW_DECISION_PROPOSER",
        "REVIEW_DECISION_RESOLVER",
        "REVIEWER",
        "ASSESSOR",
        "PERMIT_ISSUER",
    ]
    principal: PrincipalIdentity
    principal_version_hash: HashDigest
    independence_domain_key: NonEmptyString
    lineage_head_ref: ObjectHashReference

    @model_validator(mode="after")
    def tenant_bound_lineage(self) -> LifecyclePrincipalLineageBinding:
        if self.principal.tenant_id != self.lineage_head_ref.tenant_id:
            raise ValueError("principal lineage binding must be tenant-bound")
        return self


class LifecycleAssessmentGrantBinding(AssuranceModel):
    grant_ref: ObjectHashReference
    role: Literal[AuthorityRole.INDEPENDENT_ASSESSOR]
    scope: AuthorityScope
    sequence: PositiveInt
    valid_from: UtcTimestamp
    valid_until: UtcTimestamp

    @model_validator(mode="after")
    def valid_interval(self) -> LifecycleAssessmentGrantBinding:
        if self.valid_until <= self.valid_from:
            raise ValueError("assessment grant validity must be half-open")
        return self


class LifecycleVerifierAssessmentBinding(AssuranceModel):
    verifier_report_ref: ObjectHashReference
    verifier_evidence_ref: ObjectHashReference
    verdict: Literal["PASS"]
    assessed_at: AuthorityInstant100ns
    valid_from: AuthorityInstant100ns
    valid_until: AuthorityInstant100ns

    @model_validator(mode="after")
    def valid_assessment_interval(self) -> LifecycleVerifierAssessmentBinding:
        if not (
            self.valid_from.unix_epoch_100ns_ticks_decimal
            <= self.assessed_at.unix_epoch_100ns_ticks_decimal
            < self.valid_until.unix_epoch_100ns_ticks_decimal
        ):
            raise ValueError("assessment time must be inside its half-open validity")
        return self


class LifecycleSeparationResult(AssuranceModel):
    subject_bindings: Annotated[
        CanonicalSet[LifecyclePrincipalLineageBinding],
        Field(min_length=7),
    ]
    assessor_independent_from: CanonicalSet[
        Literal[
            "BUILDER",
            "GOVERNING_DECISION_PROPOSER",
            "GOVERNING_DECISION_RESOLVER",
            "REVIEW_DECISION_PROPOSER",
            "REVIEW_DECISION_RESOLVER",
        ]
    ]
    reviewer_independent_from: CanonicalSet[
        Literal[
            "BUILDER",
            "GOVERNING_DECISION_PROPOSER",
            "GOVERNING_DECISION_RESOLVER",
            "REVIEW_DECISION_PROPOSER",
            "REVIEW_DECISION_RESOLVER",
            "ASSESSOR",
        ]
    ]
    passed: Literal[True]

    @model_validator(mode="after")
    def complete_separation_result(self) -> LifecycleSeparationResult:
        roles = [item.binding_role for item in self.subject_bindings]
        required = {
            "BUILDER",
            "GOVERNING_DECISION_PROPOSER",
            "GOVERNING_DECISION_RESOLVER",
            "REVIEW_DECISION_PROPOSER",
            "REVIEW_DECISION_RESOLVER",
            "REVIEWER",
            "ASSESSOR",
        }
        if len(roles) != len(set(roles)) or not required <= set(roles):
            raise ValueError("separation result is missing a protected role")
        if set(self.assessor_independent_from) != required - {
            "REVIEWER",
            "ASSESSOR",
        }:
            raise ValueError("assessor separation set is incomplete")
        if set(self.reviewer_independent_from) != (required - {"REVIEWER"}):
            raise ValueError("reviewer separation set is incomplete")
        return self


LIFECYCLE_ADVANCEMENT_VERIFIER_CRITERIA = frozenset(
    {
        "AC-DW-API-006",
        "AC-DW-DB-006",
        "AC-DW-DB-007",
        "AC-DW-DB-008",
        "AC-DW-DOM-005",
        "AC-DW-GAT-007",
        "AC-DW-IDN-006",
        "AC-DW-IDN-007",
        "AC-DW-LCY-011",
        "AC-DW-LCY-012",
        "AC-DW-QA-004",
        "AC-DW-QA-005",
    }
)
CanonicalHexBytes = Annotated[
    str,
    StringConstraints(pattern=r"^(?:[0-9a-f]{2})+$", strict=True),
]


class LifecycleVerifierEvidenceEntry(AssuranceModel):
    path: NonEmptyString
    byte_length: NonNegativeInt
    digest: HashDigest


def lifecycle_advancement_verifier_content_id(
    *,
    namespace: UUID,
    tenant_id: UUID,
    content_hash: str,
) -> UUID:
    return uuid5(
        namespace,
        f"{str(tenant_id).lower()}:{content_hash}",
    )


def lifecycle_advancement_verifier_artifact_id(
    *,
    tenant_id: UUID,
    review_decision_id: UUID,
    implementation_manifest_hash: str,
    report_content_hash: str,
    evidence_bundle_hash: str,
    assessor_principal_version_id: UUID,
    assessed_at: AuthorityInstant100ns,
) -> UUID:
    return uuid5(
        REVIEW_ADVANCEMENT_VERIFIER_ARTIFACT_NAMESPACE,
        (
            f"{str(tenant_id).lower()}:"
            f"{str(review_decision_id).lower()}:"
            f"{implementation_manifest_hash}:"
            f"{report_content_hash}:"
            f"{evidence_bundle_hash}:"
            f"{str(assessor_principal_version_id).lower()}:"
            f"{assessed_at.canonical_rfc3339}"
        ),
    )


class LifecycleAdvancementVerifierArtifact(StoredObject):
    schema_name: Literal["LifecycleAdvancementVerifierArtifact"]
    schema_version: SchemaVersion
    artifact_kind: Literal["INDEPENDENT_VERIFICATION_PASS"]
    administration: AdministrationDecisionBinding
    store_instance_id: UUID
    execution_realm_ref: ObjectHashReference
    administration_authority: AdministrationActorAssignment
    manifest_observation_ref: ObjectHashReference
    snapshot_content_id: HashDigest
    review_decision_ref: ObjectHashReference
    review_decided_at: AuthorityInstant100ns
    implementation_manifest: LifecycleAdvancementArtifactManifest
    verifier_report_ref: ObjectHashReference
    verifier_report_canonical_bytes_hex: CanonicalHexBytes
    verifier_evidence_ref: ObjectHashReference
    verifier_evidence_canonical_bytes_hex: CanonicalHexBytes
    evidence_entries: Annotated[
        CanonicalSet[LifecycleVerifierEvidenceEntry],
        Field(min_length=1),
    ]
    verdict: Literal["PASS"]
    criterion_ids: Annotated[CanonicalSet[NonEmptyString], Field(min_length=12, max_length=12)]
    verifier_tool_id: NonEmptyString
    verifier_tool_version: NonEmptyString
    assessed_at: AuthorityInstant100ns
    valid_from: AuthorityInstant100ns
    valid_until: AuthorityInstant100ns
    assessor: LifecyclePrincipalLineageBinding
    assessment_grant: LifecycleAssessmentGrantBinding
    separation: LifecycleSeparationResult
    artifact_hash: HashDigest

    @model_validator(mode="after")
    def exact_retained_verifier_provenance(
        self,
    ) -> LifecycleAdvancementVerifierArtifact:
        report_bytes = bytes.fromhex(self.verifier_report_canonical_bytes_hex)
        evidence_bytes = bytes.fromhex(self.verifier_evidence_canonical_bytes_hex)
        try:
            report_document = json.loads(report_bytes)
            evidence_document = json.loads(evidence_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("verifier content must be canonical UTF-8 JSON") from error
        if (
            canonical_json(report_document) != report_bytes
            or canonical_json(evidence_document) != evidence_bytes
        ):
            raise ValueError("verifier content bytes are not canonical JSON")
        report_hash = sha256_digest(report_bytes)
        evidence_hash = sha256_digest(evidence_bytes)
        expected_report_id = lifecycle_advancement_verifier_content_id(
            namespace=REVIEW_ADVANCEMENT_VERIFIER_REPORT_NAMESPACE,
            tenant_id=self.tenant_id,
            content_hash=report_hash,
        )
        expected_evidence_id = lifecycle_advancement_verifier_content_id(
            namespace=REVIEW_ADVANCEMENT_VERIFIER_EVIDENCE_NAMESPACE,
            tenant_id=self.tenant_id,
            content_hash=evidence_hash,
        )
        if (
            self.tenant_id != REVIEW_ADVANCEMENT_TENANT_ID
            or self.administration.tenant_id != self.tenant_id
            or self.execution_realm_ref.tenant_id != self.tenant_id
            or self.manifest_observation_ref.tenant_id != self.tenant_id
            or self.administration_authority.operation
            != "RECORD_LIFECYCLE_ADVANCEMENT_VERIFIER_ARTIFACT"
            or self.administration_authority not in self.administration.actor_assignments
            or self.review_decided_at != REVIEW_ADVANCEMENT_DECIDED_AT
            or self.review_decision_ref.tenant_id != self.tenant_id
            or self.verifier_report_ref
            != ObjectHashReference(
                tenant_id=self.tenant_id,
                object_id=expected_report_id,
                object_hash=report_hash,
            )
            or self.verifier_evidence_ref
            != ObjectHashReference(
                tenant_id=self.tenant_id,
                object_id=expected_evidence_id,
                object_hash=evidence_hash,
            )
            or set(self.criterion_ids) != LIFECYCLE_ADVANCEMENT_VERIFIER_CRITERIA
            or self.assessor.binding_role != "ASSESSOR"
            or self.valid_from != REVIEW_ADVANCEMENT_DECIDED_AT
            or self.valid_until != REVIEW_ADVANCEMENT_VALID_UNTIL
            or not (
                self.valid_from.unix_epoch_100ns_ticks_decimal
                <= self.assessed_at.unix_epoch_100ns_ticks_decimal
                < self.valid_until.unix_epoch_100ns_ticks_decimal
            )
        ):
            raise ValueError("verifier artifact bindings are invalid")
        if not isinstance(report_document, dict):
            raise ValueError("verifier execution report must be an object")
        criterion_results = report_document.get("criterion_results")
        report_expected_fields = {
            "assessed_at",
            "assessor_principal_version_id",
            "criterion_results",
            "manifest_observation_hash",
            "manifest_observation_id",
            "result",
            "schema_name",
            "schema_version",
            "snapshot_content_id",
            "verifier_tool_id",
            "verifier_tool_version",
        }
        criterion_map_is_exact = (
            isinstance(criterion_results, list)
            and len(criterion_results) == 12
            and {item.get("criterion_id") for item in criterion_results if isinstance(item, dict)}
            == LIFECYCLE_ADVANCEMENT_VERIFIER_CRITERIA
            and all(
                isinstance(item, dict)
                and set(item)
                == {
                    "code_paths",
                    "criterion_id",
                    "evidence_refs",
                    "observed_result",
                    "test_ids",
                }
                and item["observed_result"] == "PASS"
                and all(
                    isinstance(item[field], list) and bool(item[field])
                    for field in ("code_paths", "test_ids", "evidence_refs")
                )
                for item in criterion_results
            )
        )
        report_is_exact = (
            set(report_document) == report_expected_fields
            and report_document["schema_name"] == "IndependentVerificationExecution"
            and report_document["schema_version"] == 1
            and report_document["snapshot_content_id"] == self.snapshot_content_id
            and report_document["manifest_observation_id"]
            == str(self.manifest_observation_ref.object_id)
            and report_document["manifest_observation_hash"]
            == self.manifest_observation_ref.object_hash
            and report_document["assessed_at"] == self.assessed_at.model_dump(mode="json")
            and report_document["assessor_principal_version_id"]
            == str(self.assessor.principal.principal_version_id)
            and report_document["result"] == self.verdict
            and report_document["verifier_tool_id"] == self.verifier_tool_id
            and report_document["verifier_tool_version"] == self.verifier_tool_version
            and criterion_map_is_exact
        )
        evidence_expected = {
            "entries": [entry.model_dump(mode="json") for entry in self.evidence_entries]
        }
        if not report_is_exact or evidence_document != evidence_expected:
            raise ValueError("verifier content authorship or evidence index is invalid")
        expected_id = lifecycle_advancement_verifier_artifact_id(
            tenant_id=self.tenant_id,
            review_decision_id=self.review_decision_ref.object_id,
            implementation_manifest_hash=self.implementation_manifest.manifest_hash,
            report_content_hash=report_hash,
            evidence_bundle_hash=evidence_hash,
            assessor_principal_version_id=(self.assessor.principal.principal_version_id),
            assessed_at=self.assessed_at,
        )
        if self.object_id != expected_id:
            raise ValueError("verifier artifact identifier is not deterministic")
        return self


def risk_spec_lifecycle_advancement_verification_gate_id(
    *,
    tenant_id: UUID,
    review_decision_id: UUID,
    artifact_manifest_hash: str,
    verifier_artifact_hash: str,
    assessed_at: AuthorityInstant100ns,
) -> UUID:
    return uuid5(
        REVIEW_ADVANCEMENT_GATE_NAMESPACE,
        (
            f"{str(tenant_id).lower()}:"
            f"{str(review_decision_id).lower()}:"
            f"{artifact_manifest_hash}:"
            f"{verifier_artifact_hash}:"
            f"{assessed_at.canonical_rfc3339}"
        ),
    )


class RiskSpecLifecycleAdvancementVerificationGate(StoredObject):
    schema_name: Literal["RiskSpecLifecycleAdvancementVerificationGate"]
    schema_version: SchemaVersion
    administration: AdministrationDecisionBinding
    store_instance_id: UUID
    execution_realm_ref: ObjectHashReference
    administration_authority: AdministrationActorAssignment
    review_decision_ref: ObjectHashReference
    review_decided_at: AuthorityInstant100ns
    verifier_artifact_ref: ObjectHashReference
    artifact_manifest: LifecycleAdvancementArtifactManifest
    verifier_assessment: LifecycleVerifierAssessmentBinding
    assessor: LifecyclePrincipalLineageBinding
    assessment_grant: LifecycleAssessmentGrantBinding
    separation: LifecycleSeparationResult
    valid_from: AuthorityInstant100ns
    valid_until: AuthorityInstant100ns
    gate_hash: HashDigest

    @model_validator(mode="after")
    def exact_gate_identity_and_links(
        self,
    ) -> RiskSpecLifecycleAdvancementVerificationGate:
        refs = (
            self.review_decision_ref,
            self.administration.admin_decision_ref,
            self.execution_realm_ref,
            self.verifier_artifact_ref,
            self.verifier_assessment.verifier_report_ref,
            self.verifier_assessment.verifier_evidence_ref,
            self.assessor.lineage_head_ref,
            self.assessment_grant.grant_ref,
            *(binding.lineage_head_ref for binding in self.separation.subject_bindings),
        )
        if (
            self.tenant_id != REVIEW_ADVANCEMENT_TENANT_ID
            or any(reference.tenant_id != self.tenant_id for reference in refs)
            or self.administration.tenant_id != self.tenant_id
            or self.administration_authority.operation
            != "RECORD_RISK_SPEC_LIFECYCLE_ADVANCEMENT_VERIFICATION_GATE"
            or self.administration_authority not in self.administration.actor_assignments
            or self.review_decided_at != REVIEW_ADVANCEMENT_DECIDED_AT
            or self.assessor.binding_role != "ASSESSOR"
            or self.valid_from != self.verifier_assessment.valid_from
            or self.valid_until != self.verifier_assessment.valid_until
        ):
            raise ValueError("verification gate bindings are invalid")
        expected_manifest_hash = lifecycle_advancement_artifact_manifest_hash(
            tenant_id=self.tenant_id,
            artifacts=self.artifact_manifest.artifacts,
            alembic_revision=self.artifact_manifest.alembic_revision,
        )
        if self.artifact_manifest.manifest_hash != expected_manifest_hash:
            raise ValueError("verification gate artifact manifest hash is invalid")
        expected_id = risk_spec_lifecycle_advancement_verification_gate_id(
            tenant_id=self.tenant_id,
            review_decision_id=self.review_decision_ref.object_id,
            artifact_manifest_hash=self.artifact_manifest.manifest_hash,
            verifier_artifact_hash=self.verifier_artifact_ref.object_hash,
            assessed_at=self.verifier_assessment.assessed_at,
        )
        if self.object_id != expected_id:
            raise ValueError("verification gate identifier is not deterministic")
        return self


PermitProtectedBindingRole = Literal[
    "SPEC_CREATOR",
    "DRAFT_HEAD_ACTOR",
    "GOVERNING_DECISION_PROPOSER",
    "GOVERNING_DECISION_RESOLVER",
    "REVIEW_DECISION_PROPOSER",
    "REVIEW_DECISION_RESOLVER",
    "PERMIT_ISSUER",
]


def risk_spec_lifecycle_advancement_permit_id(
    *,
    review_decision_id: UUID,
    spec_version_id: UUID,
    draft_head_event_id: UUID,
    nonce: UUID,
) -> UUID:
    return uuid5(
        REVIEW_ADVANCEMENT_PERMIT_NAMESPACE,
        (
            f"{str(review_decision_id).lower()}:"
            f"{str(spec_version_id).lower()}:"
            f"{str(draft_head_event_id).lower()}:"
            f"{str(nonce).lower()}"
        ),
    )


class RiskSpecLifecycleAdvancementPermit(StoredObject):
    schema_name: Literal["RiskSpecLifecycleAdvancementPermit"]
    schema_version: SchemaVersion
    administration: AdministrationDecisionBinding
    store_instance_id: UUID
    execution_realm_ref: ObjectHashReference
    administration_authority: AdministrationActorAssignment
    gate_ref: ObjectHashReference
    spec_key: NonEmptyString
    spec_version_ref: VersionedSpecReference
    restriction_ref: ObjectHashReference
    expected_draft_head_ref: ObjectHashReference
    governing_decision_ref: ObjectHashReference
    review_decision_ref: ObjectHashReference
    from_state: Literal[LifecycleState.DRAFT]
    to_state: Literal[LifecycleState.REVIEWED]
    nonce: UUID
    reviewer: PrincipalIdentity
    reviewer_principal_version_hash: HashDigest
    reviewer_independence_domain_key: Literal["domain-reviewer"]
    reviewer_grant_ref: ObjectHashReference
    reviewer_grant_role: Literal[AuthorityRole.REVIEWER]
    reviewer_grant_scope: AuthorityScope
    reviewer_grant_sequence: Literal[1]
    reviewer_grant_valid_from: UtcTimestamp
    reviewer_grant_valid_until: UtcTimestamp
    authority: LifecycleReviewAuthorityTuple
    protected_lineage_bindings: Annotated[
        CanonicalSet[LifecyclePrincipalLineageBinding],
        Field(min_length=6),
    ]
    issued_by: LifecyclePrincipalLineageBinding
    issued_at: UtcTimestamp
    issued_at_instant: AuthorityInstant100ns
    valid_from: AuthorityInstant100ns
    valid_until: AuthorityInstant100ns
    reason_code: Literal["CORRECTION_002_EXACT_DRAFT_TO_REVIEWED_PERMIT"]
    permit_hash: HashDigest

    @model_validator(mode="after")
    def exact_permit_identity_and_bindings(
        self,
    ) -> RiskSpecLifecycleAdvancementPermit:
        expected = RISK_SPEC_DRAFT_REVIEW_AUTHORIZATION_EXPECTATIONS.get(self.spec_key)
        references = (
            self.gate_ref,
            self.administration.admin_decision_ref,
            self.execution_realm_ref,
            self.restriction_ref,
            self.expected_draft_head_ref,
            self.governing_decision_ref,
            self.review_decision_ref,
            self.reviewer_grant_ref,
            self.issued_by.lineage_head_ref,
            *(binding.lineage_head_ref for binding in self.protected_lineage_bindings),
        )
        if expected is None or any(
            reference.tenant_id != self.tenant_id for reference in references
        ):
            raise ValueError("permit references must bind one exact tenant item")
        if (
            self.administration.tenant_id != self.tenant_id
            or self.administration_authority.operation
            != "ISSUE_RISK_SPEC_LIFECYCLE_ADVANCEMENT_PERMIT"
            or self.administration_authority not in self.administration.actor_assignments
            or self.issued_by.principal.principal_version_id
            != self.administration_authority.principal.principal_version_id
        ):
            raise ValueError("permit administration authority is invalid")
        if (
            self.tenant_id,
            self.spec_version_ref.tenant_id,
            self.spec_version_ref.spec_version_id,
            self.spec_version_ref.module_key,
            self.spec_version_ref.version,
            self.spec_version_ref.content_hash,
            self.spec_version_ref.semantic_hash,
            self.restriction_ref.object_id,
            self.restriction_ref.object_hash,
            self.expected_draft_head_ref.object_id,
            self.expected_draft_head_ref.object_hash,
            self.governing_decision_ref.object_id,
            self.governing_decision_ref.object_hash,
            self.nonce,
            self.reviewer.principal_id,
            self.reviewer.principal_version_id,
            self.reviewer.independence_domain_id,
            self.reviewer.principal_type,
            self.reviewer_principal_version_hash,
            self.reviewer_grant_ref.object_id,
            self.reviewer_grant_ref.object_hash,
            self.reviewer_grant_valid_from,
            self.reviewer_grant_valid_until,
            self.authority.business_object,
            self.authority.policy_module,
            self.valid_from,
            self.valid_until,
        ) != (
            REVIEW_ADVANCEMENT_TENANT_ID,
            REVIEW_ADVANCEMENT_TENANT_ID,
            expected.spec_version_id,
            expected.module_key,
            1,
            expected.content_hash,
            expected.semantic_hash,
            expected.restriction_id,
            expected.restriction_hash,
            expected.draft_head_event_id,
            expected.draft_head_event_hash,
            GOVERNING_CORRECTION_DECISION_ID,
            GOVERNING_CORRECTION_DECISION_HASH,
            expected.nonce,
            REVIEWER_PRINCIPAL_ID,
            REVIEWER_PRINCIPAL_VERSION_ID,
            REVIEWER_INDEPENDENCE_DOMAIN_ID,
            PrincipalType.HUMAN,
            REVIEWER_PRINCIPAL_VERSION_HASH,
            REVIEWER_GRANT_ID,
            REVIEWER_GRANT_HASH,
            REVIEWER_GRANT_VALID_FROM,
            REVIEWER_GRANT_VALID_UNTIL,
            expected.spec_key,
            expected.module_key,
            REVIEW_ADVANCEMENT_DECIDED_AT,
            REVIEW_ADVANCEMENT_VALID_UNTIL,
        ):
            raise ValueError("permit does not match one exact accepted review item")
        expected_id = risk_spec_lifecycle_advancement_permit_id(
            review_decision_id=self.review_decision_ref.object_id,
            spec_version_id=self.spec_version_ref.spec_version_id,
            draft_head_event_id=self.expected_draft_head_ref.object_id,
            nonce=self.nonce,
        )
        if self.object_id != expected_id:
            raise ValueError("permit identifier is not deterministic")
        roles = {item.binding_role for item in self.protected_lineage_bindings}
        required_roles = {
            "SPEC_CREATOR",
            "DRAFT_HEAD_ACTOR",
            "GOVERNING_DECISION_PROPOSER",
            "GOVERNING_DECISION_RESOLVER",
            "REVIEW_DECISION_PROPOSER",
            "REVIEW_DECISION_RESOLVER",
        }
        if not required_roles <= roles:
            raise ValueError("permit protected-lineage set is incomplete")
        if (
            self.issued_by.principal.principal_version_id
            not in {item.principal.principal_version_id for item in self.protected_lineage_bindings}
            and "PERMIT_ISSUER" not in roles
        ):
            raise ValueError("a distinct permit issuer must be protected")
        if not (
            self.valid_from.unix_epoch_100ns_ticks_decimal
            <= self.issued_at_instant.unix_epoch_100ns_ticks_decimal
            < self.valid_until.unix_epoch_100ns_ticks_decimal
        ):
            raise ValueError("permit issuance must be inside exact validity")
        return self


def risk_spec_lifecycle_advancement_consumption_id(
    *,
    permit_id: UUID,
    lifecycle_event_id: UUID,
) -> UUID:
    return uuid5(
        REVIEW_ADVANCEMENT_CONSUMPTION_NAMESPACE,
        f"{str(permit_id).lower()}:{str(lifecycle_event_id).lower()}",
    )


class RiskSpecLifecycleAdvancementConsumption(StoredObject):
    schema_name: Literal["RiskSpecLifecycleAdvancementConsumption"]
    schema_version: SchemaVersion
    administration_decision_ref: ObjectHashReference
    store_instance_id: UUID
    execution_realm_ref: ObjectHashReference
    permit_ref: ObjectHashReference
    nonce: UUID
    exact_prior_head_ref: ObjectHashReference
    reviewed_event_ref: ObjectHashReference
    actor: PrincipalIdentity
    authority_grant_ref: ObjectHashReference
    review_decision_ref: ObjectHashReference
    protected_lineage_refs: Annotated[
        CanonicalSet[ObjectHashReference],
        Field(min_length=1),
    ]
    consumed_at: UtcTimestamp
    consumed_at_instant: AuthorityInstant100ns
    authority_valid_from: AuthorityInstant100ns
    authority_valid_until: AuthorityInstant100ns
    api_request_hash: HashDigest
    idempotency_key_hash: HashDigest
    consumption_hash: HashDigest

    @model_validator(mode="after")
    def exact_consumption_identity(
        self,
    ) -> RiskSpecLifecycleAdvancementConsumption:
        references = (
            self.permit_ref,
            self.administration_decision_ref,
            self.execution_realm_ref,
            self.exact_prior_head_ref,
            self.reviewed_event_ref,
            self.authority_grant_ref,
            self.review_decision_ref,
            *self.protected_lineage_refs,
        )
        if (
            self.tenant_id != REVIEW_ADVANCEMENT_TENANT_ID
            or any(reference.tenant_id != self.tenant_id for reference in references)
            or self.actor.tenant_id != self.tenant_id
            or self.actor.principal_id != REVIEWER_PRINCIPAL_ID
            or self.actor.principal_version_id != REVIEWER_PRINCIPAL_VERSION_ID
            or self.actor.independence_domain_id != REVIEWER_INDEPENDENCE_DOMAIN_ID
            or self.authority_grant_ref.object_id != REVIEWER_GRANT_ID
            or self.authority_grant_ref.object_hash != REVIEWER_GRANT_HASH
            or self.authority_valid_from != REVIEW_ADVANCEMENT_DECIDED_AT
            or self.authority_valid_until != REVIEW_ADVANCEMENT_VALID_UNTIL
            or not (
                self.authority_valid_from.unix_epoch_100ns_ticks_decimal
                <= self.consumed_at_instant.unix_epoch_100ns_ticks_decimal
                < self.authority_valid_until.unix_epoch_100ns_ticks_decimal
            )
            or self.object_id
            != risk_spec_lifecycle_advancement_consumption_id(
                permit_id=self.permit_ref.object_id,
                lifecycle_event_id=self.reviewed_event_ref.object_id,
            )
        ):
            raise ValueError("consumption does not bind the exact review result")
        return self


RiskSpecContract = Annotated[
    RiskSpecVersion | RiskSpecCorrection | RiskSpecVersionV3,
    Field(discriminator="schema_version"),
]


def risk_spec_semantic_hash(spec: RiskSpecVersion) -> str:
    """Preserve v1 semantics while binding all schema-v2 policy scope."""

    if isinstance(spec, RiskSpecVersionV3):
        return canonical_hash(
            schema="RiskSpecVersionSemantics",
            schema_version=3,
            tenant_id=spec.tenant_id,
            payload={
                "policy_module": spec.policy_module,
                "trace_refs": spec.trace_refs,
                "item_traces": spec.item_traces,
            },
        )
    if isinstance(spec, RiskSpecCorrection):
        return canonical_hash(
            schema="RiskSpecCorrectionSemantics",
            schema_version=2,
            tenant_id=spec.tenant_id,
            payload={
                "policy_module": spec.policy_module,
                "environments": spec.environments,
                "effective_from": spec.effective_from,
                "effective_until": spec.effective_until,
                "trace_refs": spec.trace_refs,
                "approval_interpretations": (spec.approval_interpretations),
                "item_traces": spec.item_traces,
            },
        )
    return canonical_hash(
        schema="PolicyModule",
        schema_version=1,
        tenant_id=spec.tenant_id,
        payload=spec.policy_module,
    )


def policy_item_trace_paths(spec: RiskSpecVersion) -> tuple[str, ...]:
    """Return every trace-bearing semantic item path in canonical order."""

    paths = ["spec", "policy_module.coverage"]
    for rule in spec.policy_module.rules:
        prefix = f"rule:{rule.rule_key}"
        paths.extend((prefix, f"{prefix}:on_unknown"))
        paths.extend(f"{prefix}:when:{index}" for index, _ in enumerate(rule.when, start=1))
        for requirement in rule.requirements:
            item = f"{prefix}:requirement:{requirement.control_key}"
            paths.extend((item, f"{item}:failure_effect"))
        for prohibition in rule.prohibitions:
            item = f"{prefix}:prohibition:{prohibition.prohibition_key}"
            paths.extend((item, f"{item}:on_unknown"))
            paths.extend(
                f"{item}:when:{index}" for index, _ in enumerate(prohibition.when, start=1)
            )
        paths.extend(
            f"{prefix}:route_constraint:{index}"
            for index, _ in enumerate(rule.route_constraints, start=1)
        )
        paths.extend(f"{prefix}:condition:{condition.control_key}" for condition in rule.conditions)
        for cap in rule.economic_caps:
            item = f"{prefix}:economic_cap:{cap.cap_key}"
            paths.extend((item, f"{item}:breach_effect"))
    return tuple(sorted(paths))


class LifecycleEvent(StoredObject):
    schema_name: Literal["LifecycleEvent"]
    schema_version: SchemaVersion
    spec_version_ref: VersionedSpecReference
    prior_state: LifecycleState | None
    prior_event_ref: ObjectHashReference | None
    next_state: LifecycleState
    actor: PrincipalIdentity
    authority_grant_ref: ObjectHashReference
    event_at: UtcTimestamp
    effective_at: UtcTimestamp | None
    exact_content_hash: HashDigest
    accepted_decision_refs: CanonicalSet[ObjectHashReference]
    reason_code: NonEmptyString
    sequence: PositiveInt
    event_hash: HashDigest


class LifecycleAdvancementReviewResult(AssuranceModel):
    schema_name: Literal["LifecycleAdvancementReviewResult"]
    schema_version: SchemaVersion
    tenant_id: UUID
    event: LifecycleEvent
    consumption: RiskSpecLifecycleAdvancementConsumption
    permit_ref: ObjectHashReference
    request_hash: HashDigest
    completed_at: UtcTimestamp
    result_hash: HashDigest

    @model_validator(mode="after")
    def result_links_are_exact(self) -> LifecycleAdvancementReviewResult:
        if (
            self.event.tenant_id != self.tenant_id
            or self.consumption.tenant_id != self.tenant_id
            or self.permit_ref.tenant_id != self.tenant_id
            or self.consumption.reviewed_event_ref.object_id != self.event.object_id
            or self.consumption.reviewed_event_ref.object_hash != self.event.event_hash
            or self.consumption.permit_ref != self.permit_ref
            or self.consumption.api_request_hash != self.request_hash
            or self.consumption.consumed_at != self.completed_at
        ):
            raise ValueError("review result links are inconsistent")
        return self


class RecordVerifierArtifactCommand(AssuranceModel):
    administration_decision_ref: ObjectHashReference
    store_instance_id: UUID
    execution_realm_ref: ObjectHashReference
    manifest_observation: SignedLifecycleFilesystemManifestObservation
    artifact: LifecycleAdvancementVerifierArtifact


class RecordVerificationGateCommand(AssuranceModel):
    administration_decision_ref: ObjectHashReference
    store_instance_id: UUID
    execution_realm_ref: ObjectHashReference
    gate: RiskSpecLifecycleAdvancementVerificationGate


class IssueLifecycleAdvancementPermitCommand(AssuranceModel):
    administration_decision_ref: ObjectHashReference
    store_instance_id: UUID
    execution_realm_ref: ObjectHashReference
    gate_ref: ObjectHashReference
    spec_version_id: UUID


class LifecycleAdvancementReviewCommand(AssuranceModel):
    idempotency_key: NonEmptyString
    spec_version_id: UUID
    permit_ref: ObjectHashReference
    permit_nonce: UUID
    expected_draft_head_ref: ObjectHashReference
    reason_code: Literal["CORRECTION_002_EXACT_DRAFT_TO_REVIEWED_PERMIT"]


class ActionIntent(StoredObject):
    schema_name: Literal["ActionIntent"]
    schema_version: SchemaVersion
    principal: PrincipalIdentity
    behalf_of_party_id: UUID
    canonical_action: CanonicalAction
    domain_verb: DomainVerb
    accepted_action_mapping: CanonicalActionMapping
    resource: ResourceIdentity
    requested_state_change: TypedValue
    context: CanonicalSet[ContextClaim]
    evidence_refs: CanonicalSet[ObjectHashReference]
    requested_cost: Money
    server_meter_refs: CanonicalSet[MeterReference]
    retry: RetryData
    requested_at: UtcTimestamp
    requested_route: RouteId
    idempotency_key: NonEmptyString
    intent_hash: HashDigest

    @model_validator(mode="after")
    def validate_intent_bindings(self) -> ActionIntent:
        nested_tenants = {
            self.principal.tenant_id,
            self.resource.tenant_id,
            self.accepted_action_mapping.human_decision_ref.tenant_id,
            *(reference.tenant_id for reference in self.evidence_refs),
            *(reference.tenant_id for reference in self.server_meter_refs),
        }
        if nested_tenants != {self.tenant_id}:
            raise ValueError("all ActionIntent links must be tenant-bound")
        mapping = self.accepted_action_mapping
        if (
            mapping.domain_verb != self.domain_verb
            or mapping.canonical_action != self.canonical_action
            or mapping.resource_type != self.resource.resource_type
        ):
            raise ValueError("action tuple must match the accepted action mapping")
        return self


class StreamHeadReference(AssuranceModel):
    tenant_id: UUID
    stream_type: StreamType
    stream_id: UUID
    sequence: NonNegativeInt
    head_hash: HashDigest


class QueryDescriptor(AssuranceModel):
    query_type: QueryType
    descriptor_hash: HashDigest
    stream_heads: CanonicalSet[StreamHeadReference]


class EvaluationToolchain(AssuranceModel):
    contract_schema_version: NonEmptyString
    policy_algebra_version: NonEmptyString
    canonicalizer_id: NonEmptyString
    canonicalizer_version: NonEmptyString
    evaluator_build_id: NonEmptyString
    evaluator_build_digest: HashDigest


class EvaluationInputManifest(StoredObject):
    schema_name: Literal["EvaluationInputManifest"]
    schema_version: SchemaVersion
    evaluated_at: UtcTimestamp
    intent_ref: ObjectHashReference
    resolved_fact_refs: CanonicalSet[ObjectHashReference]
    query_descriptors: CanonicalSet[QueryDescriptor]
    selected_specs: CanonicalSet[VersionedSpecReference]
    lifecycle_event_refs: CanonicalSet[ObjectHashReference]
    human_decision_refs: CanonicalSet[ObjectHashReference]
    authority_grant_refs: CanonicalSet[ObjectHashReference]
    lineage_membership_refs: CanonicalSet[ObjectHashReference]
    evidence_production_event_refs: CanonicalSet[ObjectHashReference]
    evidence_certification_event_refs: CanonicalSet[ObjectHashReference]
    evidence_verification_event_refs: CanonicalSet[ObjectHashReference]
    economic_meter_event_refs: CanonicalSet[ObjectHashReference]
    toolchain: EvaluationToolchain
    manifest_hash: HashDigest

    @model_validator(mode="after")
    def manifest_is_tenant_bound(self) -> EvaluationInputManifest:
        references = [
            self.intent_ref,
            *self.resolved_fact_refs,
            *self.lifecycle_event_refs,
            *self.human_decision_refs,
            *self.authority_grant_refs,
            *self.lineage_membership_refs,
            *self.evidence_production_event_refs,
            *self.evidence_certification_event_refs,
            *self.evidence_verification_event_refs,
            *self.economic_meter_event_refs,
        ]
        spec_tenants = {spec.tenant_id for spec in self.selected_specs}
        query_tenants = {
            head.tenant_id
            for descriptor in self.query_descriptors
            for head in descriptor.stream_heads
        }
        if {reference.tenant_id for reference in references} | spec_tenants | query_tenants != {
            self.tenant_id
        }:
            raise ValueError("every manifest input must be tenant-bound")
        return self


class RequirementResult(AssuranceModel):
    requirement: Requirement
    status: RequirementStatus
    origin_specs: Annotated[CanonicalSet[VersionedSpecReference], Field(min_length=1)]
    approval_refs: CanonicalSet[ObjectHashReference]
    evidence_refs: CanonicalSet[ObjectHashReference]


class ConditionResult(AssuranceModel):
    condition: Condition
    status: ConditionStatus
    origin_specs: Annotated[CanonicalSet[VersionedSpecReference], Field(min_length=1)]


class MatchedProhibition(AssuranceModel):
    prohibition: Prohibition
    origin_specs: Annotated[CanonicalSet[VersionedSpecReference], Field(min_length=1)]


class RouteConflict(AssuranceModel):
    conflicting_constraints: Annotated[CanonicalSet[RouteConstraint], Field(min_length=2)]
    origin_specs: Annotated[CanonicalSet[VersionedSpecReference], Field(min_length=2)]


class EconomicEnvelope(AssuranceModel):
    meter_refs: CanonicalSet[MeterReference]
    current_attempt_count: NonNegativeInt
    current_cost: Money
    remaining_attempts: NonNegativeInt | None
    remaining_cost: Money | None


class ControlDecisionSemanticPayload(AssuranceModel):
    selected_specs: CanonicalSet[VersionedSpecReference]
    requirements: CanonicalSet[RequirementResult]
    matched_prohibitions: CanonicalSet[MatchedProhibition]
    route_conflicts: CanonicalSet[RouteConflict]
    conditions: CanonicalSet[ConditionResult]
    approval_refs: CanonicalSet[ObjectHashReference]
    evidence_refs: CanonicalSet[ObjectHashReference]
    mandatory_allow_sets: CanonicalSet[RouteConstraint]
    denied_routes: CanonicalSet[RouteId]
    feasible_routes: CanonicalSet[RouteId]
    economic_envelope: EconomicEnvelope
    verdict: Verdict
    explanation_codes: Annotated[CanonicalSet[ExplanationCode], Field(min_length=1)]
    requires_reauthorization: StrictBool


class ControlDecision(StoredObject):
    schema_name: Literal["ControlDecision"]
    schema_version: SchemaVersion
    intent_ref: ObjectHashReference
    evaluation_manifest_ref: ObjectHashReference
    evaluated_at: UtcTimestamp
    expires_at: UtcTimestamp
    predecessor_decision_ref: ObjectHashReference | None
    semantic_payload: ControlDecisionSemanticPayload
    display_prose: str | None
    decision_hash: HashDigest

    @model_validator(mode="after")
    def validate_decision_bindings(self) -> ControlDecision:
        references = [self.intent_ref, self.evaluation_manifest_ref]
        if self.predecessor_decision_ref is not None:
            references.append(self.predecessor_decision_ref)
        if any(reference.tenant_id != self.tenant_id for reference in references):
            raise ValueError("all ControlDecision links must be tenant-bound")
        if self.expires_at <= self.evaluated_at:
            raise ValueError("expires_at must be after evaluated_at")
        if any(spec.tenant_id != self.tenant_id for spec in self.semantic_payload.selected_specs):
            raise ValueError("selected specs must be tenant-bound")
        return self


class Approval(StoredObject):
    schema_name: Literal["Approval"]
    schema_version: SchemaVersion
    approval_request_ref: ObjectHashReference
    decision_ref: ObjectHashReference
    intent_ref: ObjectHashReference
    approved_requirement_key: NonEmptyString
    approved_scope: AuthorityScope
    approved_route: RouteId | None
    approver: PrincipalIdentity
    authority_grant_ref: ObjectHashReference
    valid_from: UtcTimestamp
    valid_until: UtcTimestamp
    outcome: ApprovalOutcome
    predecessor_event_ref: ObjectHashReference | None
    approval_hash: HashDigest

    @model_validator(mode="after")
    def validate_approval_bindings(self) -> Approval:
        references = [
            self.approval_request_ref,
            self.decision_ref,
            self.intent_ref,
            self.authority_grant_ref,
        ]
        if self.predecessor_event_ref is not None:
            references.append(self.predecessor_event_ref)
        if self.approver.tenant_id != self.tenant_id or any(
            reference.tenant_id != self.tenant_id for reference in references
        ):
            raise ValueError("all Approval links must be tenant-bound")
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self


class EvidenceProductionEvent(StoredObject):
    schema_name: Literal["EvidenceProductionEvent"]
    schema_version: SchemaVersion
    evidence_item_id: UUID
    producer: PrincipalIdentity
    subject_ref: ObjectHashReference
    decision_ref: ObjectHashReference
    requirement_key: NonEmptyString
    content_hash: HashDigest
    claimed_provenance: NonEmptyString
    produced_at: UtcTimestamp
    event_hash: HashDigest


class EvidenceCertificationEvent(StoredObject):
    schema_name: Literal["EvidenceCertificationEvent"]
    schema_version: SchemaVersion
    evidence_item_id: UUID
    production_event_ref: ObjectHashReference
    certifier: PrincipalIdentity
    authority_grant_ref: ObjectHashReference
    certified_at: UtcTimestamp
    event_hash: HashDigest


class EvidenceVerificationEvent(StoredObject):
    schema_name: Literal["EvidenceVerificationEvent"]
    schema_version: SchemaVersion
    evidence_item_id: UUID
    production_event_ref: ObjectHashReference
    certification_event_ref: ObjectHashReference | None
    verifier_id: NonEmptyString
    verifier_version: NonEmptyString
    outcome: EvidenceVerificationOutcome
    derived_classification: Classification
    valid_from: UtcTimestamp | None
    valid_until: UtcTimestamp | None
    verified_at: UtcTimestamp
    event_hash: HashDigest


class EvidenceItem(StoredObject):
    schema_name: Literal["EvidenceItem"]
    schema_version: SchemaVersion
    subject_ref: ObjectHashReference
    decision_ref: ObjectHashReference
    requirement_key: NonEmptyString
    content_reference: ContentReference
    content_hash: HashDigest
    production_event_ref: ObjectHashReference
    certification_event_refs: CanonicalSet[ObjectHashReference]
    verification_event_refs: CanonicalSet[ObjectHashReference]
    evidence_hash: HashDigest

    @model_validator(mode="after")
    def evidence_links_are_tenant_bound(self) -> EvidenceItem:
        refs = [
            self.subject_ref,
            self.decision_ref,
            self.production_event_ref,
            *self.certification_event_refs,
            *self.verification_event_refs,
        ]
        if any(reference.tenant_id != self.tenant_id for reference in refs):
            raise ValueError("all EvidenceItem links must be tenant-bound")
        return self


class ExecutionRecord(StoredObject):
    schema_name: Literal["ExecutionRecord"]
    schema_version: SchemaVersion
    intent_ref: ObjectHashReference
    decision_ref: ObjectHashReference
    idempotency_key: NonEmptyString
    gate_result: ExecutionGateResult
    actual_route: RouteId | None
    simulator_input_hash: HashDigest | None
    simulator_output_hash: HashDigest | None
    started_at: UtcTimestamp | None
    ended_at: UtcTimestamp
    executor: PrincipalIdentity
    observed_cost: Money
    attempt_number: PositiveInt
    outcome: ExecutionOutcome
    predecessor_event_ref: ObjectHashReference | None
    event_chain_hash: HashDigest


def semantic_action_group_hash(
    *,
    tenant_id: UUID,
    resource_id: UUID,
    canonical_action: CanonicalAction,
    domain_verb: DomainVerb,
    requested_state_change: TypedValue,
) -> str:
    """Hash only the approved stable semantic-action partition dimensions."""

    return canonical_hash(
        schema="SemanticActionGroupKey",
        schema_version=1,
        tenant_id=tenant_id,
        payload={
            "resource_id": resource_id,
            "canonical_action": canonical_action,
            "domain_verb": domain_verb,
            "requested_state_change": requested_state_change,
        },
    )


class SemanticActionGroup(StoredObject):
    schema_name: Literal["SemanticActionGroup"]
    schema_version: SchemaVersion
    resource_id: UUID
    canonical_action: CanonicalAction
    domain_verb: DomainVerb
    requested_state_change: TypedValue
    group_hash: HashDigest

    @model_validator(mode="after")
    def group_hash_has_only_approved_dimensions(self) -> SemanticActionGroup:
        if self.group_hash != semantic_action_group_hash(
            tenant_id=self.tenant_id,
            resource_id=self.resource_id,
            canonical_action=self.canonical_action,
            domain_verb=self.domain_verb,
            requested_state_change=self.requested_state_change,
        ):
            raise ValueError("semantic action group hash does not match its closed tuple")
        return self


class ProductionExecutionAttempt(StoredObject):
    schema_name: Literal["ProductionExecutionAttempt"]
    schema_version: SchemaVersion
    semantic_action_group_ref: ObjectHashReference
    execution_request_ref: ObjectHashReference
    server_attempt_number: PositiveInt
    canonical_action: CanonicalAction
    domain_verb: DomainVerb
    resource_id: UUID
    requested_state_hash: HashDigest
    authorized_route: RouteId

    @model_validator(mode="after")
    def production_attempt_is_tenant_bound(self) -> ProductionExecutionAttempt:
        if (
            self.semantic_action_group_ref.tenant_id != self.tenant_id
            or self.execution_request_ref.tenant_id != self.tenant_id
        ):
            raise ValueError("production attempt references must be tenant-bound")
        return self


def target_key_binding_hash(
    *,
    tenant_id: UUID,
    target_connector_ref: VersionedComponentReference,
    target_registry_ref: ObjectHashReference,
    operation: str,
    purpose: TargetKeyPurpose,
    key_id: str,
    key_version: str,
    audience: str,
    algorithm: str,
    material_ref: SecretRef,
    valid_from: UtcTimestamp,
    valid_until: UtcTimestamp,
    revoked_at: UtcTimestamp | None,
) -> str:
    return canonical_hash(
        schema="TargetKeyBindingKey",
        schema_version=1,
        tenant_id=tenant_id,
        payload={
            "target_connector_ref": target_connector_ref,
            "target_registry_ref": target_registry_ref,
            "operation": operation,
            "purpose": purpose,
            "key_id": key_id,
            "key_version": key_version,
            "audience": audience,
            "algorithm": algorithm,
            "material_ref": material_ref,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "revoked_at": revoked_at,
        },
    )


class TargetKeyBinding(StoredObject):
    schema_name: Literal["TargetKeyBinding"]
    schema_version: SchemaVersion
    target_connector_ref: VersionedComponentReference
    target_registry_ref: ObjectHashReference
    operation: NonEmptyString
    purpose: TargetKeyPurpose
    key_id: NonEmptyString
    key_version: NonEmptyString
    audience: NonEmptyString
    algorithm: NonEmptyString
    material_ref: SecretRef
    valid_from: UtcTimestamp
    valid_until: UtcTimestamp
    revoked_at: UtcTimestamp | None
    binding_hash: HashDigest

    @model_validator(mode="after")
    def immutable_key_binding_is_exact(self) -> TargetKeyBinding:
        if (
            self.target_connector_ref.tenant_id != self.tenant_id
            or self.target_registry_ref.tenant_id != self.tenant_id
        ):
            raise ValueError("target key binding references must be tenant-bound")
        if self.valid_until <= self.valid_from:
            raise ValueError("target key validity must be ordered")
        if self.revoked_at is not None and self.revoked_at < self.valid_from:
            raise ValueError("target key revocation cannot precede validity")
        expected = target_key_binding_hash(
            tenant_id=self.tenant_id,
            target_connector_ref=self.target_connector_ref,
            target_registry_ref=self.target_registry_ref,
            operation=self.operation,
            purpose=self.purpose,
            key_id=self.key_id,
            key_version=self.key_version,
            audience=self.audience,
            algorithm=self.algorithm,
            material_ref=self.material_ref,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
            revoked_at=self.revoked_at,
        )
        if self.binding_hash != expected:
            raise ValueError("target key binding hash does not match its exact tuple")
        return self


class TargetAuthorization(StoredObject):
    schema_name: Literal["TargetAuthorization"]
    schema_version: SchemaVersion
    semantic_action_group_ref: ObjectHashReference
    execution_attempt_ref: ObjectHashReference
    execution_request_ref: ObjectHashReference
    intent_ref: ObjectHashReference
    decision_ref: ObjectHashReference
    target_connector_ref: VersionedComponentReference
    target_registry_ref: ObjectHashReference
    authorization_key_binding_ref: ObjectHashReference
    result_key_binding_ref: ObjectHashReference
    authorization_nonce: UUID
    server_attempt_number: PositiveInt
    canonical_action: CanonicalAction
    domain_verb: DomainVerb
    resource_id: UUID
    requested_state_change: TypedValue
    requested_state_hash: HashDigest
    authorized_route: RouteId
    issued_at: UtcTimestamp
    expires_at: UtcTimestamp
    authorization_payload_hash: HashDigest
    authorization_signature_base64: NonEmptyString
    authorization_hash: HashDigest

    @model_validator(mode="after")
    def target_authorization_is_exact_and_purpose_separated(self) -> TargetAuthorization:
        references = (
            self.semantic_action_group_ref,
            self.execution_attempt_ref,
            self.execution_request_ref,
            self.intent_ref,
            self.decision_ref,
            self.target_connector_ref,
            self.target_registry_ref,
            self.authorization_key_binding_ref,
            self.result_key_binding_ref,
        )
        if any(reference.tenant_id != self.tenant_id for reference in references):
            raise ValueError("target authorization references must be tenant-bound")
        if self.authorization_key_binding_ref == self.result_key_binding_ref:
            raise ValueError("target key binding purposes cannot substitute")
        if self.expires_at <= self.issued_at:
            raise ValueError("target authorization expiry must follow issuance")
        return self


class TargetDispatchEvent(StoredObject):
    schema_name: Literal["TargetDispatchEvent"]
    schema_version: SchemaVersion
    semantic_action_group_ref: ObjectHashReference
    execution_attempt_ref: ObjectHashReference
    execution_request_ref: ObjectHashReference
    target_authorization_ref: ObjectHashReference
    authorization_nonce: UUID
    server_attempt_number: PositiveInt
    canonical_action: CanonicalAction
    domain_verb: DomainVerb
    resource_id: UUID
    requested_state_hash: HashDigest
    authorized_route: RouteId
    target_connector_ref: VersionedComponentReference
    target_registry_ref: ObjectHashReference
    authorization_key_binding_ref: ObjectHashReference
    result_key_binding_ref: ObjectHashReference
    outbox_id: UUID
    event_kind: TargetDispatchEventKind
    delivery_number: PositiveInt
    event_at: UtcTimestamp
    lease_owner_hash: HashDigest | None
    lease_expires_at: UtcTimestamp | None
    predecessor_event_ref: ObjectHashReference | None
    event_hash: HashDigest

    @model_validator(mode="after")
    def dispatch_event_is_tenant_bound(self) -> TargetDispatchEvent:
        references = (
            self.semantic_action_group_ref,
            self.execution_attempt_ref,
            self.execution_request_ref,
            self.target_authorization_ref,
            self.target_connector_ref,
            self.target_registry_ref,
            self.authorization_key_binding_ref,
            self.result_key_binding_ref,
        )
        if any(reference.tenant_id != self.tenant_id for reference in references) or (
            self.predecessor_event_ref is not None
            and self.predecessor_event_ref.tenant_id != self.tenant_id
        ):
            raise ValueError("dispatch event references must be tenant-bound")
        lease_shape = self.lease_owner_hash is not None and self.lease_expires_at is not None
        if (self.event_kind is TargetDispatchEventKind.LEASED) != lease_shape:
            raise ValueError("only a leased dispatch event carries a complete lease")
        return self


class TargetDispatchEventV2ReceiptProjection(AssuranceModel):
    """Closed canonical receipt projection for the one safe-replay event kind."""

    schema_name: Literal["TargetDispatchEvent"]
    schema_version: Literal[2]
    event_kind: Literal["REPLAY_LEASED_CALL_STARTED"]
    proof_authentication_receipt_canonical_base64: NonEmptyString
    proof_authentication_receipt_hash: HashDigest

    @model_validator(mode="after")
    def receipt_bytes_are_canonical_and_hash_bound(
        self,
    ) -> TargetDispatchEventV2ReceiptProjection:
        try:
            receipt_bytes = base64.b64decode(
                self.proof_authentication_receipt_canonical_base64,
                validate=True,
            )
        except (binascii.Error, ValueError) as error:
            raise ValueError("safe-replay receipt encoding is invalid") from error
        canonical_base64 = base64.b64encode(receipt_bytes).decode("ascii")
        receipt_hash = f"sha256:{hashlib.sha256(receipt_bytes).hexdigest()}"
        if (
            not receipt_bytes
            or canonical_base64
            != self.proof_authentication_receipt_canonical_base64
            or receipt_hash != self.proof_authentication_receipt_hash
        ):
            raise ValueError("safe-replay receipt bytes and hash are not exact")
        return self


class ReferenceSafeReplayProofAuthenticationInputV1(AssuranceModel):
    """Exact domain-separated bytes authenticated after external Ed25519 proof."""

    schema_value: Literal["ReferenceSafeReplayProofAuthenticationInput"] = Field(
        alias="schema",
        serialization_alias="schema",
    )
    schema_version: Literal[1]
    purpose: Literal["REFERENCE_SAFE_REPLAY_NONCE_PROOF_AUTHENTICATION"]
    validator_contract_id: Literal["reference-safe-replay-proof-verifier-v1"]
    tenant_id: UUID
    worker_principal_version_id: UUID
    proof_envelope_hash: HashDigest
    claimed_proof_hash: HashDigest
    proof_payload_hash: HashDigest
    result_binding_ref: ObjectHashReference
    result_binding_hash: HashDigest
    result_binding_status_ref: ObjectHashReference
    result_binding_status_head_hash: HashDigest
    binding_status_manifest_hash: HashDigest
    target_authorization_ref: ObjectHashReference
    authorization_hash: HashDigest
    execution_request_ref: ObjectHashReference
    execution_request_hash: HashDigest
    authorization_nonce: UUID
    store_id: UUID
    store_generation_id: UUID
    store_sequence: NonNegativeInt
    store_head_hash: HashDigest
    proof_at: UtcTimestamp
    proof_state: Literal["ABSENT_AT_SIGNED_HEAD", "EXACT_RESULT"]

    @model_validator(mode="after")
    def references_are_tenant_bound(
        self,
    ) -> ReferenceSafeReplayProofAuthenticationInputV1:
        references = (
            self.result_binding_ref,
            self.result_binding_status_ref,
            self.target_authorization_ref,
            self.execution_request_ref,
        )
        if any(reference.tenant_id != self.tenant_id for reference in references):
            raise ValueError("safe-replay authentication references must be tenant-bound")
        return self


def reference_safe_replay_authentication_input_canonical_bytes(
    value: ReferenceSafeReplayProofAuthenticationInputV1,
) -> bytes:
    """Return the exact aliased canonical payload bytes authenticated by HMAC."""

    return canonical_json(value.model_dump(mode="python", by_alias=True))


class ReferenceSafeReplayProofAuthenticationReceiptV1(AssuranceModel):
    schema_name: Literal["ReferenceSafeReplayProofAuthenticationReceipt"]
    schema_version: Literal[1]
    key_id: NonEmptyString
    authority_input_hash: HashDigest
    canonical_payload_base64: NonEmptyString
    mac_base64: NonEmptyString

    @model_validator(mode="after")
    def payload_and_mac_are_strict_base64_and_hash_bound(
        self,
    ) -> ReferenceSafeReplayProofAuthenticationReceiptV1:
        try:
            payload = base64.b64decode(self.canonical_payload_base64, validate=True)
            mac = base64.b64decode(self.mac_base64, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("safe-replay authentication receipt is not strict base64") from error
        if (
            not payload
            or len(mac) != hashlib.sha256().digest_size
            or base64.b64encode(payload).decode("ascii") != self.canonical_payload_base64
            or base64.b64encode(mac).decode("ascii") != self.mac_base64
            or f"sha256:{hashlib.sha256(payload).hexdigest()}" != self.authority_input_hash
        ):
            raise ValueError("safe-replay authentication receipt is not exact")
        return self


class TargetDispatchEventV2ReceiptPersistenceProjection(AssuranceModel):
    """Decoded database-column projection for safe-replay receipt bytes."""

    proof_authentication_receipt_canonical_bytes: bytes
    proof_authentication_receipt_hash: HashDigest

    @model_validator(mode="after")
    def decoded_receipt_hash_is_exact(
        self,
    ) -> TargetDispatchEventV2ReceiptPersistenceProjection:
        expected = (
            "sha256:"
            f"{hashlib.sha256(self.proof_authentication_receipt_canonical_bytes).hexdigest()}"
        )
        if (
            not self.proof_authentication_receipt_canonical_bytes
            or self.proof_authentication_receipt_hash != expected
        ):
            raise ValueError("decoded safe-replay receipt bytes and hash are not exact")
        return self


class AuthenticatedTargetResult(StoredObject):
    schema_name: Literal["AuthenticatedTargetResult"]
    schema_version: SchemaVersion
    execution_attempt_ref: ObjectHashReference
    execution_request_ref: ObjectHashReference
    target_authorization_ref: ObjectHashReference
    semantic_action_group_ref: ObjectHashReference
    target_connector_ref: VersionedComponentReference
    target_registry_ref: ObjectHashReference
    authorization_key_binding_ref: ObjectHashReference
    result_key_binding_ref: ObjectHashReference
    authorization_nonce: UUID
    server_attempt_number: PositiveInt
    canonical_action: CanonicalAction
    domain_verb: DomainVerb
    resource_id: UUID
    requested_state_hash: HashDigest
    authorized_route: RouteId
    actual_route: RouteId
    result_payload_hash: HashDigest
    signed_result_base64: NonEmptyString
    result_signature_base64: NonEmptyString
    signed_completed_at: UtcTimestamp
    server_received_at: UtcTimestamp
    server_verified_at: UtcTimestamp
    result_hash: HashDigest

    @model_validator(mode="after")
    def authenticated_result_is_exact_and_purpose_bound(self) -> AuthenticatedTargetResult:
        references = (
            self.execution_attempt_ref,
            self.execution_request_ref,
            self.target_authorization_ref,
            self.semantic_action_group_ref,
            self.target_connector_ref,
            self.target_registry_ref,
            self.authorization_key_binding_ref,
            self.result_key_binding_ref,
        )
        if any(reference.tenant_id != self.tenant_id for reference in references):
            raise ValueError("authenticated result references must be tenant-bound")
        if self.actual_route != self.authorized_route:
            raise ValueError("actual route must match the frozen authorized route")
        if not (self.signed_completed_at <= self.server_received_at <= self.server_verified_at):
            raise ValueError("result completion, receive, and verification times must be ordered")
        return self


class ProductionExecutionRecordBridge(StoredObject):
    """Immutable bridge from the T05 attempt to the retained v1 receipt record."""

    schema_name: Literal["ProductionExecutionRecordBridge"]
    schema_version: SchemaVersion
    intent_ref: ObjectHashReference
    evaluation_manifest_ref: ObjectHashReference
    selected_specs: CanonicalSet[VersionedSpecReference]
    decision_ref: ObjectHashReference
    semantic_action_group_ref: ObjectHashReference
    execution_request_ref: ObjectHashReference
    execution_attempt_ref: ObjectHashReference
    target_authorization_ref: ObjectHashReference
    delivered_dispatch_ref: ObjectHashReference
    nonce_consumption_ref: ObjectHashReference
    authenticated_result_ref: ObjectHashReference
    terminal_event_ref: ObjectHashReference
    meter_event_refs: CanonicalSet[ObjectHashReference]
    execution_record_ref: ObjectHashReference
    execution_record_canonical_hash: HashDigest
    canonicalizer_version: NonEmptyString
    evaluator_build_id: NonEmptyString
    policy_algebra_version: NonEmptyString
    attempt_count: PositiveInt
    estimated_cost_reserved: Money
    observed_charge: Money
    realized_savings_minor_units: None = None
    financially_reconciled: Literal[False] = False
    result_succeeded: StrictBool
    actual_route: RouteId
    execution_outcome: ExecutionOutcome
    bridge_hash: HashDigest

    @model_validator(mode="after")
    def production_bridge_is_exact_and_economically_honest(
        self,
    ) -> ProductionExecutionRecordBridge:
        references = (
            self.intent_ref,
            self.evaluation_manifest_ref,
            self.decision_ref,
            self.semantic_action_group_ref,
            self.execution_request_ref,
            self.execution_attempt_ref,
            self.target_authorization_ref,
            self.delivered_dispatch_ref,
            self.nonce_consumption_ref,
            self.authenticated_result_ref,
            self.terminal_event_ref,
            self.execution_record_ref,
            *self.meter_event_refs,
        )
        if any(reference.tenant_id != self.tenant_id for reference in references) or any(
            spec.tenant_id != self.tenant_id for spec in self.selected_specs
        ):
            raise ValueError("all production bridge references must be tenant-bound")
        if len(self.meter_event_refs) != 2:
            raise ValueError("production bridge requires the exact two economic meter events")
        if (
            self.estimated_cost_reserved.currency != self.observed_charge.currency
            or self.estimated_cost_reserved.minor_units < 0
            or self.observed_charge.minor_units != 0
        ):
            raise ValueError("production economics must retain estimated cost and observed zero")
        return self


class ProductionPostActionConditionBinding(AssuranceModel):
    """Frozen post-action condition satisfied only by authenticated result proof."""

    control_key: NonEmptyString
    condition_hash: HashDigest
    evidence_kind: Literal[EvidenceKind.EXECUTION_RESULT]


class ProductionResultEvidenceBinding(StoredObject):
    """Server-derived binding from an authenticated result to finite evidence."""

    schema_name: Literal["ProductionResultEvidenceBinding"]
    schema_version: SchemaVersion
    execution_attempt_ref: ObjectHashReference
    bridge_ref: ObjectHashReference
    authenticated_result_ref: ObjectHashReference
    evidence_item_ref: ObjectHashReference
    production_event_ref: ObjectHashReference
    verification_event_ref: ObjectHashReference
    classification: Classification
    verifier_id: NonEmptyString
    verifier_version: NonEmptyString
    valid_from: UtcTimestamp
    valid_until: UtcTimestamp
    post_action_conditions: CanonicalSet[ProductionPostActionConditionBinding]
    binding_hash: HashDigest

    @model_validator(mode="after")
    def production_evidence_binding_is_finite_and_observed(
        self,
    ) -> ProductionResultEvidenceBinding:
        references = (
            self.execution_attempt_ref,
            self.bridge_ref,
            self.authenticated_result_ref,
            self.evidence_item_ref,
            self.production_event_ref,
            self.verification_event_ref,
        )
        if any(reference.tenant_id != self.tenant_id for reference in references):
            raise ValueError("all production evidence references must be tenant-bound")
        if self.classification is not Classification.OBSERVED:
            raise ValueError("authenticated production result evidence is observed")
        if self.valid_until <= self.valid_from:
            raise ValueError("production result verification must be finite")
        return self


class ProductionRequiredEvidenceEntry(AssuranceModel):
    """Exact frozen human-certified evidence used by production reconciliation."""

    requirement_control_key: NonEmptyString
    requirement_hash: HashDigest
    source_decision_ref: ObjectHashReference
    source_intent_ref: ObjectHashReference
    source_manifest_ref: ObjectHashReference
    applicability_hash: HashDigest
    evidence_kind: EvidenceKind
    classification: Classification
    evidence_item_ref: ObjectHashReference
    production_event_ref: ObjectHashReference
    certification_event_ref: ObjectHashReference
    verification_event_ref: ObjectHashReference
    certifier_grant_ref: ObjectHashReference
    producer: PrincipalIdentity
    certifier: PrincipalIdentity
    producer_lineage_ref: ObjectHashReference
    certifier_lineage_ref: ObjectHashReference
    verified_at: UtcTimestamp
    valid_from: UtcTimestamp
    valid_until: UtcTimestamp

    @model_validator(mode="after")
    def exact_required_evidence_is_tenant_bound_and_finite(
        self,
    ) -> ProductionRequiredEvidenceEntry:
        references = (
            self.evidence_item_ref,
            self.source_decision_ref,
            self.source_intent_ref,
            self.source_manifest_ref,
            self.production_event_ref,
            self.certification_event_ref,
            self.verification_event_ref,
            self.certifier_grant_ref,
            self.producer_lineage_ref,
            self.certifier_lineage_ref,
        )
        tenant_id = self.evidence_item_ref.tenant_id
        if (
            self.producer.tenant_id != tenant_id
            or self.certifier.tenant_id != tenant_id
            or any(reference.tenant_id != tenant_id for reference in references)
        ):
            raise ValueError("required production evidence must be tenant-bound")
        if self.certifier.principal_type is not PrincipalType.HUMAN:
            raise ValueError("required production evidence needs a human certifier")
        if self.valid_until <= self.valid_from:
            raise ValueError("required production evidence verification must be finite")
        return self


class ProductionAssuranceReceiptPayload(AssuranceModel):
    """Frozen production reconciliation facts; no caller-claimed assurance fields."""

    intent_ref: ObjectHashReference
    evaluation_manifest_ref: ObjectHashReference
    selected_specs: CanonicalSet[VersionedSpecReference]
    decision_ref: ObjectHashReference
    execution_attempt_ref: ObjectHashReference
    execution_record_ref: ObjectHashReference
    bridge_ref: ObjectHashReference
    target_authorization_ref: ObjectHashReference
    delivered_dispatch_ref: ObjectHashReference
    authenticated_result_ref: ObjectHashReference
    evidence_binding_refs: CanonicalSet[ObjectHashReference]
    required_evidence: CanonicalSet[ProductionRequiredEvidenceEntry]
    meter_event_refs: CanonicalSet[ObjectHashReference]
    assessor: PrincipalIdentity
    assessor_authority_grant_ref: ObjectHashReference
    assessor_lineage_ref: ObjectHashReference
    proposer_lineage_ref: ObjectHashReference
    executor_lineage_ref: ObjectHashReference
    actual_route: RouteId
    execution_outcome: ExecutionOutcome
    attempt_count: PositiveInt
    estimated_cost_reserved: Money
    observed_charge: Money
    realized_savings_minor_units: None = None
    financially_reconciled: Literal[False] = False
    correction_reason: NonEmptyString | None = None
    reopening_reason: NonEmptyString | None = None
    reversal_reason: NonEmptyString | None = None
    assurance_status: AssuranceStatus

    @model_validator(mode="after")
    def production_receipt_payload_is_tenant_bound_and_honest(
        self,
    ) -> ProductionAssuranceReceiptPayload:
        references = (
            self.intent_ref,
            self.evaluation_manifest_ref,
            self.decision_ref,
            self.execution_attempt_ref,
            self.execution_record_ref,
            self.bridge_ref,
            self.target_authorization_ref,
            self.delivered_dispatch_ref,
            self.authenticated_result_ref,
            self.assessor_authority_grant_ref,
            self.assessor_lineage_ref,
            self.proposer_lineage_ref,
            self.executor_lineage_ref,
            *self.evidence_binding_refs,
            *self.meter_event_refs,
        )
        tenant_id = self.intent_ref.tenant_id
        if (
            self.assessor.tenant_id != tenant_id
            or any(reference.tenant_id != tenant_id for reference in references)
            or any(spec.tenant_id != tenant_id for spec in self.selected_specs)
            or any(
                entry.evidence_item_ref.tenant_id != tenant_id
                for entry in self.required_evidence
            )
        ):
            raise ValueError("all production receipt payload references must be tenant-bound")
        if len(self.evidence_binding_refs) < 1 or len(self.meter_event_refs) != 2:
            raise ValueError("production receipt requires result evidence and exact meter facts")
        if (
            self.estimated_cost_reserved.currency != self.observed_charge.currency
            or self.estimated_cost_reserved.minor_units < 0
            or self.observed_charge.minor_units != 0
        ):
            raise ValueError("production receipt cannot claim reconciled financial effects")
        return self


class ProductionAssuranceReceipt(StoredObject):
    schema_name: Literal["ProductionAssuranceReceipt"]
    schema_version: SchemaVersion
    receipt_kind: ReceiptKind
    sequence: PositiveInt
    payload: ProductionAssuranceReceiptPayload
    predecessor_receipt_ref: ObjectHashReference | None
    superseded_receipt_ref: ObjectHashReference | None
    receipt_hash: HashDigest

    @model_validator(mode="after")
    def production_receipt_transition_shape(self) -> ProductionAssuranceReceipt:
        predecessor = self.predecessor_receipt_ref
        superseded = self.superseded_receipt_ref
        if self.receipt_kind is ReceiptKind.INITIAL:
            if self.sequence != 1 or predecessor is not None or superseded is not None:
                raise ValueError("an initial production receipt starts the stream")
        elif (
            self.sequence <= 1
            or predecessor is None
            or predecessor != superseded
            or predecessor.tenant_id != self.tenant_id
        ):
            raise ValueError("a later production receipt exactly supersedes its predecessor")
        reasons = (
            self.payload.correction_reason,
            self.payload.reopening_reason,
            self.payload.reversal_reason,
        )
        expected_index = {
            ReceiptKind.CORRECTION: 0,
            ReceiptKind.REOPENING: 1,
            ReceiptKind.REVERSAL: 2,
        }.get(self.receipt_kind)
        if expected_index is None:
            if any(reason is not None for reason in reasons):
                raise ValueError("an initial production receipt has no correction reason")
        elif reasons[expected_index] is None or sum(reason is not None for reason in reasons) != 1:
            raise ValueError("exactly the applicable production receipt reason is required")
        return self


class ProductionReconciliationSnapshot(StoredObject):
    """Immutable facts used to reproduce one production receipt."""

    schema_name: Literal["ProductionReconciliationSnapshot"]
    schema_version: SchemaVersion
    receipt_ref: ObjectHashReference
    execution_attempt_ref: ObjectHashReference
    bridge_ref: ObjectHashReference
    evidence_binding_refs: CanonicalSet[ObjectHashReference]
    required_evidence: CanonicalSet[ProductionRequiredEvidenceEntry]
    assessor: PrincipalIdentity
    assessor_authority_grant_ref: ObjectHashReference
    assessor_lineage_ref: ObjectHashReference
    proposer_lineage_ref: ObjectHashReference
    executor_lineage_ref: ObjectHashReference
    command_request_hash: HashDigest
    canonicalizer_version: NonEmptyString
    evaluator_build_id: NonEmptyString
    policy_algebra_version: NonEmptyString
    estimated_cost_reserved: Money
    observed_charge: Money
    realized_savings_minor_units: None = None
    financially_reconciled: Literal[False] = False
    snapshot_hash: HashDigest

    @model_validator(mode="after")
    def reconciliation_snapshot_is_tenant_bound_and_honest(
        self,
    ) -> ProductionReconciliationSnapshot:
        references = (
            self.receipt_ref,
            self.execution_attempt_ref,
            self.bridge_ref,
            self.assessor_authority_grant_ref,
            self.assessor_lineage_ref,
            self.proposer_lineage_ref,
            self.executor_lineage_ref,
            *self.evidence_binding_refs,
        )
        if self.assessor.tenant_id != self.tenant_id or any(
            reference.tenant_id != self.tenant_id for reference in references
        ) or any(
            entry.evidence_item_ref.tenant_id != self.tenant_id
            for entry in self.required_evidence
        ):
            raise ValueError("all reconciliation snapshot references must be tenant-bound")
        if (
            not self.evidence_binding_refs
            or self.estimated_cost_reserved.currency != self.observed_charge.currency
            or self.estimated_cost_reserved.minor_units < 0
            or self.observed_charge.minor_units != 0
        ):
            raise ValueError("reconciliation snapshot must preserve result and economic truth")
        return self


class ProductionReceiptStreamEvent(StoredObject):
    schema_name: Literal["ProductionReceiptStreamEvent"]
    schema_version: SchemaVersion
    execution_attempt_ref: ObjectHashReference
    receipt_ref: ObjectHashReference
    sequence: PositiveInt
    predecessor_event_ref: ObjectHashReference | None
    predecessor_receipt_ref: ObjectHashReference | None
    event_hash: HashDigest

    @model_validator(mode="after")
    def receipt_stream_event_is_exact(self) -> ProductionReceiptStreamEvent:
        refs = (self.execution_attempt_ref, self.receipt_ref)
        if any(reference.tenant_id != self.tenant_id for reference in refs):
            raise ValueError("production receipt stream references must be tenant-bound")
        if self.sequence == 1:
            if self.predecessor_event_ref is not None or self.predecessor_receipt_ref is not None:
                raise ValueError("first production receipt stream event has no predecessor")
        elif (
            self.predecessor_event_ref is None
            or self.predecessor_receipt_ref is None
            or self.predecessor_event_ref.tenant_id != self.tenant_id
            or self.predecessor_receipt_ref.tenant_id != self.tenant_id
        ):
            raise ValueError("later production receipt stream event requires exact predecessors")
        return self


class EvidenceReceiptEntry(AssuranceModel):
    evidence_item_ref: ObjectHashReference
    production_event_ref: ObjectHashReference
    certification_event_refs: CanonicalSet[ObjectHashReference]
    verification_event_refs: CanonicalSet[ObjectHashReference]


class AssuranceReceiptPayload(AssuranceModel):
    intent_ref: ObjectHashReference
    decision_ref: ObjectHashReference
    selected_specs: CanonicalSet[VersionedSpecReference]
    approval_refs: CanonicalSet[ObjectHashReference]
    override_refs: CanonicalSet[ObjectHashReference]
    actual_route: RouteId | None
    execution_ref: ObjectHashReference
    execution_outcome: ExecutionOutcome
    required_control_keys: CanonicalSet[NonEmptyString]
    supplied_evidence: CanonicalSet[EvidenceReceiptEntry]
    observed_cost: Money
    attempt_number: PositiveInt
    human_intervention_refs: CanonicalSet[ObjectHashReference]
    reopening_reason: NonEmptyString | None
    reversal_reason: NonEmptyString | None
    assurance_status: AssuranceStatus


class AssuranceReceipt(StoredObject):
    schema_name: Literal["AssuranceReceipt"]
    schema_version: SchemaVersion
    receipt_kind: ReceiptKind
    payload: AssuranceReceiptPayload
    predecessor_receipt_ref: ObjectHashReference | None
    superseded_receipt_ref: ObjectHashReference | None
    receipt_hash: HashDigest


class WorkflowActionIntent(ActionIntent):
    """Schema-version 2 intent for a protected workflow.

    The v1 ``ActionIntent`` remains available for retained change-0001 replay.
    """

    schema_version: Literal[2]  # type: ignore[assignment]
    source_event_ref: ObjectHashReference
    workflow_ref: ObjectHashReference
    published_action_mapping_ref: VersionedComponentReference
    inbound_connector_ref: VersionedComponentReference
    accepted_canonical_action_decision_ref: ObjectHashReference

    @model_validator(mode="after")
    def workflow_intent_links_are_tenant_bound(self) -> WorkflowActionIntent:
        refs: list[ObjectHashReference | VersionedComponentReference] = [
            self.source_event_ref,
            self.workflow_ref,
            self.published_action_mapping_ref,
            self.inbound_connector_ref,
            self.accepted_canonical_action_decision_ref,
        ]
        if any(ref.tenant_id != self.tenant_id for ref in refs):
            raise ValueError("all protected-workflow intent links must be tenant-bound")
        return self


class WorkflowEvaluationInputManifest(EvaluationInputManifest):
    """Schema-version 2 exact evaluation snapshot for protected workflows."""

    schema_version: Literal[2]  # type: ignore[assignment]
    workflow_ref: ObjectHashReference
    deployment_ref: VersionedComponentReference
    enforcement_point_ref: VersionedComponentReference
    action_mapping_refs: Annotated[
        CanonicalSet[VersionedComponentReference],
        Field(min_length=1),
    ]
    outcome_evidence_mapping_refs: Annotated[
        CanonicalSet[VersionedComponentReference],
        Field(min_length=1),
    ]
    connector_refs: Annotated[
        CanonicalSet[VersionedComponentReference],
        Field(min_length=1),
    ]
    protected_target_registry_ref: ObjectHashReference
    mode_transition_ref: ObjectHashReference
    mode_head: StreamHead
    readiness_report_ref: ObjectHashReference
    policy_coverage_ref: ObjectHashReference
    policy_set_digest: HashDigest
    applicability_query_head_refs: CanonicalSet[ObjectHashReference]
    component_lifecycle_event_refs: CanonicalSet[ObjectHashReference]
    connector_health_event_refs: CanonicalSet[ObjectHashReference]
    deployment_approval_refs: CanonicalSet[ObjectHashReference]
    readiness_exception_refs: CanonicalSet[ObjectHashReference]

    @model_validator(mode="after")
    def workflow_manifest_links_are_tenant_bound(
        self,
    ) -> WorkflowEvaluationInputManifest:
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
            any(ref.tenant_id != self.tenant_id for ref in object_refs)
            or any(ref.tenant_id != self.tenant_id for ref in component_refs)
            or self.mode_head.tenant_id != self.tenant_id
        ):
            raise ValueError("all protected-workflow manifest links must be tenant-bound")
        return self


class WorkflowDecisionProjection(AssuranceModel):
    workflow_ref: ObjectHashReference
    deployment_ref: VersionedComponentReference
    enforcement_point_ref: VersionedComponentReference
    policy_coverage_ref: ObjectHashReference
    mode_head: StreamHead


class WorkflowControlDecision(ControlDecision):
    """Schema-version 2 decision binding; semantic verdict remains unchanged."""

    schema_version: Literal[2]  # type: ignore[assignment]
    workflow_projection: WorkflowDecisionProjection

    @model_validator(mode="after")
    def workflow_decision_links_are_tenant_bound(self) -> WorkflowControlDecision:
        projection = self.workflow_projection
        tenants = {
            projection.workflow_ref.tenant_id,
            projection.deployment_ref.tenant_id,
            projection.enforcement_point_ref.tenant_id,
            projection.policy_coverage_ref.tenant_id,
            projection.mode_head.tenant_id,
        }
        if tenants != {self.tenant_id}:
            raise ValueError("all protected-workflow decision links must be tenant-bound")
        return self


class TargetAuthorizationBinding(AssuranceModel):
    authorization_ref: ObjectHashReference
    target_connector_ref: VersionedComponentReference
    target_registry_ref: ObjectHashReference
    key_id: NonEmptyString
    nonce_hash: HashDigest
    expires_at: UtcTimestamp


class WorkflowExecutionRecord(ExecutionRecord):
    schema_version: Literal[2]  # type: ignore[assignment]
    source_event_ref: ObjectHashReference
    workflow_ref: ObjectHashReference
    deployment_ref: VersionedComponentReference
    enforcement_point_ref: VersionedComponentReference
    action_mapping_ref: VersionedComponentReference
    outcome_mapping_ref: VersionedComponentReference
    target_authorization: TargetAuthorizationBinding | None
    requested_route: RouteId
    enforcement_disposition: EnforcementDisposition
    revalidation_codes: CanonicalSet[ReadinessCode]
    mode_head: StreamHead
    target_result_ref: ObjectHashReference | None

    @model_validator(mode="after")
    def workflow_execution_links_are_tenant_bound(self) -> WorkflowExecutionRecord:
        refs: list[ObjectHashReference | VersionedComponentReference] = [
            self.source_event_ref,
            self.workflow_ref,
            self.deployment_ref,
            self.enforcement_point_ref,
            self.action_mapping_ref,
            self.outcome_mapping_ref,
        ]
        if self.target_authorization is not None:
            refs.extend(
                [
                    self.target_authorization.authorization_ref,
                    self.target_authorization.target_connector_ref,
                    self.target_authorization.target_registry_ref,
                ]
            )
        if self.target_result_ref is not None:
            refs.append(self.target_result_ref)
        if (
            any(ref.tenant_id != self.tenant_id for ref in refs)
            or self.mode_head.tenant_id != self.tenant_id
        ):
            raise ValueError("all protected-workflow execution links must be tenant-bound")
        return self


class WorkflowAssuranceReceiptPayload(AssuranceReceiptPayload):
    workflow_ref: ObjectHashReference
    deployment_ref: VersionedComponentReference
    enforcement_point_ref: VersionedComponentReference
    action_mapping_ref: VersionedComponentReference
    outcome_mapping_ref: VersionedComponentReference
    source_event_ref: ObjectHashReference
    evaluation_manifest_ref: ObjectHashReference
    policy_coverage_ref: ObjectHashReference
    policy_set_digest: HashDigest
    requested_route: RouteId
    readiness_exception_refs: CanonicalSet[ObjectHashReference]
    authenticated_outcome_ref: ObjectHashReference | None
    connector_refs: CanonicalSet[VersionedComponentReference]
    mode_head: StreamHead


class WorkflowAssuranceReceipt(AssuranceReceipt):
    schema_version: Literal[2]  # type: ignore[assignment]
    payload: WorkflowAssuranceReceiptPayload

    @model_validator(mode="after")
    def workflow_receipt_links_are_tenant_bound(self) -> WorkflowAssuranceReceipt:
        payload = self.payload
        refs: list[ObjectHashReference | VersionedComponentReference] = [
            payload.workflow_ref,
            payload.deployment_ref,
            payload.enforcement_point_ref,
            payload.action_mapping_ref,
            payload.outcome_mapping_ref,
            payload.source_event_ref,
            payload.evaluation_manifest_ref,
            payload.policy_coverage_ref,
            *payload.readiness_exception_refs,
            *payload.connector_refs,
        ]
        if (
            any(ref.tenant_id != self.tenant_id for ref in refs)
            or payload.mode_head.tenant_id != self.tenant_id
        ):
            raise ValueError("all protected-workflow receipt links must be tenant-bound")
        return self
