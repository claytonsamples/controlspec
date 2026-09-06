"""Closed versioned data AST from design decision D-001.

The module defines data only. It intentionally contains no predicate evaluator,
composition reducer, verdict selection, or policy decision.
"""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StrictBool, model_validator

from assurance.contracts.common import (
    AssuranceModel,
    AuthorityOperation,
    CanonicalSet,
    CurrencyCode,
    HashDigest,
    NonEmptyString,
    NonNegativeInt,
    PositiveInt,
    TypedValue,
)
from assurance.domain import (
    AuthorityRole,
    CanonicalAction,
    Classification,
    DomainVerb,
    EconomicMetric,
    EvidenceKind,
    FieldPath,
    NonPermissiveEffect,
    PredicateOperator,
    PrincipalType,
    ResourceType,
    RouteId,
    SubjectRole,
)


class SourceFragmentTrace(AssuranceModel):
    trace_type: Literal["SOURCE_FRAGMENT"] = "SOURCE_FRAGMENT"
    fragment_id: UUID
    fragment_hash: HashDigest


class HumanDecisionTrace(AssuranceModel):
    trace_type: Literal["HUMAN_DECISION"] = "HUMAN_DECISION"
    decision_id: UUID
    decision_hash: HashDigest


TraceRef = Annotated[SourceFragmentTrace | HumanDecisionTrace, Field(discriminator="trace_type")]


class EqPredicate(AssuranceModel):
    operator: Literal[PredicateOperator.EQ] = PredicateOperator.EQ
    field_path: FieldPath
    value: TypedValue


class InPredicate(AssuranceModel):
    operator: Literal[PredicateOperator.IN] = PredicateOperator.IN
    field_path: FieldPath
    values: Annotated[CanonicalSet[TypedValue], Field(min_length=1)]


class ComparisonPredicate(AssuranceModel):
    operator: Literal[
        PredicateOperator.LT,
        PredicateOperator.LTE,
        PredicateOperator.GT,
        PredicateOperator.GTE,
    ]
    field_path: FieldPath
    value: TypedValue


class ExistsPredicate(AssuranceModel):
    operator: Literal[PredicateOperator.EXISTS] = PredicateOperator.EXISTS
    field_path: FieldPath
    expected: StrictBool


Predicate = Annotated[
    EqPredicate | InPredicate | ComparisonPredicate | ExistsPredicate,
    Field(discriminator="operator"),
]


class BlockEffect(AssuranceModel):
    effect: Literal[NonPermissiveEffect.BLOCK] = NonPermissiveEffect.BLOCK


class RequireApprovalEffect(AssuranceModel):
    effect: Literal[NonPermissiveEffect.REQUIRE_APPROVAL] = (
        NonPermissiveEffect.REQUIRE_APPROVAL
    )


class SwitchRouteEffect(AssuranceModel):
    effect: Literal[NonPermissiveEffect.SWITCH_ROUTE] = NonPermissiveEffect.SWITCH_ROUTE
    target_routes: Annotated[CanonicalSet[RouteId], Field(min_length=1)]


NonPermissiveEffectSpec = Annotated[
    BlockEffect | RequireApprovalEffect | SwitchRouteEffect,
    Field(discriminator="effect"),
]


class RequirementBase(AssuranceModel):
    control_key: NonEmptyString
    trace_refs: Annotated[CanonicalSet[TraceRef], Field(min_length=1)]
    failure_effect: NonPermissiveEffectSpec


class EvidenceRequirement(RequirementBase):
    requirement_type: Literal["EVIDENCE"] = "EVIDENCE"
    verifier: Literal["EVIDENCE_VALID"] = "EVIDENCE_VALID"
    evidence_kind: EvidenceKind
    subject_role: SubjectRole
    minimum_count: PositiveInt
    max_age_seconds: NonNegativeInt | None
    required_classification: Classification
    require_producer_certifier_separation: StrictBool


class ApprovalRequirement(RequirementBase):
    requirement_type: Literal["APPROVAL"] = "APPROVAL"
    verifier: Literal["APPROVAL_VALID"] = "APPROVAL_VALID"
    role: AuthorityRole
    scope_key: NonEmptyString
    minimum_count: PositiveInt
    validity_seconds: PositiveInt | None
    separate_from: CanonicalSet[SubjectRole]


class AuthorityRequirement(RequirementBase):
    requirement_type: Literal["AUTHORITY"] = "AUTHORITY"
    verifier: Literal["AUTHORITY_VALID"] = "AUTHORITY_VALID"
    role: AuthorityRole
    scope_key: NonEmptyString
    validity_seconds: PositiveInt | None


class SelectedRouteAuthorityRequirement(RequirementBase):
    """Authority evaluated only for one policy-selected alternate route."""

    requirement_type: Literal["SELECTED_ROUTE_AUTHORITY"] = (
        "SELECTED_ROUTE_AUTHORITY"
    )
    verifier: Literal["AUTHORITY_VALID_FOR_SELECTED_ROUTE"] = (
        "AUTHORITY_VALID_FOR_SELECTED_ROUTE"
    )
    role: AuthorityRole
    scope_key: NonEmptyString
    authority_policy_module: NonEmptyString
    operation: AuthorityOperation
    validity_seconds: PositiveInt | None


class IndependenceRequirement(RequirementBase):
    requirement_type: Literal["INDEPENDENCE"] = "INDEPENDENCE"
    verifier: Literal["INDEPENDENCE_DOMAINS_DIFFER"] = "INDEPENDENCE_DOMAINS_DIFFER"
    subject_roles: Annotated[CanonicalSet[SubjectRole], Field(min_length=2)]


class ContextAssertionRequirement(RequirementBase):
    requirement_type: Literal["CONTEXT_ASSERTION"] = "CONTEXT_ASSERTION"
    verifier: Literal["CONTEXT_FACT_TRUE"] = "CONTEXT_FACT_TRUE"
    field_path: FieldPath
    expected_value: TypedValue


Requirement = Annotated[
    EvidenceRequirement
    | ApprovalRequirement
    | AuthorityRequirement
    | IndependenceRequirement
    | ContextAssertionRequirement,
    Field(discriminator="requirement_type"),
]


RiskSpecV3Requirement = Annotated[
    EvidenceRequirement
    | ApprovalRequirement
    | AuthorityRequirement
    | SelectedRouteAuthorityRequirement
    | IndependenceRequirement
    | ContextAssertionRequirement,
    Field(discriminator="requirement_type"),
]


class Prohibition(AssuranceModel):
    prohibition_key: NonEmptyString
    when: Annotated[CanonicalSet[Predicate], Field(min_length=1)]
    code: NonEmptyString
    on_unknown: NonPermissiveEffectSpec
    trace_refs: Annotated[CanonicalSet[TraceRef], Field(min_length=1)]


class AllowSetConstraint(AssuranceModel):
    constraint_type: Literal["ALLOW_SET"] = "ALLOW_SET"
    routes: Annotated[CanonicalSet[RouteId], Field(min_length=1)]
    trace_refs: Annotated[CanonicalSet[TraceRef], Field(min_length=1)]


class DenySetConstraint(AssuranceModel):
    constraint_type: Literal["DENY_SET"] = "DENY_SET"
    routes: Annotated[CanonicalSet[RouteId], Field(min_length=1)]
    trace_refs: Annotated[CanonicalSet[TraceRef], Field(min_length=1)]


RouteConstraint = Annotated[
    AllowSetConstraint | DenySetConstraint,
    Field(discriminator="constraint_type"),
]


class RouteCondition(AssuranceModel):
    condition_type: Literal["ROUTE"] = "ROUTE"
    verifier: Literal["ROUTE_IS_ALLOWED"] = "ROUTE_IS_ALLOWED"
    control_key: NonEmptyString
    permitted_routes: Annotated[CanonicalSet[RouteId], Field(min_length=1)]
    trace_refs: Annotated[CanonicalSet[TraceRef], Field(min_length=1)]


class ApprovalCondition(AssuranceModel):
    condition_type: Literal["APPROVAL"] = "APPROVAL"
    verifier: Literal["APPROVAL_VALID"] = "APPROVAL_VALID"
    control_key: NonEmptyString
    role: AuthorityRole
    trace_refs: Annotated[CanonicalSet[TraceRef], Field(min_length=1)]


class EvidenceCondition(AssuranceModel):
    condition_type: Literal["EVIDENCE"] = "EVIDENCE"
    verifier: Literal["EVIDENCE_VALID"] = "EVIDENCE_VALID"
    control_key: NonEmptyString
    evidence_kind: EvidenceKind
    trace_refs: Annotated[CanonicalSet[TraceRef], Field(min_length=1)]


class PostActionVerificationCondition(AssuranceModel):
    condition_type: Literal["POST_ACTION_VERIFICATION"] = "POST_ACTION_VERIFICATION"
    verifier: Literal["POST_ACTION_EVIDENCE_VERIFIED"] = "POST_ACTION_EVIDENCE_VERIFIED"
    control_key: NonEmptyString
    evidence_kind: EvidenceKind
    trace_refs: Annotated[CanonicalSet[TraceRef], Field(min_length=1)]


Condition = Annotated[
    RouteCondition | ApprovalCondition | EvidenceCondition | PostActionVerificationCondition,
    Field(discriminator="condition_type"),
]


class EconomicCap(AssuranceModel):
    cap_key: NonEmptyString
    meter_id: NonEmptyString
    metric: EconomicMetric
    limit: NonNegativeInt
    boundary: Literal[PredicateOperator.LT, PredicateOperator.LTE]
    currency: CurrencyCode | None
    breach_effect: NonPermissiveEffectSpec
    trace_refs: Annotated[CanonicalSet[TraceRef], Field(min_length=1)]

    @model_validator(mode="after")
    def currency_matches_metric(self) -> EconomicCap:
        if self.metric is EconomicMetric.COST_MINOR_UNITS and self.currency is None:
            raise ValueError("currency is required for COST_MINOR_UNITS")
        if self.metric is EconomicMetric.ATTEMPT_COUNT and self.currency is not None:
            raise ValueError("currency is forbidden for ATTEMPT_COUNT")
        return self


class CoverageKey(AssuranceModel):
    canonical_action: CanonicalAction
    domain_verb: DomainVerb
    resource_type: ResourceType
    principal_type: PrincipalType
    policy_namespace: NonEmptyString | None


class Rule(AssuranceModel):
    rule_key: NonEmptyString
    when: CanonicalSet[Predicate]
    on_unknown: NonPermissiveEffectSpec
    requirements: CanonicalSet[Requirement]
    prohibitions: CanonicalSet[Prohibition]
    route_constraints: CanonicalSet[RouteConstraint]
    conditions: CanonicalSet[Condition]
    economic_caps: CanonicalSet[EconomicCap]
    trace_refs: Annotated[CanonicalSet[TraceRef], Field(min_length=1)]


class PolicyModule(AssuranceModel):
    algebra_name: Literal["D-001"] = "D-001"
    algebra_version: Literal[1] = 1
    module_key: NonEmptyString
    coverage: CoverageKey
    rules: Annotated[CanonicalSet[Rule], Field(min_length=1)]


class RiskSpecV3Rule(AssuranceModel):
    """Additive schema-v3 rule preserving the exact legacy rule field surface."""

    rule_key: NonEmptyString
    when: CanonicalSet[Predicate]
    on_unknown: NonPermissiveEffectSpec
    requirements: CanonicalSet[RiskSpecV3Requirement]
    prohibitions: CanonicalSet[Prohibition]
    route_constraints: CanonicalSet[RouteConstraint]
    conditions: CanonicalSet[Condition]
    economic_caps: CanonicalSet[EconomicCap]
    trace_refs: Annotated[CanonicalSet[TraceRef], Field(min_length=1)]


class PolicyModuleV3(AssuranceModel):
    """Additive schema-v3 module; legacy PolicyModule remains byte-exact."""

    algebra_name: Literal["D-001"] = "D-001"
    algebra_version: Literal[1] = 1
    module_key: NonEmptyString
    coverage: CoverageKey
    rules: Annotated[CanonicalSet[RiskSpecV3Rule], Field(min_length=1)]
