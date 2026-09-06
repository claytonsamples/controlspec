"""Closed ControlSpec v0 shapes with open, explicitly namespaced vocabularies."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, ClassVar, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    model_validator,
)

from assurance.contracts.canonical import canonical_json, sha256_digest

NonEmptyString = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=256)]
Identifier = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=128)]
def _validate_semver(value: str) -> str:
    parts = value.split("+", maxsplit=1)
    public = parts[0]
    if len(parts) == 2 and any(not identifier for identifier in parts[1].split(".")):
        raise ValueError("SemVer build identifiers cannot be empty")
    if "-" not in public:
        return value
    prerelease = public.split("-", maxsplit=1)[1]
    identifiers = prerelease.split(".")
    if any(
        not identifier
        or (identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"))
        for identifier in identifiers
    ):
        raise ValueError("SemVer prerelease identifiers cannot be empty or zero-padded")
    return value


SemVer = Annotated[
    str,
    StringConstraints(
        strict=True,
        pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$",
    ),
    AfterValidator(_validate_semver),
]
Namespace = Annotated[
    str, StringConstraints(strict=True, pattern=r"^[a-z][a-z0-9]*(?:[.-][a-z][a-z0-9_-]*)+$")
]
NamespacedValue = Namespace
HashDigest = Annotated[str, StringConstraints(strict=True, pattern=r"^sha256:[0-9a-f]{64}$")]
def _validate_timestamp(value: str) -> str:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise ValueError("timestamp must be a real canonical UTC instant") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise ValueError("timestamp must use six fractional digits and uppercase Z")
    return value


UtcTimestamp = Annotated[
    str,
    StringConstraints(
        strict=True, pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
    ),
    AfterValidator(_validate_timestamp),
]


def _reject_noncanonical_json(value: Any) -> Any:
    if isinstance(value, float):
        raise ValueError("floating-point values are forbidden")
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and (value < -(2**63) or value > 2**63 - 1)
    ):
        raise ValueError("integers must fit the signed 64-bit canonical profile")
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        for item in value.values():
            _reject_noncanonical_json(item)
    elif isinstance(value, list | tuple):
        for item in value:
            _reject_noncanonical_json(item)
    elif value is not None and not isinstance(value, str | int | bool | BaseModel):
        raise ValueError("values must use the portable JSON scalar and container types")
    return value


def _portable_json(value: Any) -> Any:
    if isinstance(value, BaseModel):
        raise ValueError("portable JSON values cannot embed executable or typed model objects")
    if isinstance(value, dict):
        for item in value.values():
            _portable_json(item)
    elif isinstance(value, list | tuple):
        for item in value:
            _portable_json(item)
    return _reject_noncanonical_json(value)


SignedInteger = Annotated[StrictInt, Field(ge=-(2**63), le=2**63 - 1)]
type JsonValue = Annotated[
    StrictBool
    | SignedInteger
    | str
    | list[JsonValue]
    | dict[str, JsonValue]
    | None,
    BeforeValidator(_portable_json),
]


def _canonical_set(value: Any) -> Any:
    if not isinstance(value, list | tuple):
        raise ValueError("canonical sets must be arrays")
    keyed = [(canonical_json(_reject_noncanonical_json(item)), item) for item in value]
    keys = [key for key, _ in keyed]
    if len(keys) != len(set(keys)):
        raise ValueError("canonical sets reject duplicate members")
    return tuple(item for _, item in sorted(keyed, key=lambda pair: pair[0]))


type CanonicalSet[T] = Annotated[tuple[T, ...], BeforeValidator(_canonical_set)]


class ControlSpecModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        validate_by_alias=True,
        validate_by_name=True,
    )

    @model_validator(mode="before")
    @classmethod
    def canonical_json_types_only(cls, value: Any) -> Any:
        return _reject_noncanonical_json(value)


class ObjectRef(ControlSpecModel):
    namespace: Namespace
    object_type: NamespacedValue
    object_id: Identifier
    version: NonEmptyString | None
    digest: HashDigest | None


class ActorRef(ControlSpecModel):
    namespace: Namespace
    actor_id: Identifier
    version: NonEmptyString


class ResourceRef(ControlSpecModel):
    namespace: Namespace
    resource_id: Identifier
    version: NonEmptyString
    type: NamespacedValue


class ControlRef(ControlSpecModel):
    namespace: Namespace
    control_id: Identifier
    version: SemVer
    semantic_digest: HashDigest


class IntentRef(ControlSpecModel):
    namespace: Namespace
    intent_id: Identifier
    intent_digest: HashDigest


class DecisionRef(ControlSpecModel):
    namespace: Namespace
    decision_id: Identifier
    semantic_digest: HashDigest


class ControlPackRef(ControlSpecModel):
    namespace: Namespace
    pack_id: Identifier
    version: SemVer
    semantic_digest: HashDigest


class EvidenceRef(ControlSpecModel):
    namespace: Namespace
    evidence_id: Identifier
    digest: HashDigest
    kind: NamespacedValue


class SourceReference(ControlSpecModel):
    source_type: NamespacedValue
    locator: NonEmptyString
    captured_digest: HashDigest


class Amount(ControlSpecModel):
    currency: Annotated[str, StringConstraints(strict=True, pattern=r"^[A-Z]{3}$")]
    minor_units: StrictInt


class CanonicalAction(StrEnum):
    OBSERVE = "observe"
    INFER = "infer"
    COMMUNICATE = "communicate"
    MODIFY = "modify"
    COMMIT = "commit"
    TRANSFER = "transfer"
    DELEGATE = "delegate"


class ActorType(StrEnum):
    AGENT = "agent"
    HUMAN = "human"
    SERVICE = "service"
    WORKFLOW = "workflow"
    APPLICATION = "application"
    ORGANIZATION = "organization"


class ControlStatus(StrEnum):
    DRAFT = "draft"
    PUBLISHED = "published"
    RETIRED = "retired"


class Verdict(StrEnum):
    ALLOW = "allow"
    ALLOW_WITH_CONDITIONS = "allow_with_conditions"
    REQUIRE_APPROVAL = "require_approval"
    ROUTE = "route"
    BLOCK = "block"
    CONFLICT = "conflict"


class CoreRouteKind(StrEnum):
    CONTINUE = "continue"
    ASK_USER = "ask_user"
    HUMAN_REVIEW = "human_review"
    SPECIALIST_AGENT = "specialist_agent"
    DIFFERENT_MODEL = "different_model"
    REDACT_THEN_CONTINUE = "redact_then_continue"
    NARROW_ACTION = "narrow_action"
    BLOCK = "block"
    RECORD_ONLY = "record_only"


class ReceiptOutcome(StrEnum):
    COMPLETED = "completed"
    BLOCKED = "blocked"
    APPROVED = "approved"
    REJECTED = "rejected"
    INCOMPLETE = "incomplete"
    FAILED = "failed"
    REVERSED = "reversed"
    PENDING = "pending"


class ReceiptStatus(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


class ExecutionOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ABORTED = "aborted"
    NOT_EXECUTED = "not_executed"


class ExtensionBearing(ControlSpecModel):
    schema_name: NonEmptyString = Field(alias="schema")
    schema_version: Literal["0.1.0"] = "0.1.0"
    namespace: Namespace
    extensions: dict[NamespacedValue, JsonValue] = Field(default_factory=dict)
    digest_field: ClassVar[str]


class Actor(ExtensionBearing):
    schema_name: Literal["controlspec/v0/actor"] = Field("controlspec/v0/actor", alias="schema")
    actor_id: Identifier
    version: NonEmptyString
    type: ActorType
    owner_ref: ObjectRef | None
    lineage_refs: CanonicalSet[ObjectRef]
    attributes: dict[str, JsonValue]
    digest_field: ClassVar[str] = ""


class Resource(ExtensionBearing):
    schema_name: Literal["controlspec/v0/resource"] = Field(
        "controlspec/v0/resource", alias="schema"
    )
    resource_id: Identifier
    version: NonEmptyString
    type: NamespacedValue
    business_id: NonEmptyString | None
    display_name: NonEmptyString | None = None
    attributes: dict[str, JsonValue]
    digest_field: ClassVar[str] = ""


class Action(ControlSpecModel):
    type: CanonicalAction
    domain_action: NamespacedValue
    requested_effect: JsonValue


class Route(ExtensionBearing):
    schema_name: Literal["controlspec/v0/route"] = Field("controlspec/v0/route", alias="schema")
    route_id: Identifier
    kind: CoreRouteKind | NamespacedValue
    target_ref: ObjectRef | None
    parameters: dict[NamespacedValue, JsonValue]
    requires_recheck: StrictBool
    digest_field: ClassVar[str] = ""


class ActionIntent(ExtensionBearing):
    schema_name: Literal["controlspec/v0/action-intent"] = Field(
        "controlspec/v0/action-intent", alias="schema"
    )
    intent_id: Identifier
    actor: Actor
    action: Action
    resource: Resource
    context: dict[NamespacedValue, JsonValue]
    requested_route: Route | None
    evidence_refs: CanonicalSet[EvidenceRef]
    cost: Amount | None
    retry_count: Annotated[StrictInt, Field(ge=0)] | None
    requested_at: UtcTimestamp
    idempotency_key: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=128)]
    context_digest: HashDigest
    intent_digest: HashDigest | None = None
    digest_field: ClassVar[str] = "intent_digest"

    @model_validator(mode="after")
    def binds_exact_context(self) -> ActionIntent:
        if sha256_digest(canonical_json(self.context)) != self.context_digest:
            raise ValueError("context_digest must bind the exact canonical context")
        return self


class Predicate(ControlSpecModel):
    operator: Literal["eq", "in", "lt", "lte", "gt", "gte", "exists"]
    path: Annotated[
        str, StringConstraints(strict=True, pattern=r"^/(actor|action|resource|context)(/.*)?$")
    ]
    value: JsonValue | None = None
    values: CanonicalSet[JsonValue] = ()
    expected: StrictBool | None = None

    @model_validator(mode="after")
    def operator_shape(self) -> Predicate:
        if self.operator == "in":
            if not self.values or self.value is not None or self.expected is not None:
                raise ValueError("in requires only non-empty values")
        elif self.operator == "exists":
            if self.expected is None or self.value is not None or self.values:
                raise ValueError("exists requires only expected")
        elif self.value is None or self.values or self.expected is not None:
            raise ValueError("comparison predicates require only value")
        return self


class FailureEffect(ControlSpecModel):
    verdict: Literal["require_approval", "route", "block"]
    route: Route | None
    code: NamespacedValue

    @model_validator(mode="after")
    def route_matches_verdict(self) -> FailureEffect:
        if self.verdict == "route" and self.route is None:
            raise ValueError("route failure requires a route")
        if self.verdict == "block" and (
            self.route is None or self.route.kind != CoreRouteKind.BLOCK
        ):
            raise ValueError("block failure requires a block route")
        if self.verdict == "require_approval" and self.route is not None:
            raise ValueError("require_approval failure cannot select a route")
        return self


class RequirementBase(ControlSpecModel):
    requirement_id: Identifier
    failure: FailureEffect


class EvidenceSeparation(ControlSpecModel):
    producer_not_actor: StrictBool
    certifier_not_actor: StrictBool
    producer_certifier_distinct: StrictBool


class EvidenceRequirement(RequirementBase):
    requirement_type: Literal["evidence"] = "evidence"
    kind: NamespacedValue
    subject: NamespacedValue
    minimum_count: Annotated[StrictInt, Field(gt=0)]
    max_age_seconds: Annotated[StrictInt, Field(ge=0)] | None
    verifier: NamespacedValue
    separation: EvidenceSeparation


class ApprovalRequirement(RequirementBase):
    requirement_type: Literal["approval"] = "approval"
    role: NamespacedValue
    scope: dict[NamespacedValue, JsonValue]
    minimum_count: Annotated[StrictInt, Field(gt=0)]
    validity_seconds: Annotated[StrictInt, Field(gt=0)] | None
    separate_from_actor: StrictBool
    separate_from_roles: CanonicalSet[NamespacedValue]


class ProfileRequirement(RequirementBase):
    requirement_type: Literal["profile"] = "profile"
    verifier: NamespacedValue
    parameters: dict[NamespacedValue, JsonValue]


type Requirement = Annotated[
    EvidenceRequirement | ApprovalRequirement | ProfileRequirement,
    Field(discriminator="requirement_type"),
]


class Condition(ControlSpecModel):
    condition_id: Identifier
    verifier: NamespacedValue
    parameters: dict[NamespacedValue, JsonValue]
    failure: FailureEffect


class ControlMatch(ControlSpecModel):
    actor_types: Annotated[CanonicalSet[ActorType], Field(min_length=1)]
    action_types: Annotated[CanonicalSet[CanonicalAction], Field(min_length=1)]
    domain_actions: Annotated[CanonicalSet[NamespacedValue], Field(min_length=1)]
    resource_types: Annotated[CanonicalSet[NamespacedValue], Field(min_length=1)]
    predicates: CanonicalSet[Predicate]


class ControlEffect(ControlSpecModel):
    verdict: Literal["allow", "allow_with_conditions", "require_approval", "route", "block"]
    route: Route
    requirements: CanonicalSet[Requirement]
    conditions: CanonicalSet[Condition]
    code: NamespacedValue

    @model_validator(mode="after")
    def route_matches_verdict(self) -> ControlEffect:
        if self.verdict == "block" and self.route.kind != CoreRouteKind.BLOCK:
            raise ValueError("block effect requires a block route")
        if self.verdict == "route" and self.route.kind in {
            CoreRouteKind.CONTINUE,
            CoreRouteKind.RECORD_ONLY,
            CoreRouteKind.BLOCK,
        }:
            raise ValueError("route effect requires a non-default alternate route")
        if self.verdict == "require_approval" and self.route.kind in {
            CoreRouteKind.CONTINUE,
            CoreRouteKind.RECORD_ONLY,
            CoreRouteKind.BLOCK,
        }:
            raise ValueError("require_approval effect requires an approval route")
        if self.verdict in {"allow", "allow_with_conditions"} and (
            self.route.kind == CoreRouteKind.BLOCK
        ):
            raise ValueError("permissive effects cannot select a block route")
        return self


class Control(ExtensionBearing):
    schema_name: Literal["controlspec/v0/control"] = Field("controlspec/v0/control", alias="schema")
    control_id: Identifier
    version: SemVer
    status: ControlStatus
    effective_from: UtcTimestamp | None
    effective_until: UtcTimestamp | None
    title: NonEmptyString
    description: str
    owner_ref: ObjectRef | None = None
    source_refs: CanonicalSet[SourceReference] = ()
    match: ControlMatch
    on_unknown: FailureEffect
    effect: ControlEffect
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    semantic_digest: HashDigest | None = None
    digest_field: ClassVar[str] = "semantic_digest"

    @model_validator(mode="after")
    def lifecycle_window_is_coherent(self) -> Control:
        if (
            self.effective_from is not None
            and self.effective_until is not None
            and self.effective_until <= self.effective_from
        ):
            raise ValueError("effective_until must be after effective_from")
        if (
            self.status is ControlStatus.PUBLISHED
            and "-" in self.version.split("+", maxsplit=1)[0]
        ):
            raise ValueError("prerelease controls cannot be published")
        return self


class CanonicalizerBinding(ControlSpecModel):
    name: Literal["RFC8785-INTEGER-AUTHORITY"] = "RFC8785-INTEGER-AUTHORITY"
    version: Literal["1"] = "1"


class EvaluatorBinding(ControlSpecModel):
    name: NonEmptyString
    version: NonEmptyString


class DecisionBinding(ControlSpecModel):
    actor_ref: ActorRef
    action_type: CanonicalAction
    domain_action: NamespacedValue
    resource_ref: ResourceRef
    context_digest: HashDigest
    intent_digest: HashDigest
    control_set_digest: HashDigest
    canonicalizer: CanonicalizerBinding = CanonicalizerBinding()
    evaluator: EvaluatorBinding


class ConditionResult(ControlSpecModel):
    condition_id: Identifier
    status: Literal["satisfied", "outstanding", "failed", "unknown"]
    code: NamespacedValue


class Decision(ExtensionBearing):
    schema_name: Literal["controlspec/v0/decision"] = Field(
        "controlspec/v0/decision", alias="schema"
    )
    decision_id: Identifier
    intent_ref: IntentRef
    evaluated_at: UtcTimestamp
    expires_at: UtcTimestamp
    predecessor_decision_ref: DecisionRef | None
    verdict: Verdict
    route: Route
    conditions: CanonicalSet[ConditionResult]
    approval_requirements: CanonicalSet[ApprovalRequirement]
    required_evidence: CanonicalSet[EvidenceRequirement]
    applied_controls: CanonicalSet[ControlRef]
    explanation_codes: Annotated[CanonicalSet[NamespacedValue], Field(min_length=1)]
    binding: DecisionBinding
    requires_recheck: StrictBool
    semantic_digest: HashDigest | None = None
    digest_field: ClassVar[str] = "semantic_digest"

    @model_validator(mode="after")
    def decision_window_is_finite(self) -> Decision:
        if self.expires_at <= self.evaluated_at:
            raise ValueError("expires_at must be after evaluated_at")
        if self.verdict in {Verdict.ALLOW, Verdict.ALLOW_WITH_CONDITIONS} and not (
            self.applied_controls
        ):
            raise ValueError(
                "permissive decisions require at least one exact applied control"
            )
        if (
            self.verdict in {Verdict.BLOCK, Verdict.CONFLICT}
            and self.route.kind != CoreRouteKind.BLOCK
        ):
            raise ValueError("block and conflict decisions require a block route")
        if self.verdict is Verdict.ROUTE and self.route.kind in {
            CoreRouteKind.CONTINUE,
            CoreRouteKind.RECORD_ONLY,
            CoreRouteKind.BLOCK,
        }:
            raise ValueError("route decisions require a non-default alternate route")
        if self.verdict in {Verdict.ALLOW, Verdict.ALLOW_WITH_CONDITIONS} and (
            self.route.kind == CoreRouteKind.BLOCK
        ):
            raise ValueError("permissive decisions cannot select a block route")
        return self


class Approval(ExtensionBearing):
    schema_name: Literal["controlspec/v0/approval"] = Field(
        "controlspec/v0/approval", alias="schema"
    )
    approval_id: Identifier
    decision_ref: DecisionRef
    intent_ref: IntentRef
    requirement_id: Identifier
    scope: dict[NamespacedValue, JsonValue]
    scope_digest: HashDigest
    approved_route_ref: ObjectRef | None
    approver_ref: ActorRef
    authority_ref: ObjectRef
    approved: StrictBool
    conditions: CanonicalSet[Condition]
    decided_at: UtcTimestamp
    valid_from: UtcTimestamp
    valid_until: UtcTimestamp
    predecessor_approval_ref: ObjectRef | None
    approval_digest: HashDigest | None = None
    digest_field: ClassVar[str] = "approval_digest"

    @model_validator(mode="after")
    def approval_window_is_finite(self) -> Approval:
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self


class ReportedExecution(ControlSpecModel):
    execution_result: NamespacedValue | None
    evidence_refs: CanonicalSet[EvidenceRef]
    business_outcome: NamespacedValue | None


class Receipt(ExtensionBearing):
    schema_name: Literal["controlspec/v0/receipt"] = Field("controlspec/v0/receipt", alias="schema")
    receipt_id: Identifier
    receipt_kind: Literal["execution"] = "execution"
    sequence: Annotated[StrictInt, Field(gt=0)]
    decision_ref: DecisionRef
    intent_ref: IntentRef
    actual_route: Route | None
    reported_execution: ReportedExecution
    verified_evidence_refs: CanonicalSet[EvidenceRef]
    missing_evidence_requirement_ids: CanonicalSet[Identifier]
    execution_outcome: ExecutionOutcome
    outcome: ReceiptOutcome
    status: ReceiptStatus
    status_authority: Literal["system_determined"] = "system_determined"
    occurred_at: UtcTimestamp
    recorded_at: UtcTimestamp
    predecessor_receipt_ref: ObjectRef | None
    receipt_digest: HashDigest | None = None
    digest_field: ClassVar[str] = "receipt_digest"

    @model_validator(mode="after")
    def success_is_system_verified(self) -> Receipt:
        if self.status is ReceiptStatus.COMPLETE:
            if self.execution_outcome is not ExecutionOutcome.SUCCEEDED:
                raise ValueError("complete requires succeeded execution")
            if self.actual_route is None:
                raise ValueError("complete receipts require an actual route")
            if self.missing_evidence_requirement_ids:
                raise ValueError("complete receipts cannot have missing evidence")
            if self.outcome is not ReceiptOutcome.COMPLETED:
                raise ValueError("complete status requires completed outcome")
        if self.outcome is ReceiptOutcome.COMPLETED and self.status is not ReceiptStatus.COMPLETE:
            raise ValueError("completed outcome requires complete system status")
        if (
            self.outcome in {ReceiptOutcome.APPROVED, ReceiptOutcome.REJECTED}
            and self.execution_outcome is ExecutionOutcome.SUCCEEDED
        ):
            raise ValueError("approval outcomes never establish execution success")
        return self


class VerifierDeclaration(ControlSpecModel):
    name: NamespacedValue
    version: NonEmptyString
    input_schema_digest: HashDigest


class RouteDeclaration(ControlSpecModel):
    route_id: Identifier
    kind: CoreRouteKind | NamespacedValue
    parameters_schema_digest: HashDigest


class ExtensionDeclaration(ControlSpecModel):
    key: NamespacedValue
    version: NonEmptyString
    classification: Literal["authority", "evidence", "display"]
    required: StrictBool


class Vocabularies(ControlSpecModel):
    domain_actions: CanonicalSet[NamespacedValue]
    resource_types: CanonicalSet[NamespacedValue]
    verifiers: CanonicalSet[VerifierDeclaration]
    routes: CanonicalSet[RouteDeclaration]


class ControlPack(ExtensionBearing):
    schema_name: Literal["controlspec/v0/control-pack"] = Field(
        "controlspec/v0/control-pack", alias="schema"
    )
    pack_id: Identifier
    name: NonEmptyString
    version: SemVer
    status: ControlStatus
    title: NonEmptyString
    description: str
    controls: CanonicalSet[Control]
    dependencies: CanonicalSet[ControlPackRef]
    vocabularies: Vocabularies
    extension_requirements: CanonicalSet[ExtensionDeclaration]
    conformance_profile: Literal["core", "riskspec-enterprise"]
    examples: CanonicalSet[dict[str, JsonValue]]
    metadata: dict[str, JsonValue]
    semantic_digest: HashDigest | None = None
    digest_field: ClassVar[str] = "semantic_digest"

    @model_validator(mode="after")
    def extensions_are_declared_once(self) -> ControlPack:
        keys = [item.key for item in self.extension_requirements]
        if len(keys) != len(set(keys)):
            raise ValueError("extension keys must be declared exactly once")
        declared = set(keys)
        used: set[str] = set()

        def collect(value: Any) -> None:
            if isinstance(value, ExtensionBearing):
                used.update(value.extensions)
            if isinstance(value, BaseModel):
                for field_value in value.__dict__.values():
                    collect(field_value)
            elif isinstance(value, dict):
                for field_value in value.values():
                    collect(field_value)
            elif isinstance(value, list | tuple):
                for field_value in value:
                    collect(field_value)

        collect(self)
        if not used <= declared:
            raise ValueError("every pack/control extension must be declared")

        if any(control.namespace != self.namespace for control in self.controls):
            raise ValueError("every Control in a pack must use the pack namespace")
        declared_domains = set(self.vocabularies.domain_actions)
        declared_resources = set(self.vocabularies.resource_types)
        used_domains = {
            item for control in self.controls for item in control.match.domain_actions
        }
        used_resources = {
            item for control in self.controls for item in control.match.resource_types
        }
        if not used_domains <= declared_domains or not used_resources <= declared_resources:
            raise ValueError("Control match vocabulary must be declared by the pack")

        declared_verifiers = {item.name for item in self.vocabularies.verifiers}
        used_verifiers: set[str] = set()
        for control in self.controls:
            used_verifiers.update(condition.verifier for condition in control.effect.conditions)
            for requirement in control.effect.requirements:
                if isinstance(requirement, EvidenceRequirement | ProfileRequirement):
                    used_verifiers.add(requirement.verifier)
        if not used_verifiers <= declared_verifiers:
            raise ValueError("every deterministic verifier must be declared by the pack")

        declared_routes = {
            (item.route_id, item.kind) for item in self.vocabularies.routes
        }
        used_extension_routes: set[tuple[str, CoreRouteKind | str]] = set()

        def collect_routes(value: Any) -> None:
            if isinstance(value, Route) and not isinstance(value.kind, CoreRouteKind):
                used_extension_routes.add((value.route_id, value.kind))
            if isinstance(value, BaseModel):
                for field_value in value.__dict__.values():
                    collect_routes(field_value)
            elif isinstance(value, dict):
                for field_value in value.values():
                    collect_routes(field_value)
            elif isinstance(value, list | tuple):
                for field_value in value:
                    collect_routes(field_value)

        collect_routes(self.controls)
        if not used_extension_routes <= declared_routes:
            raise ValueError("every extension route must be declared by the pack")
        if (
            self.status is ControlStatus.PUBLISHED
            and "-" in self.version.split("+", maxsplit=1)[0]
        ):
            raise ValueError("prerelease packs cannot be published")
        return self


PORTABLE_OBJECTS: tuple[type[ExtensionBearing], ...] = (
    Actor,
    ActionIntent,
    Resource,
    Control,
    Decision,
    Route,
    Approval,
    Receipt,
    ControlPack,
)
