"""Stateless orchestration over the accepted pure ControlSpec T02 engine."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from threading import Lock
from typing import Literal, Protocol, runtime_checkable

from assurance.contracts.canonical import canonical_json, sha256_digest
from assurance.controlspec.api_models import (
    CatalogBinding,
    ComparisonStatus,
    DecideRequest,
    DecideResponse,
    EvaluationOptions,
    ReceiptAssessmentRequest,
    ReceiptAssessmentResponse,
    RecheckComparisons,
    RecheckRequest,
    RecheckResponse,
    ReferenceEvaluationTrace,
    ReferenceSelection,
    ReferenceTraceControl,
)
from assurance.controlspec.canonical import verify_object_digest
from assurance.controlspec.contracts import (
    ActionIntent,
    Control,
    ControlRef,
    ControlSpecModel,
    ControlStatus,
    Decision,
    DecisionRef,
    HashDigest,
    ObjectRef,
    ReceiptStatus,
    ReportedExecution,
    Verdict,
)
from assurance.controlspec.evaluator import ControlSpecEvaluator
from assurance.controlspec.facts import (
    EvaluationFacts,
    PublishedControlSnapshot,
    RecheckResult,
    TrustedExecutionObservation,
    facts_digest,
    finalize_execution,
)
from assurance.controlspec.receipt import ReceiptAssessmentError, assess_receipt
from assurance.controlspec.recheck import recheck
from assurance.controlspec.reference_catalog import (
    ImmutableReferenceCatalog,
    ReferenceScenarioFixture,
    clone_reference_scenario,
    fact_fixture_digest,
    verify_reference_scenario,
)

EXECUTION_UNVERIFIED = "controlspec.reference.execution_unverified"
RECEIPT_NOT_STORED = "controlspec.reference.receipt_not_stored"
CURRENT_CONTROL_INEFFECTIVE = "controlspec.reference.current_control_ineffective"
ROUTE_MISMATCH = "controlspec.reference.route_mismatch"
DECISION_NOT_PERMISSIVE = "controlspec.reference.decision_not_permissive"


class ReferenceServiceError(ValueError):
    """A typed request cannot be composed safely through the T02 engine."""


class PriorBindingError(ReferenceServiceError):
    """A prior Decision does not bind the exact supplied original intent."""


class ReferenceClock(Protocol):
    def now(self) -> datetime: ...


class SystemReferenceClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


@runtime_checkable
class ReferenceFactProvider(Protocol):
    def facts_for(
        self,
        *,
        intent: ActionIntent,
        snapshot: PublishedControlSnapshot,
        prior_decision: Decision | None,
    ) -> ReferenceFactSet: ...


class ReferenceFactSet(ControlSpecModel):
    """Exact server-owned fixture identity and the facts derived from it."""

    fixture_digest: HashDigest
    facts: EvaluationFacts


class ReferenceFactContext(ControlSpecModel):
    """Catalog-resolved context unavailable to caller-defined wire fields."""

    release_id: str
    catalog_digest: HashDigest
    selection: ReferenceSelection
    selection_digest: HashDigest
    selected_catalog_ids: tuple[str, ...]
    observed_at: str
    intent: ActionIntent
    snapshot: PublishedControlSnapshot
    prior_decision: Decision | None


@runtime_checkable
class ContextReferenceFactProvider(Protocol):
    def facts_for_context(self, *, context: ReferenceFactContext) -> ReferenceFactSet: ...


class EmptyReferenceFactProvider:
    def facts_for(
        self,
        *,
        intent: ActionIntent,
        snapshot: PublishedControlSnapshot,
        prior_decision: Decision | None,
    ) -> ReferenceFactSet:
        del intent, snapshot, prior_decision
        return ReferenceFactSet(
            fixture_digest=fact_fixture_digest(()),
            facts=EvaluationFacts(
                approval_basis_ref=None,
                approvals=(),
                evidence=(),
                profile_assessments=(),
            ),
        )


class NamespaceScopedFactProvider:
    """Load one profile provider only for an exact namespace segment."""

    def __init__(
        self,
        *,
        namespace_prefix: str,
        provider_loader: Callable[[], ReferenceFactProvider],
        expected_fixture_digest: HashDigest,
    ) -> None:
        self._namespace_prefix = namespace_prefix
        self._provider_loader = provider_loader
        self._expected_fixture_digest = expected_fixture_digest
        self._provider: ReferenceFactProvider | None = None
        self._empty = EmptyReferenceFactProvider()

    def _matches(self, namespace: str) -> bool:
        return namespace == self._namespace_prefix or namespace.startswith(
            self._namespace_prefix + "."
        )

    def facts_for(
        self,
        *,
        intent: ActionIntent,
        snapshot: PublishedControlSnapshot,
        prior_decision: Decision | None,
    ) -> ReferenceFactSet:
        if not self._matches(intent.namespace):
            return self._empty.facts_for(
                intent=intent,
                snapshot=snapshot,
                prior_decision=prior_decision,
            )
        if self._provider is None:
            self._provider = self._provider_loader()
        result = self._provider.facts_for(
            intent=intent,
            snapshot=snapshot,
            prior_decision=prior_decision,
        )
        if result.fixture_digest != self._expected_fixture_digest:
            raise ReferenceServiceError(
                "profile fact fixture differs from the immutable catalog"
            )
        return result


class ImmutableScenarioFactProvider:
    """Exact finite coordinator over one already-loaded immutable release."""

    def __init__(
        self,
        *,
        release_id: str,
        catalog_digest: HashDigest,
        scenarios: tuple[ReferenceScenarioFixture, ...],
        enterprise_loader: Callable[[ReferenceScenarioFixture], ReferenceFactProvider],
    ) -> None:
        self._release_id = release_id
        self._catalog_digest = catalog_digest
        self._scenarios = tuple(
            clone_reference_scenario(scenario) for scenario in scenarios
        )
        self._enterprise_loader = enterprise_loader
        self._enterprise_providers: dict[str, ReferenceFactProvider] = {}
        self._lock = Lock()

    @staticmethod
    def _empty_resolution(context: ReferenceFactContext) -> ReferenceFactSet:
        return ReferenceFactSet(
            fixture_digest=sha256_digest(
                canonical_json(
                    {
                        "schema": "controlspec/reference/v0/scenario-resolution",
                        "schema_version": "0.1.0",
                        "release_id": context.release_id,
                        "catalog_digest": context.catalog_digest,
                        "matched_fixture": None,
                    }
                )
            ),
            facts=EvaluationFacts(
                approval_basis_ref=None,
                approvals=(),
                evidence=(),
                profile_assessments=(),
            ),
        )

    @staticmethod
    def _matches(
        scenario: ReferenceScenarioFixture,
        context: ReferenceFactContext,
    ) -> bool:
        if (
            scenario.release_id != context.release_id
            or scenario.selection != context.selection
            or sha256_digest(canonical_json(scenario.selection))
            != context.selection_digest
            or scenario.reference_time != context.observed_at
            or scenario.intent != context.intent
        ):
            return False
        actual_refs = tuple(_control_ref(control) for control in context.snapshot.controls)
        return actual_refs == scenario.control_refs

    def _enterprise_provider(
        self,
        scenario: ReferenceScenarioFixture,
    ) -> ReferenceFactProvider:
        assert scenario.semantic_digest is not None
        provider = self._enterprise_providers.get(scenario.semantic_digest)
        if provider is not None:
            return provider
        with self._lock:
            provider = self._enterprise_providers.get(scenario.semantic_digest)
            if provider is None:
                provider = self._enterprise_loader(scenario)
                self._enterprise_providers[scenario.semantic_digest] = provider
        return provider

    def facts_for_context(self, *, context: ReferenceFactContext) -> ReferenceFactSet:
        if (
            context.release_id != self._release_id
            or context.catalog_digest != self._catalog_digest
        ):
            raise ReferenceServiceError("fact context differs from immutable release")
        matches: list[ReferenceScenarioFixture] = []
        for scenario in self._scenarios:
            if not verify_reference_scenario(scenario):
                raise ReferenceServiceError(
                    "retained reference scenario integrity is invalid"
                )
            if self._matches(scenario, context):
                matches.append(scenario)
        if not matches:
            return self._empty_resolution(context)
        if len(matches) != 1:
            raise ReferenceServiceError("exact scenario resolution is ambiguous")
        scenario = matches[0]
        if scenario.semantic_digest is None:
            raise ReferenceServiceError("matched scenario has no exact digest")
        if scenario.profile_kind == "portable_core":
            basis = scenario.approval_basis_decision
            return ReferenceFactSet(
                fixture_digest=scenario.semantic_digest,
                facts=EvaluationFacts(
                    approval_basis_ref=(
                        _decision_ref(basis) if basis is not None else None
                    ),
                    approvals=scenario.approvals,
                    evidence=(),
                    profile_assessments=(),
                ),
            )
        result = self._enterprise_provider(scenario).facts_for(
            intent=context.intent,
            snapshot=context.snapshot,
            prior_decision=context.prior_decision,
        )
        if result.fixture_digest != scenario.semantic_digest:
            raise ReferenceServiceError(
                "enterprise leaf differs from exact matched scenario"
            )
        return result


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ReferenceServiceError("reference clock must return a timezone-aware instant")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def _decision_ref(value: Decision) -> DecisionRef:
    if value.semantic_digest is None:
        raise PriorBindingError("prior Decision requires an exact semantic digest")
    return DecisionRef(
        namespace=value.namespace,
        decision_id=value.decision_id,
        semantic_digest=value.semantic_digest,
    )


def _effective(control: Control, observed_at: str) -> bool:
    observed = _instant(observed_at)
    return (
        control.status is ControlStatus.PUBLISHED
        and (
            control.effective_from is None
            or _instant(control.effective_from) <= observed
        )
        and (
            control.effective_until is None
            or observed < _instant(control.effective_until)
        )
    )


def _control_ref(control: Control) -> ControlRef:
    if control.semantic_digest is None:
        raise ReferenceServiceError("catalog Control requires an exact semantic digest")
    return ControlRef(
        namespace=control.namespace,
        control_id=control.control_id,
        version=control.version,
        semantic_digest=control.semantic_digest,
    )


class ReferenceControlPlaneService:
    """Pure request orchestration; owns no store, lifecycle, or effect authority."""

    def __init__(
        self,
        *,
        catalog: ImmutableReferenceCatalog,
        fact_provider: ReferenceFactProvider | ContextReferenceFactProvider | None = None,
        clock: ReferenceClock | None = None,
    ) -> None:
        self._catalog = catalog
        self._fact_provider = fact_provider or EmptyReferenceFactProvider()
        self._clock = clock or SystemReferenceClock()

    @property
    def catalog(self) -> ImmutableReferenceCatalog:
        return self._catalog

    def _reference_time(
        self,
        value: str | None,
    ) -> tuple[str, Literal["caller_reference", "server_reference"]]:
        if value is not None:
            return value, "caller_reference"
        return _timestamp(self._clock.now()), "server_reference"

    @staticmethod
    def _evaluator(snapshot: PublishedControlSnapshot) -> ControlSpecEvaluator:
        return ControlSpecEvaluator(
            verifier_registry=frozenset(snapshot.supported_verifiers),
        )

    @staticmethod
    def _bind_facts(
        binding: CatalogBinding,
        fact_set: ReferenceFactSet,
    ) -> CatalogBinding:
        actual_facts_digest = facts_digest(fact_set.facts)
        semantic_input_digest = sha256_digest(
            canonical_json(
                {
                    "catalog_digest": binding.catalog_digest,
                    "selection_digest": binding.selection_digest,
                    "fact_fixture_digest": fact_set.fixture_digest,
                    "facts_digest": actual_facts_digest,
                }
            )
        )
        return CatalogBinding(
            catalog_digest=binding.catalog_digest,
            selection_digest=binding.selection_digest,
            fact_fixture_digest=fact_set.fixture_digest,
            facts_digest=actual_facts_digest,
            semantic_input_digest=semantic_input_digest,
            selected_catalog_ids=binding.selected_catalog_ids,
        )

    def _facts_for(
        self,
        *,
        selection: ReferenceSelection,
        observed_at: str,
        intent: ActionIntent,
        snapshot: PublishedControlSnapshot,
        binding: CatalogBinding,
        prior_decision: Decision | None,
    ) -> ReferenceFactSet:
        if isinstance(self._fact_provider, ContextReferenceFactProvider):
            return self._fact_provider.facts_for_context(
                context=ReferenceFactContext(
                    release_id=self._catalog.release_id,
                    catalog_digest=binding.catalog_digest,
                    selection=selection,
                    selection_digest=binding.selection_digest,
                    selected_catalog_ids=tuple(
                        str(item) for item in binding.selected_catalog_ids
                    ),
                    observed_at=observed_at,
                    intent=intent,
                    snapshot=snapshot,
                    prior_decision=prior_decision,
                )
            )
        assert isinstance(self._fact_provider, ReferenceFactProvider)
        return self._fact_provider.facts_for(
            intent=intent,
            snapshot=snapshot,
            prior_decision=prior_decision,
        )

    def decide(self, request: DecideRequest) -> DecideResponse:
        if request.action_intent.intent_digest is None or not verify_object_digest(
            request.action_intent
        ):
            raise ReferenceServiceError("ActionIntent semantic digest is invalid")
        observed_at, time_source = self._reference_time(request.options.reference_time)
        snapshot, binding = self._catalog.resolve(
            request.selection,
            observed_at=observed_at,
        )
        fact_set = self._facts_for(
            selection=request.selection,
            observed_at=observed_at,
            intent=request.action_intent,
            snapshot=snapshot,
            binding=binding,
            prior_decision=None,
        )
        binding = self._bind_facts(binding, fact_set)
        evaluated = self._evaluator(snapshot).evaluate(
            intent=request.action_intent,
            snapshot=snapshot,
            facts=fact_set.facts,
        )
        if evaluated.decision.applied_controls != tuple(
            item.control_ref
            for item in evaluated.trace.evaluated_controls
        ):
            raise ReferenceServiceError("Decision and trace Control bindings differ")
        return DecideResponse(
            schema="controlspec/api/v0/decide-response",
            decision=evaluated.decision,
            matched_controls=evaluated.decision.applied_controls,
            trace=(
                ReferenceEvaluationTrace(
                    snapshot_digest=evaluated.trace.snapshot_digest,
                    facts_digest=evaluated.trace.facts_digest,
                    evaluated_controls=tuple(
                        ReferenceTraceControl(
                            control_ref=item.control_ref,
                            selection=item.selection,
                            predicate_results=item.predicate_results,
                            emitted_code=item.emitted_code,
                        )
                        for item in evaluated.trace.evaluated_controls
                    ),
                    final_verdict=evaluated.trace.final_verdict,
                    final_route=evaluated.trace.final_route,
                    explanation_codes=evaluated.trace.explanation_codes,
                )
                if request.options.include_trace
                else None
            ),
            catalog_binding=binding,
            time_source=time_source,
            explanation_codes=evaluated.decision.explanation_codes,
        )

    @staticmethod
    def _verify_prior(
        *,
        original_intent: ActionIntent,
        prior: Decision,
    ) -> None:
        if original_intent.intent_digest is None or not verify_object_digest(
            original_intent
        ):
            raise PriorBindingError("original ActionIntent semantic digest is invalid")
        if prior.semantic_digest is None or not verify_object_digest(prior):
            raise PriorBindingError("prior Decision semantic digest is invalid")
        if (
            prior.intent_ref.namespace != original_intent.namespace
            or prior.intent_ref.intent_id != original_intent.intent_id
            or prior.intent_ref.intent_digest != original_intent.intent_digest
        ):
            raise PriorBindingError("prior Decision does not bind the original intent")

    @staticmethod
    def _comparisons(
        *,
        original: ActionIntent,
        current: ActionIntent,
        prior: Decision,
        current_snapshot: PublishedControlSnapshot,
        current_time: str,
    ) -> RecheckComparisons:
        current_refs = {_control_ref(control) for control in current_snapshot.controls}
        controls_same = set(prior.applied_controls) <= current_refs
        current_effective = all(
            any(
                _control_ref(control) == reference
                and _effective(control, current_time)
                for control in current_snapshot.controls
            )
            for reference in prior.applied_controls
        )
        return RecheckComparisons(
            actor=(
                ComparisonStatus.SAME
                if original.actor == current.actor
                else ComparisonStatus.CHANGED
            ),
            action=(
                ComparisonStatus.SAME
                if original.action == current.action
                else ComparisonStatus.CHANGED
            ),
            resource=(
                ComparisonStatus.SAME
                if original.resource == current.resource
                else ComparisonStatus.CHANGED
            ),
            context=(
                ComparisonStatus.SAME
                if original.context_digest == current.context_digest
                else ComparisonStatus.CHANGED
            ),
            controls=(
                ComparisonStatus.SAME
                if controls_same and current_effective
                else ComparisonStatus.CHANGED
            ),
            decision_window=(
                ComparisonStatus.SAME
                if _instant(current_time) < _instant(prior.expires_at)
                else ComparisonStatus.CHANGED
            ),
        )

    def recheck(self, request: RecheckRequest) -> RecheckResponse:
        self._verify_prior(
            original_intent=request.original_action_intent,
            prior=request.prior_decision,
        )
        if request.current_action_intent.intent_digest is None or not verify_object_digest(
            request.current_action_intent
        ):
            raise PriorBindingError("current ActionIntent semantic digest is invalid")
        current_time, _ = self._reference_time(request.options.reference_time)
        current_snapshot, binding = self._catalog.resolve(
            request.selection,
            observed_at=current_time,
        )
        comparisons = self._comparisons(
            original=request.original_action_intent,
            current=request.current_action_intent,
            prior=request.prior_decision,
            current_snapshot=current_snapshot,
            current_time=current_time,
        )
        prior_ref = _decision_ref(request.prior_decision)
        if comparisons.decision_window is not ComparisonStatus.SAME:
            checked = RecheckResult(
                valid=False,
                prior_decision_ref=prior_ref,
                reason_code="controlspec.core.recheck.expired",
                current_decision_ref=None,
            )
        elif comparisons.controls is not ComparisonStatus.SAME:
            checked = RecheckResult(
                valid=False,
                prior_decision_ref=prior_ref,
                reason_code=CURRENT_CONTROL_INEFFECTIVE,
                current_decision_ref=None,
            )
        else:
            prior_snapshot, _ = self._catalog.resolve(
                request.selection,
                observed_at=request.prior_decision.evaluated_at,
            )
            fact_set = self._facts_for(
                selection=request.selection,
                observed_at=request.prior_decision.evaluated_at,
                intent=request.current_action_intent,
                snapshot=prior_snapshot,
                binding=binding,
                prior_decision=request.prior_decision,
            )
            binding = self._bind_facts(binding, fact_set)
            checked = recheck(
                prior=request.prior_decision,
                intent=request.current_action_intent,
                snapshot=prior_snapshot,
                facts=fact_set.facts,
                evaluator=self._evaluator(prior_snapshot),
            )
        return RecheckResponse(
            schema="controlspec/api/v0/recheck-response",
            recheck=checked,
            comparisons=comparisons,
            catalog_binding=binding,
            explanation_codes=(checked.reason_code,),
        )

    def assess_receipt(
        self,
        request: ReceiptAssessmentRequest,
    ) -> ReceiptAssessmentResponse:
        recorded_at, _ = self._reference_time(request.options.reference_time)
        if _instant(recorded_at) < _instant(request.reported_execution.occurred_at):
            raise ReferenceServiceError("reported execution cannot occur after assessment")
        checked = self.recheck(
            RecheckRequest(
                schema="controlspec/api/v0/recheck-request",
                original_action_intent=request.action_intent,
                prior_decision=request.decision,
                current_action_intent=request.action_intent,
                selection=request.selection,
                options=EvaluationOptions(
                    include_trace=False,
                    reference_time=recorded_at,
                ),
            )
        )
        prior_snapshot, binding = self._catalog.resolve(
            request.selection,
            observed_at=request.decision.evaluated_at,
        )
        fact_set = self._facts_for(
            selection=request.selection,
            observed_at=request.decision.evaluated_at,
            intent=request.action_intent,
            snapshot=prior_snapshot,
            binding=binding,
            prior_decision=request.decision,
        )
        binding = self._bind_facts(binding, fact_set)
        report_payload = request.reported_execution.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=False,
        )
        report_digest = sha256_digest(canonical_json(report_payload))
        observation = finalize_execution(
            TrustedExecutionObservation(
                execution_ref=ObjectRef(
                    namespace=request.action_intent.namespace,
                    object_type="controlspec.reference.execution_report",
                    object_id=report_digest.removeprefix("sha256:"),
                    version="0.1.0",
                    digest=report_digest,
                ),
                actual_route=request.reported_execution.actual_route,
                execution_outcome="not_executed",
                occurred_at=request.reported_execution.occurred_at,
                recorded_at=recorded_at,
            )
        )
        reported = ReportedExecution(
            execution_result=request.reported_execution.execution_result,
            evidence_refs=request.reported_execution.evidence_refs,
            business_outcome=request.reported_execution.business_outcome,
        )
        try:
            receipt = assess_receipt(
                decision=request.decision,
                intent=request.action_intent,
                recheck_result=checked.recheck,
                facts=fact_set.facts,
                observation=observation,
                reported_execution=reported,
            )
        except ReceiptAssessmentError as exc:
            raise ReferenceServiceError("receipt assessment input is invalid") from exc
        if receipt.status is ReceiptStatus.COMPLETE:
            raise ReferenceServiceError(
                "caller-reported execution cannot produce complete reference assurance"
            )
        codes = {EXECUTION_UNVERIFIED, RECEIPT_NOT_STORED}
        codes.add(checked.recheck.reason_code)
        if request.reported_execution.actual_route != request.decision.route:
            codes.add(ROUTE_MISMATCH)
        if request.decision.verdict not in {
            Verdict.ALLOW,
            Verdict.ALLOW_WITH_CONDITIONS,
        }:
            codes.add(DECISION_NOT_PERMISSIVE)
        codes.update(
            requirement.failure.code
            for requirement in request.decision.required_evidence
            if requirement.requirement_id in receipt.missing_evidence_requirement_ids
        )
        return ReceiptAssessmentResponse(
            schema="controlspec/api/v0/receipt-assessment-response",
            receipt=receipt,
            catalog_binding=binding,
            explanation_codes=tuple(sorted(codes)),
        )
