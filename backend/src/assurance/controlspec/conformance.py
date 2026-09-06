"""Canonical, explicitly non-authoritative ControlSpec conformance runner."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import model_validator

from assurance.contracts.canonical import canonical_json, sha256_digest
from assurance.controlspec.contracts import (
    ActionIntent,
    CanonicalSet,
    Control,
    ControlSpecModel,
    CoreRouteKind,
    HashDigest,
    NamespacedValue,
    ReceiptStatus,
    ReportedExecution,
    Verdict,
)
from assurance.controlspec.evaluator import ControlSpecEvaluator, EvaluationResult
from assurance.controlspec.facts import (
    EvaluationFacts,
    PublishedControlSnapshot,
    SnapshotAuthorityMode,
    TrustedExecutionObservation,
    finalize_snapshot,
)
from assurance.controlspec.receipt import assess_receipt
from assurance.controlspec.recheck import recheck


class RecheckMutation(ControlSpecModel):
    mutation_id: NamespacedValue
    intent: ActionIntent
    controls: CanonicalSet[Control]
    trusted_time: str
    facts: EvaluationFacts


class ConformanceVector(ControlSpecModel):
    schema_name: Literal["controlspec/conformance/v0/vector"] = "controlspec/conformance/v0/vector"
    schema_version: Literal["0.1.0"] = "0.1.0"
    case_id: str
    authority_mode: Literal["non_authoritative_conformance"]
    operation: Literal["evaluate", "recheck", "assess_receipt"]
    intent: ActionIntent
    prior_intent: ActionIntent | None = None
    controls: CanonicalSet[Control]
    trusted_time: str
    supported_extensions: CanonicalSet[NamespacedValue]
    display_extensions: CanonicalSet[NamespacedValue]
    supported_verifiers: CanonicalSet[NamespacedValue]
    facts: EvaluationFacts
    expected_verdict: Verdict
    expected_route_kind: CoreRouteKind | NamespacedValue
    required_explanation_codes: CanonicalSet[NamespacedValue]
    forbidden_verdicts: CanonicalSet[Verdict]
    expected_recheck_valid: bool | None = None
    expected_recheck_code: NamespacedValue | None = None
    execution_observation: TrustedExecutionObservation | None = None
    reported_execution: ReportedExecution | None = None
    expected_receipt_status: ReceiptStatus | None = None
    mutation_cases: CanonicalSet[RecheckMutation] = ()
    control_permutations: tuple[tuple[Control, ...], ...] = ()
    vector_digest: HashDigest | None = None

    @model_validator(mode="after")
    def expected_is_not_forbidden(self) -> ConformanceVector:
        if self.expected_verdict in self.forbidden_verdicts:
            raise ValueError("expected verdict cannot also be forbidden")
        if self.operation == "recheck" and (
            self.prior_intent is None
            or self.expected_recheck_valid is None
            or self.expected_recheck_code is None
        ):
            raise ValueError("recheck vectors require prior input and exact expected result")
        if self.operation == "assess_receipt" and (
            self.execution_observation is None
            or self.reported_execution is None
            or self.expected_receipt_status is None
        ):
            raise ValueError("receipt vectors require exact execution input and status")
        return self


class ConformanceObservation(ControlSpecModel):
    case_id: str
    passed: bool
    observed_verdict: Verdict
    observed_route_kind: CoreRouteKind | NamespacedValue
    observed_explanation_codes: CanonicalSet[NamespacedValue]
    observed_recheck_valid: bool | None = None
    observed_recheck_code: NamespacedValue | None = None
    observed_receipt_status: ReceiptStatus | None = None
    mutation_matrix_passed: bool | None = None
    control_permutations_passed: bool | None = None


def _vector_digest(value: ConformanceVector) -> HashDigest:
    payload = value.model_dump(mode="json", exclude_none=False)
    payload.pop("vector_digest", None)
    return sha256_digest(canonical_json(payload))


def finalize_vector(value: ConformanceVector) -> ConformanceVector:
    return value.model_copy(update={"vector_digest": _vector_digest(value)})


def run_vector(
    vector: ConformanceVector,
    *,
    evaluator: ControlSpecEvaluator | None = None,
) -> tuple[ConformanceObservation, EvaluationResult]:
    if vector.vector_digest != _vector_digest(vector):
        raise ValueError("conformance vector digest is invalid")
    snapshot = finalize_snapshot(
        PublishedControlSnapshot(
            controls=vector.controls,
            observed_at=vector.trusted_time,
            authority_mode=SnapshotAuthorityMode.NON_AUTHORITATIVE_CONFORMANCE,
            host_authority_refs=(),
            supported_extensions=vector.supported_extensions,
            display_extensions=vector.display_extensions,
            supported_verifiers=vector.supported_verifiers,
        )
    )
    active_evaluator = evaluator or ControlSpecEvaluator()
    result = active_evaluator.evaluate(
        intent=vector.intent,
        snapshot=snapshot,
        facts=vector.facts,
    )
    semantic_match = bool(
        result.decision.verdict is vector.expected_verdict
        and result.decision.route.kind == vector.expected_route_kind
        and set(vector.required_explanation_codes)
        <= set(result.decision.explanation_codes)
        and result.decision.verdict not in vector.forbidden_verdicts
    )
    observed_recheck_valid: bool | None = None
    observed_recheck_code: NamespacedValue | None = None
    observed_receipt_status: ReceiptStatus | None = None
    operation_match = True
    if vector.operation == "recheck":
        assert vector.prior_intent is not None
        prior = active_evaluator.evaluate(
            intent=vector.prior_intent,
            snapshot=snapshot,
            facts=vector.facts,
        ).decision
        checked = recheck(
            prior=prior,
            intent=vector.intent,
            snapshot=snapshot,
            facts=vector.facts,
            evaluator=active_evaluator,
        )
        observed_recheck_valid = checked.valid
        observed_recheck_code = checked.reason_code
        operation_match = bool(
            checked.valid is vector.expected_recheck_valid
            and checked.reason_code == vector.expected_recheck_code
        )
    elif vector.operation == "assess_receipt":
        assert vector.execution_observation is not None
        assert vector.reported_execution is not None
        checked = recheck(
            prior=result.decision,
            intent=vector.intent,
            snapshot=snapshot,
            facts=vector.facts,
            evaluator=active_evaluator,
        )
        receipt = assess_receipt(
            decision=result.decision,
            intent=vector.intent,
            recheck_result=checked,
            facts=vector.facts,
            observation=vector.execution_observation,
            reported_execution=vector.reported_execution,
        )
        observed_receipt_status = receipt.status
        operation_match = receipt.status is vector.expected_receipt_status
    mutation_matrix_passed: bool | None = None
    if vector.mutation_cases:
        mutation_results: list[bool] = []
        for mutation in vector.mutation_cases:
            mutated_snapshot = finalize_snapshot(
                PublishedControlSnapshot(
                    controls=mutation.controls,
                    observed_at=mutation.trusted_time,
                    authority_mode=SnapshotAuthorityMode.NON_AUTHORITATIVE_CONFORMANCE,
                    host_authority_refs=(),
                    supported_extensions=vector.supported_extensions,
                    display_extensions=vector.display_extensions,
                    supported_verifiers=vector.supported_verifiers,
                )
            )
            mutation_results.append(
                not recheck(
                    prior=result.decision,
                    intent=mutation.intent,
                    snapshot=mutated_snapshot,
                    facts=mutation.facts,
                    evaluator=active_evaluator,
                ).valid
            )
        mutation_matrix_passed = all(mutation_results)
    control_permutations_passed: bool | None = None
    if vector.control_permutations:
        permutation_digests = []
        for controls in vector.control_permutations:
            permuted_snapshot = finalize_snapshot(
                PublishedControlSnapshot(
                    controls=controls,
                    observed_at=vector.trusted_time,
                    authority_mode=SnapshotAuthorityMode.NON_AUTHORITATIVE_CONFORMANCE,
                    host_authority_refs=(),
                    supported_extensions=vector.supported_extensions,
                    display_extensions=vector.display_extensions,
                    supported_verifiers=vector.supported_verifiers,
                )
            )
            permutation_digests.append(
                active_evaluator.evaluate(
                    intent=vector.intent,
                    snapshot=permuted_snapshot,
                    facts=vector.facts,
                ).decision.semantic_digest
            )
        control_permutations_passed = bool(
            permutation_digests
            and all(item == result.decision.semantic_digest for item in permutation_digests)
        )
    passed = bool(
        semantic_match
        and operation_match
        and mutation_matrix_passed is not False
        and control_permutations_passed is not False
    )
    return (
        ConformanceObservation(
            case_id=vector.case_id,
            passed=passed,
            observed_verdict=result.decision.verdict,
            observed_route_kind=result.decision.route.kind,
            observed_explanation_codes=result.decision.explanation_codes,
            observed_recheck_valid=observed_recheck_valid,
            observed_recheck_code=observed_recheck_code,
            observed_receipt_status=observed_receipt_status,
            mutation_matrix_passed=mutation_matrix_passed,
            control_permutations_passed=control_permutations_passed,
        ),
        result,
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_vector(path: Path) -> ConformanceVector:
    data = path.read_bytes()
    parsed = json.loads(data, object_pairs_hook=_unique_object)
    if canonical_json(parsed) != data:
        raise ValueError("conformance vector must use canonical JSON")
    return ConformanceVector.model_validate(parsed, strict=False)


def run_directory(path: Path) -> tuple[ConformanceObservation, ...]:
    return tuple(run_vector(load_vector(item))[0] for item in sorted(path.glob("*.json")))
