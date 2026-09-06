from __future__ import annotations

import pytest

from assurance.controlspec.contracts import (
    Actor,
    ActorType,
    ControlEffect,
    CoreRouteKind,
    EvidenceRef,
    EvidenceRequirement,
    EvidenceSeparation,
    FailureEffect,
    ObjectRef,
    ReceiptStatus,
    ReportedExecution,
    Verdict,
)
from assurance.controlspec.evaluator import ControlSpecEvaluator
from assurance.controlspec.facts import (
    EvaluationFacts,
    TrustedExecutionObservation,
    VerifiedEvidenceFact,
    finalize_execution,
    finalize_fact,
    finalize_snapshot,
)
from assurance.controlspec.receipt import ReceiptAssessmentError, assess_receipt
from assurance.controlspec.recheck import recheck
from tests.controlspec.test_t02_composition import approval_control
from tests.controlspec.test_t02_facts import NOW, control, digest, intent, route, snapshot


def evidence_control():
    requirement = EvidenceRequirement(
        requirement_id="purchase-receipt",
        kind="personal.evidence.receipt",
        subject="personal.purchase",
        minimum_count=1,
        max_age_seconds=3600,
        verifier="controlspec.core.verifier.evidence",
        separation=EvidenceSeparation(
            producer_not_actor=False,
            certifier_not_actor=False,
            producer_certifier_distinct=False,
        ),
        failure=FailureEffect(
            verdict="block",
            route=route(
                CoreRouteKind.BLOCK,
                route_id="missing-evidence",
            ),
            code="controlspec.core.evidence.missing",
        ),
    )
    return control(
        effect=ControlEffect(
            verdict="allow",
            route=route(),
            requirements=(requirement,),
            conditions=(),
            code="controlspec.core.allow",
        )
    )


def empty_facts() -> EvaluationFacts:
    return EvaluationFacts(
        approval_basis_ref=None,
        approvals=(),
        evidence=(),
        profile_assessments=(),
    )


def observation(actual_route):
    return finalize_execution(
        TrustedExecutionObservation(
            execution_ref=ObjectRef(
                namespace="controlspec.personal",
                object_type="controlspec.execution.observation",
                object_id="execution-1",
                version="1",
                digest=digest("execution"),
            ),
            actual_route=actual_route,
            execution_outcome="succeeded",
            occurred_at=NOW,
            recorded_at=NOW,
        )
    )


def test_caller_reported_success_cannot_replace_missing_verified_evidence() -> None:
    evaluator = ControlSpecEvaluator()
    action = intent()
    policy_snapshot = snapshot(evidence_control()).model_copy(
        update={"supported_verifiers": ("controlspec.core.verifier.evidence",)}
    )
    from assurance.controlspec.facts import finalize_snapshot

    policy_snapshot = finalize_snapshot(policy_snapshot)
    facts = empty_facts()
    decision = evaluator.evaluate(
        intent=action,
        snapshot=policy_snapshot,
        facts=facts,
    ).decision
    checked = recheck(
        prior=decision,
        intent=action,
        snapshot=policy_snapshot,
        facts=facts,
        evaluator=evaluator,
    )
    fabricated = EvidenceRef(
        namespace="controlspec.personal",
        evidence_id="caller-claim",
        digest=digest("caller"),
        kind="personal.evidence.receipt",
    )
    receipt = assess_receipt(
        decision=decision,
        intent=action,
        recheck_result=checked,
        facts=facts,
        observation=observation(decision.route),
        reported_execution=ReportedExecution(
            execution_result="personal.execution.succeeded",
            evidence_refs=(fabricated,),
            business_outcome="personal.purchase.completed",
        ),
    )
    assert receipt.status is ReceiptStatus.INCOMPLETE
    assert receipt.verified_evidence_refs == ()
    assert receipt.missing_evidence_requirement_ids == ("purchase-receipt",)


def test_exact_verified_evidence_allows_complete_receipt() -> None:
    evaluator = ControlSpecEvaluator()
    action = intent()
    policy_snapshot = snapshot(evidence_control()).model_copy(
        update={"supported_verifiers": ("controlspec.core.verifier.evidence",)}
    )
    from assurance.controlspec.facts import finalize_snapshot

    policy_snapshot = finalize_snapshot(policy_snapshot)
    evaluation_facts = empty_facts()
    decision = evaluator.evaluate(
        intent=action,
        snapshot=policy_snapshot,
        facts=evaluation_facts,
    ).decision
    checked = recheck(
        prior=decision,
        intent=action,
        snapshot=policy_snapshot,
        facts=evaluation_facts,
        evaluator=evaluator,
    )
    reference = EvidenceRef(
        namespace="controlspec.personal",
        evidence_id="receipt-1",
        digest=digest("receipt-1"),
        kind="personal.evidence.receipt",
    )
    assert action.intent_digest is not None
    evidence = finalize_fact(
        VerifiedEvidenceFact(
            evidence_ref=reference,
            intent_ref=decision.intent_ref,
            kind="personal.evidence.receipt",
            subject="personal.purchase",
            producer_actor_id="merchant",
            producer_lineage_ids=(),
            certifier_actor_id="receipt-verifier",
            certifier_lineage_ids=(),
            verified_at=NOW,
        )
    )
    receipt = assess_receipt(
        decision=decision,
        intent=action,
        recheck_result=checked,
        facts=EvaluationFacts(
            approval_basis_ref=None,
            approvals=(),
            evidence=(evidence,),
            profile_assessments=(),
        ),
        observation=observation(decision.route),
        reported_execution=ReportedExecution(
            execution_result="personal.execution.succeeded",
            evidence_refs=(),
            business_outcome=None,
        ),
    )
    assert receipt.status is ReceiptStatus.COMPLETE
    assert receipt.verified_evidence_refs == (reference,)


def test_execution_outside_decision_window_is_rejected() -> None:
    evaluator = ControlSpecEvaluator(decision_ttl_seconds=60)
    action = intent()
    policy_snapshot = snapshot(control())
    facts = empty_facts()
    decision = evaluator.evaluate(
        intent=action,
        snapshot=policy_snapshot,
        facts=facts,
    ).decision
    checked = recheck(
        prior=decision,
        intent=action,
        snapshot=policy_snapshot,
        facts=facts,
        evaluator=evaluator,
    )
    late = finalize_execution(
        observation(decision.route).model_copy(
            update={
                "occurred_at": "2026-08-20T12:02:00.000000Z",
                "recorded_at": "2026-08-20T12:02:00.000000Z",
                "observation_digest": None,
            }
        )
    )
    with pytest.raises(ReceiptAssessmentError, match="Decision window"):
        assess_receipt(
            decision=decision,
            intent=action,
            recheck_result=checked,
            facts=facts,
            observation=late,
            reported_execution=ReportedExecution(
                execution_result="personal.execution.succeeded",
                evidence_refs=(),
                business_outcome=None,
            ),
        )


def test_stale_decision_digest_mutations_are_rejected_before_receipt_derivation() -> None:
    evaluator = ControlSpecEvaluator()
    action = intent()
    policy_snapshot = snapshot(control())
    facts = empty_facts()
    decision = evaluator.evaluate(
        intent=action, snapshot=policy_snapshot, facts=facts
    ).decision
    checked = recheck(
        prior=decision,
        intent=action,
        snapshot=policy_snapshot,
        facts=facts,
        evaluator=evaluator,
    )
    for mutation in (
        {"verdict": Verdict.ALLOW_WITH_CONDITIONS},
        {"required_evidence": evidence_control().effect.requirements},
        {"applied_controls": ()},
        {
            "binding": decision.binding.model_copy(
                update={"context_digest": digest("stale-context")}
            )
        },
    ):
        stale = decision.model_copy(update=mutation)
        with pytest.raises(ReceiptAssessmentError, match="semantic digest"):
            assess_receipt(
                decision=stale,
                intent=action,
                recheck_result=checked,
                facts=facts,
                observation=observation(decision.route),
                reported_execution=ReportedExecution(
                    execution_result="personal.execution.succeeded",
                    evidence_refs=(),
                    business_outcome=None,
                ),
            )


def test_stale_require_approval_to_allow_mutation_cannot_complete() -> None:
    evaluator = ControlSpecEvaluator()
    action = intent()
    policy_snapshot = snapshot(approval_control())
    facts = empty_facts()
    required = evaluator.evaluate(
        intent=action, snapshot=policy_snapshot, facts=facts
    ).decision
    assert required.verdict is Verdict.REQUIRE_APPROVAL
    checked = recheck(
        prior=required,
        intent=action,
        snapshot=policy_snapshot,
        facts=facts,
        evaluator=evaluator,
    )
    stale_allow = required.model_copy(update={"verdict": Verdict.ALLOW})
    with pytest.raises(ReceiptAssessmentError, match="semantic digest"):
        assess_receipt(
            decision=stale_allow,
            intent=action,
            recheck_result=checked,
            facts=facts,
            observation=observation(required.route),
            reported_execution=ReportedExecution(
                execution_result="personal.execution.succeeded",
                evidence_refs=(),
                business_outcome=None,
            ),
        )


def test_cross_namespace_evidence_cannot_complete_receipt() -> None:
    evaluator = ControlSpecEvaluator()
    action = intent()
    policy_snapshot = finalize_snapshot(
        snapshot(evidence_control()).model_copy(
            update={"supported_verifiers": ("controlspec.core.verifier.evidence",)}
        )
    )
    decision = evaluator.evaluate(
        intent=action, snapshot=policy_snapshot, facts=empty_facts()
    ).decision
    checked = recheck(
        prior=decision,
        intent=action,
        snapshot=policy_snapshot,
        facts=empty_facts(),
        evaluator=evaluator,
    )
    cross_namespace = finalize_fact(
        VerifiedEvidenceFact(
            evidence_ref=EvidenceRef(
                namespace="other.tenant",
                evidence_id="receipt-cross-tenant",
                digest=digest("cross-tenant"),
                kind="personal.evidence.receipt",
            ),
            intent_ref=decision.intent_ref,
            kind="personal.evidence.receipt",
            subject="personal.purchase",
            producer_actor_id="merchant",
            producer_lineage_ids=(),
            certifier_actor_id="verifier",
            certifier_lineage_ids=(),
            verified_at=NOW,
        )
    )
    receipt = assess_receipt(
        decision=decision,
        intent=action,
        recheck_result=checked,
        facts=EvaluationFacts(
            approval_basis_ref=None,
            approvals=(),
            evidence=(cross_namespace,),
            profile_assessments=(),
        ),
        observation=observation(decision.route),
        reported_execution=ReportedExecution(
            execution_result="personal.execution.succeeded",
            evidence_refs=(),
            business_outcome=None,
        ),
    )
    assert receipt.status is ReceiptStatus.INCOMPLETE


def test_incomplete_or_shared_producer_lineage_cannot_satisfy_independence() -> None:
    action = intent().model_copy(
        update={
            "actor": Actor(
                schema="controlspec/v0/actor",
                namespace="controlspec.personal",
                actor_id="agent-1",
                version="1",
                type=ActorType.AGENT,
                owner_ref=None,
                lineage_refs=(
                    ObjectRef(
                        namespace="controlspec.personal",
                        object_type="controlspec.actor.lineage",
                        object_id="shared-owner",
                        version="1",
                        digest=digest("shared-owner"),
                    ),
                ),
                attributes={},
                extensions={},
            ),
            "intent_digest": None,
        }
    )
    from assurance.controlspec.canonical import finalize_object

    action = finalize_object(action)
    requirement = evidence_control().effect.requirements[0].model_copy(
        update={
            "separation": evidence_control().effect.requirements[0].separation.model_copy(
                update={"producer_not_actor": True}
            )
        }
    )
    guarded = evidence_control().model_copy(
        update={
            "effect": evidence_control().effect.model_copy(
                update={"requirements": (requirement,)}
            ),
            "semantic_digest": None,
        }
    )
    guarded = finalize_object(guarded)
    policy_snapshot = finalize_snapshot(
        snapshot(guarded).model_copy(
            update={"supported_verifiers": ("controlspec.core.verifier.evidence",)}
        )
    )
    evaluator = ControlSpecEvaluator()
    decision = evaluator.evaluate(
        intent=action, snapshot=policy_snapshot, facts=empty_facts()
    ).decision
    checked = recheck(
        prior=decision,
        intent=action,
        snapshot=policy_snapshot,
        facts=empty_facts(),
        evaluator=evaluator,
    )
    for complete in (False, True):
        evidence = finalize_fact(
            VerifiedEvidenceFact(
                evidence_ref=EvidenceRef(
                    namespace=action.namespace,
                    evidence_id=f"lineage-{complete}",
                    digest=digest(f"lineage-{complete}"),
                    kind="personal.evidence.receipt",
                ),
                intent_ref=decision.intent_ref,
                kind="personal.evidence.receipt",
                subject="personal.purchase",
                producer_actor_id="merchant",
                producer_lineage_ids=(("shared-owner",) if complete else ()),
                producer_lineage_complete=complete,
                certifier_actor_id="verifier",
                certifier_lineage_ids=(),
                verified_at=NOW,
            )
        )
        receipt = assess_receipt(
            decision=decision,
            intent=action,
            recheck_result=checked,
            facts=EvaluationFacts(
                approval_basis_ref=None,
                approvals=(),
                evidence=(evidence,),
                profile_assessments=(),
            ),
            observation=observation(decision.route),
            reported_execution=ReportedExecution(
                execution_result="personal.execution.succeeded",
                evidence_refs=(),
                business_outcome=None,
            ),
        )
        assert receipt.status is ReceiptStatus.INCOMPLETE
