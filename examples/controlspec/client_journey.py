"""Fresh-intent simulation using the existing reference API; no targets execute."""

from __future__ import annotations

import argparse

from assurance.contracts.canonical import canonical_json
from assurance.controlspec.api_models import (
    DecideRequest,
    EvaluationOptions,
    PackSelection,
    ReceiptAssessmentRequest,
    RecheckRequest,
    ReferenceReportedExecution,
    ReferenceTimeOptions,
)
from assurance.controlspec.client import ControlSpecReferenceClient, build_action_intent
from assurance.controlspec.contracts import (
    Action,
    Actor,
    ActorType,
    CanonicalAction,
    JsonValue,
    Resource,
)


def run_journey(
    client: ControlSpecReferenceClient,
    *,
    requested_at: str,
    idempotency_prefix: str,
) -> dict[str, JsonValue]:
    """Discover exact fixtures; decide, recheck, change context, report simulation.

    All reported outcomes below are caller simulations, not execution evidence.
    """
    catalog = client.list_packs()
    results: dict[str, JsonValue] = {"simulation_only": True}
    cases: tuple[tuple[str, str, str, CanonicalAction, dict[str, JsonValue]], ...] = (
        (
            "personal.agent.spending",
            "personal.purchase",
            "personal.cart",
            CanonicalAction.COMMIT,
            {
                "personal.spending.total_minor_units": 4200,
                "personal.spending.recurring": False,
            },
        ),
        (
            "smb.sales.controls",
            "smb.sales.offer_discount",
            "smb.customer_email",
            CanonicalAction.COMMUNICATE,
            {"smb.sales.discount_basis_points": 800},
        ),
    )
    for index, (
        namespace,
        domain_action,
        resource_type,
        canonical_action,
        context,
    ) in enumerate(cases):
        summary = next(item for item in catalog.items if item.namespace == namespace)
        pack = client.get_pack(summary.catalog_id)
        if pack.summary.semantic_digest != summary.semantic_digest:
            raise ValueError(
                "catalog changed during discovery; stop and review the exact selection"
            )
        selected = PackSelection(
            catalog_id=summary.catalog_id, semantic_digest=summary.semantic_digest
        )
        actor = Actor(
            schema="controlspec/v0/actor",
            namespace=namespace,
            actor_id="example-agent",
            version="1",
            type=ActorType.AGENT,
            owner_ref=None,
            lineage_refs=(),
            attributes={},
        )
        action = Action(
            type=canonical_action,
            domain_action=domain_action,
            requested_effect={"example.simulation": True},
        )
        resource = Resource(
            schema="controlspec/v0/resource",
            namespace=namespace,
            resource_id="example-resource",
            version="1",
            type=resource_type,
            business_id=None,
            attributes={},
        )
        original = build_action_intent(
            namespace=namespace,
            intent_id=f"{idempotency_prefix}-{index}",
            actor=actor,
            action=action,
            resource=resource,
            context=context,
            requested_at=requested_at,
            idempotency_key=f"{idempotency_prefix}-{index}",
        )
        options = EvaluationOptions(reference_time=requested_at)
        decision = client.decide(
            DecideRequest(
                schema="controlspec/api/v0/decide-request",
                action_intent=original,
                selection=selected,
                options=options,
            )
        )
        same = client.recheck(
            RecheckRequest(
                schema="controlspec/api/v0/recheck-request",
                original_action_intent=original,
                prior_decision=decision.decision,
                current_action_intent=original,
                selection=selected,
                options=options,
            )
        )
        changed_context = dict(context)
        changed_context["example.binding_changed"] = True
        changed_intent = build_action_intent(
            namespace=namespace,
            intent_id=original.intent_id,
            actor=actor,
            action=action,
            resource=resource,
            context=changed_context,
            requested_at=requested_at,
            idempotency_key=original.idempotency_key,
        )
        changed = client.recheck(
            RecheckRequest(
                schema="controlspec/api/v0/recheck-request",
                original_action_intent=original,
                prior_decision=decision.decision,
                current_action_intent=changed_intent,
                selection=selected,
                options=options,
            )
        )
        assessment = client.assess_receipt(
            ReceiptAssessmentRequest(
                schema="controlspec/api/v0/receipt-assessment-request",
                action_intent=original,
                decision=decision.decision,
                selection=selected,
                reported_execution=ReferenceReportedExecution(
                    actual_route=decision.decision.route,
                    execution_result="example.simulated_success",
                    evidence_refs=(),
                    business_outcome="example.simulated_outcome",
                    occurred_at=requested_at,
                ),
                options=ReferenceTimeOptions(reference_time=requested_at),
            )
        )
        results[namespace] = {
            "catalog_id": selected.catalog_id,
            "pack_digest": selected.semantic_digest,
            "intent_digest": original.intent_digest,
            "verdict": decision.decision.verdict.value,
            "same_binding_valid": same.recheck.valid,
            "changed_binding_valid": changed.recheck.valid,
            "receipt_status": assessment.receipt.status.value,
            "assessment_basis": assessment.assessment_basis,
            "stored": assessment.stored,
            "may_authorize_external_effect": decision.authority.may_authorize_external_effect,
        }
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument(
        "--requested-at", required=True, help="UTC instant with six fractional digits"
    )
    parser.add_argument(
        "--idempotency-prefix", required=True, help="caller-owned simulation identity"
    )
    args = parser.parse_args()
    result = run_journey(
        ControlSpecReferenceClient(args.base_url),
        requested_at=args.requested_at,
        idempotency_prefix=args.idempotency_prefix,
    )
    print(canonical_json(result).decode("utf-8"))


if __name__ == "__main__":
    main()
