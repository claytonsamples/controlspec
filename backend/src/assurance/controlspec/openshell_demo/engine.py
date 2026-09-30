"""Real ControlSpec evaluation, synthetic approval facts, and one-use reservations."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from assurance.contracts.canonical import canonical_json, sha256_digest
from assurance.controlspec.contracts import (
    ActionIntent,
    Actor,
    ActorType,
    Control,
    CoreRouteKind,
    Decision,
    DecisionRef,
    ObjectRef,
    Verdict,
)
from assurance.controlspec.evaluator import ControlSpecEvaluator
from assurance.controlspec.facts import (
    ApprovalFact,
    EvaluationFacts,
    EvaluationTrace,
    finalize_fact,
)
from assurance.controlspec.openshell_demo.ledger import Ledger
from assurance.controlspec.openshell_demo.policy import (
    NAMESPACE,
    PurchaseRequest,
    TrustedScope,
    make_intent,
    policy_digest,
    request_digest,
    snapshot,
    synthetic_controls,
    timestamp,
)


@dataclass(frozen=True)
class Evaluation:
    intent: ActionIntent
    decision: Decision
    trace: EvaluationTrace

    @property
    def allowed(self) -> bool:
        return self.decision.verdict in {Verdict.ALLOW, Verdict.ALLOW_WITH_CONDITIONS} and (
            self.decision.route.kind is CoreRouteKind.CONTINUE
        )


class DemoDenied(ValueError):
    def __init__(self, reason: str, evaluation: Evaluation | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.evaluation = evaluation


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def _ref(decision: Decision) -> DecisionRef:
    assert decision.semantic_digest is not None
    return DecisionRef(
        namespace=decision.namespace,
        decision_id=decision.decision_id,
        semantic_digest=decision.semantic_digest,
    )


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def sign_ticket(payload: dict[str, Any], secret: bytes) -> str:
    raw = canonical_json(payload)
    return _b64(raw) + "." + _b64(hmac.digest(secret, raw, "sha256"))


def verify_ticket(ticket: str, secret: bytes) -> dict[str, Any]:
    try:
        if len(ticket) > 8192:
            raise ValueError("oversized ticket")
        payload, signature = ticket.split(".")
        raw = base64.b64decode(payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True)
        mac = base64.b64decode(
            signature + "=" * (-len(signature) % 4), altchars=b"-_", validate=True
        )
        if not hmac.compare_digest(mac, hmac.digest(secret, raw, "sha256")):
            raise ValueError("invalid signature")
        value = json.loads(raw)
        if not isinstance(value, dict) or canonical_json(value) != raw:
            raise ValueError("noncanonical ticket")
        return value
    except (ValueError, TypeError, UnicodeError) as exc:
        raise DemoDenied("invalid_ticket") from exc


class DemoEngine:
    """Host-only synthetic service. Secrets must never enter the agent environment."""

    def __init__(
        self,
        db_path: str | Path,
        ticket_secret: bytes,
        operator_secret: bytes,
        operator_id: str = "demo-human",
        *,
        controls: tuple[Control, ...] | None = None,
    ) -> None:
        if len(ticket_secret) < 32 or len(operator_secret) < 32:
            raise ValueError("demo secrets must contain at least 32 bytes")
        if hmac.compare_digest(ticket_secret, operator_secret):
            raise ValueError("operator and ticket secrets must differ")
        self.ledger = Ledger(db_path)
        self._ticket_secret = ticket_secret
        self._operator_secret = operator_secret
        self._operator_id = operator_id
        # Exact typed example policy is host-owned, never accepted through a request.
        self.controls = controls if controls is not None else synthetic_controls()
        self.policy_digest = policy_digest(self.controls)
        self._evaluator = ControlSpecEvaluator(decision_ttl_seconds=120)

    def _evaluate(
        self,
        connection: sqlite3.Connection,
        request: PurchaseRequest,
        scope: TrustedScope,
        observed: str,
    ) -> tuple[dict[str, Any], Evaluation]:
        digest = request_digest(request)
        state = Ledger.latest(connection, scope.key, request.action_id, "state")
        if state is None:
            intent = make_intent(request, scope, observed)
            state = {
                "request": request.model_dump(mode="json"),
                "request_digest": digest,
                "scope": scope.model_dump(mode="json"),
                "first_seen": observed,
                "intent": intent.model_dump(mode="json", by_alias=True),
                "policy_digest": self.policy_digest,
                "status": "pending",
                "approvals": [],
                "basis": None,
            }
        if state["request_digest"] != digest:
            raise DemoDenied("action_changed")
        if state["policy_digest"] != self.policy_digest:
            raise DemoDenied("policy_changed")
        if observed < state["first_seen"] or _instant(observed) >= (
            _instant(state["first_seen"]) + timedelta(seconds=300)
        ):
            raise DemoDenied("action_expired")
        intent = ActionIntent.model_validate_json(json.dumps(state["intent"]))
        facts = EvaluationFacts(
            approval_basis_ref=DecisionRef.model_validate(state["basis"])
            if state["basis"]
            else None,
            approvals=tuple(
                ApprovalFact.model_validate_json(json.dumps(fact)) for fact in state["approvals"]
            ),
            evidence=(),
            profile_assessments=(),
        )
        result = self._evaluator.evaluate(
            intent=intent, snapshot=snapshot(self.controls, observed), facts=facts
        )
        evaluation = Evaluation(intent, result.decision, result.trace)
        state["decision"] = result.decision.model_dump(mode="json", by_alias=True)
        state["trace"] = result.trace.model_dump(mode="json")
        Ledger.append(connection, scope.key, request.action_id, "state", state)
        return state, evaluation

    def evaluate(
        self, request: PurchaseRequest, scope: TrustedScope, now: datetime | None = None
    ) -> Evaluation:
        observed = timestamp(now)
        error: DemoDenied | None = None
        evaluation: Evaluation | None = None
        with self.ledger.transaction() as connection:
            try:
                _, evaluation = self._evaluate(connection, request, scope, observed)
            except DemoDenied as exc:
                error = exc
                Ledger.append(
                    connection,
                    scope.key,
                    request.action_id,
                    "denied",
                    {"reason": exc.reason, "at": observed},
                )
        if error:
            raise error
        assert evaluation is not None
        return evaluation

    def pending(self, action_id: str, scope: TrustedScope) -> dict[str, Any] | None:
        """Host CLI inspection: includes exact action, decision, policy and scope."""
        with self.ledger.transaction() as connection:
            return Ledger.latest(connection, scope.key, action_id, "state")

    def approve(
        self, action_id: str, scope: TrustedScope, operator_token: str, now: datetime | None = None
    ) -> Evaluation:
        observed = timestamp(now)
        error: DemoDenied | None = None
        evaluation: Evaluation | None = None
        with self.ledger.transaction() as connection:
            try:
                if not hmac.compare_digest(operator_token.encode(), self._operator_secret):
                    raise DemoDenied("operator_authentication_failed")
                state = Ledger.latest(connection, scope.key, action_id, "state")
                if state is None:
                    raise DemoDenied("unknown_pending_action")
                if state["status"] != "pending" or state["approvals"]:
                    raise DemoDenied("action_not_pending")
                request = PurchaseRequest.model_validate(state["request"])
                basis = Decision.model_validate_json(json.dumps(state["decision"]))
                if observed >= basis.expires_at:
                    raise DemoDenied("pending_decision_expired")
                if basis.verdict is not Verdict.REQUIRE_APPROVAL:
                    raise DemoDenied("approval_not_required")
                if state["policy_digest"] != self.policy_digest:
                    raise DemoDenied("policy_changed")
                intent = ActionIntent.model_validate_json(json.dumps(state["intent"]))
                basis_ref = _ref(basis)
                facts = []
                for requirement in basis.approval_requirements:
                    authority = ObjectRef(
                        namespace=NAMESPACE,
                        object_type="controlspec.synthetic.operator_authority",
                        object_id=self._operator_id,
                        version="1",
                        digest=sha256_digest(
                            canonical_json({"operator": self._operator_id, "synthetic_only": True})
                        ),
                    )
                    fact = finalize_fact(
                        ApprovalFact(
                            approval_id="approval-" + secrets.token_hex(16),
                            intent_ref=basis.intent_ref,
                            basis_decision_ref=basis_ref,
                            requirement_id=requirement.requirement_id,
                            scope_digest=sha256_digest(canonical_json(requirement.scope)),
                            approver=Actor(
                                schema="controlspec/v0/actor",
                                namespace=NAMESPACE,
                                actor_id=self._operator_id,
                                version="1",
                                type=ActorType.HUMAN,
                                owner_ref=None,
                                lineage_refs=(),
                                attributes={},
                            ),
                            authority_ref=authority,
                            roles=(requirement.role,),
                            separated_role_actor_ids={},
                            lineage_complete=True,
                            approved=True,
                            valid_from=observed,
                            valid_until=min(
                                basis.expires_at,
                                timestamp(_instant(observed) + timedelta(seconds=120)),
                            ),
                        )
                    )
                    facts.append(fact.model_dump(mode="json"))
                state["approvals"] = facts
                state["basis"] = basis_ref.model_dump(mode="json")
                state["status"] = "approved"
                Ledger.append(connection, scope.key, action_id, "state", state)
                _, evaluation = self._evaluate(connection, request, scope, observed)
                if not evaluation.allowed:
                    error = DemoDenied("approval_rejected", evaluation)
                # The synthetic identity registry is only the exact agent plus host operator.
                assert intent.actor.actor_id == scope.actor_id
            except DemoDenied as exc:
                error = exc
            if error:
                Ledger.append(
                    connection,
                    scope.key,
                    action_id,
                    "denied",
                    {"reason": error.reason, "at": observed},
                )
        if error:
            raise error
        assert evaluation is not None
        return evaluation

    def authorize(
        self, request: PurchaseRequest, scope: TrustedScope, now: datetime | None = None
    ) -> str:
        observed = timestamp(now)
        error: DemoDenied | None = None
        ticket = ""
        with self.ledger.transaction() as connection:
            try:
                state, evaluation = self._evaluate(connection, request, scope, observed)
                if state["status"] == "reserved":
                    raise DemoDenied("action_already_reserved", evaluation)
                if not evaluation.allowed:
                    reason = (
                        "approval_required"
                        if evaluation.decision.verdict is Verdict.REQUIRE_APPROVAL
                        else "policy_denied"
                    )
                    raise DemoDenied(reason, evaluation)
                expiration = min(
                    evaluation.decision.expires_at,
                    timestamp(_instant(observed) + timedelta(seconds=30)),
                    timestamp(_instant(state["first_seen"]) + timedelta(seconds=300)),
                )
                if state["approvals"]:
                    expiration = min(
                        expiration, *(fact["valid_until"] for fact in state["approvals"])
                    )
                payload = {
                    "schema_version": "1",
                    "purpose": "synthetic-purchase-only",
                    "scope": scope.model_dump(mode="json"),
                    "action_id": request.action_id,
                    "request_digest": state["request_digest"],
                    "policy_digest": self.policy_digest,
                    "decision_digest": evaluation.decision.semantic_digest,
                    "method": "POST",
                    "path": "/purchases",
                    "issued_at": observed,
                    "expires_at": expiration,
                    "nonce": secrets.token_hex(32),
                }
                ticket = sign_ticket(payload, self._ticket_secret)
                state["status"] = "reserved"
                state["reservation"] = payload
                # Retain binding, never the bearer ticket or secret.
                Ledger.append(connection, scope.key, request.action_id, "state", state)
            except DemoDenied as exc:
                error = exc
                Ledger.append(
                    connection,
                    scope.key,
                    request.action_id,
                    "denied",
                    {"reason": exc.reason, "at": observed},
                )
        if error:
            raise error
        return ticket

    def reconcile(
        self,
        request: PurchaseRequest,
        scope: TrustedScope,
        receipt: dict[str, Any] | None,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Only signed target evidence completes a reservation; caller claims never do."""
        observed = timestamp(now)
        with self.ledger.transaction() as connection:
            state = Ledger.latest(connection, scope.key, request.action_id, "state")
            valid = False
            if state and state["status"] == "reserved" and receipt:
                unsigned = {key: value for key, value in receipt.items() if key != "evidence_mac"}
                expected = hmac.new(
                    self._ticket_secret,
                    b"target-evidence:" + canonical_json(unsigned),
                    hashlib.sha256,
                ).hexdigest()
                valid = (
                    isinstance(receipt.get("evidence_mac"), str)
                    and hmac.compare_digest(receipt["evidence_mac"], expected)
                    and receipt.get("request_digest") == request_digest(request)
                    and receipt.get("nonce") == state["reservation"]["nonce"]
                    and receipt.get("scope") == scope.model_dump(mode="json")
                    and receipt.get("status") == "committed"
                )
            Ledger.append(
                connection,
                scope.key,
                request.action_id,
                "reconciliation",
                {"at": observed, "verified": valid, "receipt": receipt},
            )
            return valid
