"""Separate synthetic target: signed exact tickets, idempotent mutation and evidence."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationError

from assurance.contracts.canonical import canonical_json, sha256_digest
from assurance.controlspec.contracts import HashDigest, UtcTimestamp
from assurance.controlspec.openshell_demo.engine import DemoDenied, verify_ticket
from assurance.controlspec.openshell_demo.ledger import Ledger
from assurance.controlspec.openshell_demo.policy import (
    PurchaseRequest,
    TrustedScope,
    parse_purchase,
    request_digest,
    timestamp,
)


class ExecutionTicket(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    schema_version: Literal["1"]
    purpose: Literal["synthetic-purchase-only"]
    scope: TrustedScope
    action_id: str
    request_digest: HashDigest
    policy_digest: HashDigest
    decision_digest: HashDigest
    method: Literal["POST"]
    path: Literal["/purchases"]
    issued_at: UtcTimestamp
    expires_at: UtcTimestamp
    nonce: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class TargetReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    schema_version: Literal["1"] = "1"
    synthetic_only: Literal[True] = True
    status: Literal["committed"] = "committed"
    action_id: str
    scope: dict[str, str]
    request_digest: str
    nonce: str
    amount_minor: int
    committed_at: str
    evidence_id: str
    evidence_mac: str


class SyntheticTarget:
    def __init__(self, db_path: str | Path, ticket_secret: bytes) -> None:
        if len(ticket_secret) < 32:
            raise ValueError("target ticket secret requires at least 32 bytes")
        self.ledger = Ledger(db_path)
        self._secret = ticket_secret

    def commit(
        self, request: PurchaseRequest, ticket: str, now: datetime | None = None
    ) -> TargetReceipt:
        try:
            binding = ExecutionTicket.model_validate(verify_ticket(ticket, self._secret))
        except ValidationError as exc:
            raise DemoDenied("invalid_ticket") from exc
        observed = timestamp(now)
        if not (binding.issued_at <= observed < binding.expires_at):
            raise DemoDenied("ticket_expired")
        if binding.action_id != request.action_id or binding.request_digest != request_digest(
            request
        ):
            raise DemoDenied("ticket_request_mismatch")
        return self._commit(request, binding.scope, binding.nonce, observed)

    def commit_unguarded(
        self, request: PurchaseRequest, scope: TrustedScope, now: datetime | None = None
    ) -> TargetReceipt:
        """Explicit host harness baseline. Never exposed by create_target_app."""
        return self._commit(request, scope, "unguarded-synthetic-baseline", timestamp(now))

    def _commit(
        self, request: PurchaseRequest, scope: TrustedScope, nonce: str, observed: str
    ) -> TargetReceipt:
        digest = request_digest(request)
        with self.ledger.transaction() as connection:
            previous = Ledger.latest(connection, scope.key, request.action_id, "purchase")
            if previous is not None:
                if previous["request_digest"] != digest or previous["nonce"] != nonce:
                    raise DemoDenied("target_idempotency_conflict")
                return TargetReceipt.model_validate(previous)
            receipt = {
                "schema_version": "1",
                "synthetic_only": True,
                "status": "committed",
                "action_id": request.action_id,
                "scope": scope.model_dump(mode="json"),
                "request_digest": digest,
                "nonce": nonce,
                "amount_minor": request.amount_minor,
                "committed_at": observed,
                "evidence_id": sha256_digest(
                    canonical_json(
                        {
                            "scope": scope.key,
                            "action_id": request.action_id,
                            "nonce": nonce,
                            "request_digest": digest,
                        }
                    )
                ),
            }
            receipt["evidence_mac"] = hmac.new(
                self._secret, b"target-evidence:" + canonical_json(receipt), hashlib.sha256
            ).hexdigest()
            value = TargetReceipt.model_validate(receipt)
            Ledger.append(connection, scope.key, request.action_id, "purchase", value.model_dump())
            return value

    def state(self) -> dict[str, Any]:
        purchases = [
            event["payload"] for event in self.ledger.events() if event["kind"] == "purchase"
        ]
        spent = sum(purchase["amount_minor"] for purchase in purchases)
        return {
            "synthetic_only": True,
            "purchase_count": len(purchases),
            "spent_minor": spent,
            "balance_minor": 1_000_000 - spent,
            "purchases": purchases,
        }


def create_target_app(db_path: str | Path, ticket_secret: bytes) -> FastAPI:
    """Bind with uvicorn to loopback only. No unguarded endpoint or external effects."""
    target = SyntheticTarget(db_path, ticket_secret)
    app = FastAPI(title="ControlSpec synthetic purchase target", docs_url=None, redoc_url=None)
    app.state.target = target

    @app.get("/state")
    def state() -> dict[str, Any]:
        return target.state()

    @app.post("/purchases")
    async def purchase(request: Request) -> dict[str, Any]:
        if request.url.query:
            raise HTTPException(400, "query parameters are not supported")
        if request.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
            raise HTTPException(415, "application/json required")
        if len(request.headers.getlist("x-controlspec-ticket")) != 1:
            raise HTTPException(403, "exactly one execution ticket required")
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 16384:
                raise HTTPException(413, "body too large")
        try:
            body = parse_purchase(bytes(raw))
            receipt = target.commit(body, request.headers["x-controlspec-ticket"])
            return receipt.model_dump()
        except DemoDenied as exc:
            raise HTTPException(403, exc.reason) from exc
        except (ValueError, ValidationError) as exc:
            raise HTTPException(400, "invalid purchase schema") from exc

    return app
