from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from assurance.controlspec.canonical import finalize_object
from assurance.controlspec.contracts import ControlStatus, Verdict
from assurance.controlspec.openshell_demo.engine import DemoDenied, DemoEngine
from assurance.controlspec.openshell_demo.ledger import Ledger
from assurance.controlspec.openshell_demo.policy import (
    PurchaseRequest,
    TrustedScope,
    parse_purchase,
    synthetic_controls,
)
from assurance.controlspec.openshell_demo.target import SyntheticTarget, create_target_app

NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)
SECRET = b"synthetic-ticket-key-only-000000000000"
OPERATOR = b"synthetic-operator-key-only-1111111111"
SCOPE = TrustedScope(gateway_id="fixture-gateway", sandbox_id="fixture-sandbox")


def purchase(amount: int = 4200, action: str = "one", recurring: bool = False) -> PurchaseRequest:
    return PurchaseRequest(
        schema_version="1",
        action_id=action,
        amount_minor=amount,
        currency="USD",
        merchant="demo-store",
        recurring=recurring,
    )


def engine(tmp_path: Path, **kwargs: object) -> DemoEngine:
    return DemoEngine(tmp_path / "engine.sqlite", SECRET, OPERATOR, **kwargs)  # type: ignore[arg-type]


def test_real_evaluator_approval_target_and_reconciliation(tmp_path: Path) -> None:
    service = engine(tmp_path)
    target = SyntheticTarget(tmp_path / "target.sqlite", SECRET)
    request = purchase(14200)
    pending = service.evaluate(request, SCOPE, NOW)
    assert pending.decision.verdict is Verdict.REQUIRE_APPROVAL
    assert pending.decision.extensions["controlspec.conformance.non_authoritative"] is True
    assert pending.trace.evaluated_controls
    with pytest.raises(DemoDenied, match="approval_required"):
        service.authorize(request, SCOPE, NOW)
    assert target.state()["purchase_count"] == 0
    approved = service.approve(request.action_id, SCOPE, OPERATOR.decode(), NOW)
    assert approved.allowed
    assert approved.decision.predecessor_decision_ref is not None
    assert approved.intent.intent_digest == pending.intent.intent_digest
    token = service.authorize(request, SCOPE, NOW)
    receipt = target.commit(request, token, NOW)
    assert target.state()["spent_minor"] == 14200
    assert not service.reconcile(request, SCOPE, None, now=NOW)
    assert not service.reconcile(request, SCOPE, {"status": "committed"}, now=NOW)
    assert service.reconcile(request, SCOPE, receipt.model_dump(), now=NOW)
    assert service.ledger.verify()


def test_changed_body_and_foreign_scope_cannot_reuse_approval(tmp_path: Path) -> None:
    service = engine(tmp_path)
    request = purchase(14200)
    service.evaluate(request, SCOPE, NOW)
    service.approve("one", SCOPE, OPERATOR.decode(), NOW)
    with pytest.raises(DemoDenied, match="action_changed"):
        service.authorize(purchase(14201), SCOPE, NOW)
    foreign = TrustedScope(gateway_id="fixture-gateway", sandbox_id="other-sandbox")
    with pytest.raises(DemoDenied, match="approval_required"):
        service.authorize(request, foreign, NOW)


def test_self_approval_and_wrong_secret_rejected(tmp_path: Path) -> None:
    service = engine(tmp_path, operator_id=SCOPE.actor_id)
    service.evaluate(purchase(14200), SCOPE, NOW)
    with pytest.raises(DemoDenied, match="operator_authentication_failed"):
        service.approve("one", SCOPE, "invalid", NOW)
    with pytest.raises(DemoDenied, match="approval_rejected") as denied:
        service.approve("one", SCOPE, OPERATOR.decode(), NOW)
    assert denied.value.evaluation is not None
    assert denied.value.evaluation.decision.verdict is Verdict.BLOCK


def test_recurrence_drafts_and_policy_changes_fail_closed(tmp_path: Path) -> None:
    service = engine(tmp_path)
    assert not service.evaluate(purchase(999, recurring=True), SCOPE, NOW).allowed
    service.evaluate(purchase(14200, "two"), SCOPE, NOW)
    drafts = tuple(
        finalize_object(control.model_copy(update={"status": ControlStatus.DRAFT}))
        for control in synthetic_controls()
    )
    changed = engine(tmp_path, controls=drafts)
    with pytest.raises(DemoDenied, match="policy_changed"):
        changed.approve("two", SCOPE, OPERATOR.decode(), NOW)
    assert not changed.evaluate(purchase(action="three"), SCOPE, NOW).allowed


def test_expiry_reservation_unknown_outcome_and_restart(tmp_path: Path) -> None:
    service = engine(tmp_path)
    request = purchase(14200)
    service.evaluate(request, SCOPE, NOW)
    with pytest.raises(DemoDenied, match="pending_decision_expired"):
        service.approve("one", SCOPE, OPERATOR.decode(), NOW + timedelta(seconds=121))
    allowed = purchase(action="two")
    ticket = service.authorize(allowed, SCOPE, NOW)
    restarted = engine(tmp_path)
    assert not restarted.reconcile(allowed, SCOPE, None, now=NOW)
    with pytest.raises(DemoDenied, match="action_already_reserved"):
        restarted.authorize(allowed, SCOPE, NOW)
    target = SyntheticTarget(tmp_path / "target.sqlite", SECRET)
    with pytest.raises(DemoDenied, match="ticket_expired"):
        target.commit(allowed, ticket, NOW + timedelta(seconds=31))
    with pytest.raises(DemoDenied, match="action_expired"):
        restarted.authorize(allowed, SCOPE, NOW + timedelta(seconds=301))
    assert target.state()["purchase_count"] == 0


def test_concurrent_reservation_and_idempotent_target(tmp_path: Path) -> None:
    service = engine(tmp_path)
    target = SyntheticTarget(tmp_path / "target.sqlite", SECRET)
    request = purchase()

    def reserve(_: int) -> str | None:
        try:
            return service.authorize(request, SCOPE, NOW)
        except DemoDenied:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        tickets = [ticket for ticket in pool.map(reserve, range(8)) if ticket is not None]
    assert len(tickets) == 1
    with ThreadPoolExecutor(max_workers=8) as pool:
        receipts = list(pool.map(lambda _: target.commit(request, tickets[0], NOW), range(8)))
    assert len({receipt.evidence_id for receipt in receipts}) == 1
    assert target.state()["purchase_count"] == 1
    with pytest.raises(DemoDenied, match="ticket_request_mismatch"):
        target.commit(purchase(5000), tickets[0], NOW)
    with pytest.raises(DemoDenied, match="invalid_ticket"):
        target.commit(request, tickets[0][:-8] + "12345678", NOW)


@pytest.mark.parametrize(
    "update",
    [
        {"amount_minor": True},
        {"amount_minor": 1.5},
        {"amount_minor": "4200"},
        {"amount_minor": -1},
        {"currency": "EUR"},
        {"principal": "admin"},
        {"recurring": "false"},
    ],
)
def test_strict_schema(update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        parse_purchase(json.dumps(purchase().model_dump() | update).encode())


def test_duplicate_keys_and_missing_values() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        parse_purchase(b'{"action_id":"one","action_id":"two"}')
    with pytest.raises(ValidationError):
        parse_purchase(b"{}")


def test_append_only_events_reconstruction_and_unknown_schema(tmp_path: Path) -> None:
    service = engine(tmp_path)
    service.evaluate(purchase(), SCOPE, NOW)
    pending = service.pending("one", SCOPE)
    assert pending is not None
    assert service.ledger.events()[-1]["payload"] == pending
    with sqlite3.connect(service.ledger.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM events")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE events SET kind='corrupt'")
    unknown = tmp_path / "unknown.sqlite"
    with sqlite3.connect(unknown) as connection:
        connection.execute("PRAGMA user_version=999")
    with pytest.raises(ValueError, match="unsupported"):
        Ledger(unknown)


def test_approved_fact_expires_and_cannot_be_refreshed_by_agent(tmp_path: Path) -> None:
    service = engine(tmp_path)
    request = purchase(14200)
    service.evaluate(request, SCOPE, NOW)
    service.approve("one", SCOPE, OPERATOR.decode(), NOW)
    later = NOW + timedelta(seconds=121)
    assert service.evaluate(request, SCOPE, later).decision.verdict is Verdict.REQUIRE_APPROVAL
    with pytest.raises(DemoDenied, match="approval_required"):
        service.authorize(request, SCOPE, later)
    with pytest.raises(DemoDenied, match="action_not_pending"):
        service.approve("one", SCOPE, OPERATOR.decode(), later)


def test_target_http_boundary_no_ticket_no_effect(tmp_path: Path) -> None:
    service = engine(tmp_path)
    request = purchase()
    app = create_target_app(tmp_path / "http-target.sqlite", SECRET)
    with TestClient(app) as client:
        assert client.post("/purchases", json=request.model_dump()).status_code == 403
        assert client.get("/state").json()["purchase_count"] == 0
        ticket = service.authorize(request, SCOPE)
        headers = {"X-ControlSpec-Ticket": ticket}
        changed = purchase(4201).model_dump()
        assert client.post("/purchases", json=changed, headers=headers).status_code == 403
        assert (
            client.post(
                "/purchases?alias=1", json=request.model_dump(), headers=headers
            ).status_code
            == 400
        )
        assert client.post("/other", json=request.model_dump(), headers=headers).status_code == 404
        assert client.get("/state").json()["purchase_count"] == 0
        receipt = client.post("/purchases", json=request.model_dump(), headers=headers)
        assert receipt.status_code == 200
        duplicate = client.post("/purchases", json=request.model_dump(), headers=headers)
        assert duplicate.json() == receipt.json()
        assert client.get("/state").json()["purchase_count"] == 1
        proof = receipt.json()
        proof["amount_minor"] = 1
        assert not service.reconcile(request, SCOPE, proof)


def test_gateway_scope_is_separate_and_durable(tmp_path: Path) -> None:
    service = engine(tmp_path)
    request = purchase(14200)
    service.evaluate(request, SCOPE, NOW)
    other_gateway = TrustedScope(gateway_id="other", sandbox_id=SCOPE.sandbox_id)
    assert service.pending("one", other_gateway) is None
    with pytest.raises(DemoDenied, match="unknown_pending_action"):
        service.approve("one", other_gateway, OPERATOR.decode(), NOW)
    assert engine(tmp_path).pending("one", SCOPE) is not None


def test_corrupted_event_chain_fails_startup(tmp_path: Path) -> None:
    service = engine(tmp_path)
    service.evaluate(purchase(), SCOPE, NOW)
    # Demonstrates detection, not protection from a host administrator.
    with sqlite3.connect(service.ledger.path) as connection:
        connection.execute("DROP TRIGGER immutable_update")
        connection.execute("UPDATE events SET payload='{}'")
    with pytest.raises(ValueError, match="chain verification failed"):
        engine(tmp_path)
