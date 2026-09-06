from __future__ import annotations

import asyncio
import io
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import ProxyHandler

import pytest
from fastapi import FastAPI
from pydantic import ValidationError
from starlette.types import Message, Scope

from assurance.api.controlspec import create_default_controlspec_reference_app
from assurance.contracts.canonical import canonical_json
from assurance.controlspec import client as client_module
from assurance.controlspec.api_models import (
    ComparisonStatus,
    ControlSpecApiErrorCode,
    DecideRequest,
    EvaluationOptions,
    PackSelection,
    ReceiptAssessmentRequest,
    RecheckRequest,
    ReferenceReportedExecution,
    ReferenceTimeOptions,
)
from assurance.controlspec.canonical import verify_object_digest
from assurance.controlspec.client import (
    ControlSpecReferenceClient,
    ReferenceClientError,
    ReferenceHttpError,
    ReferenceProtocolError,
    ReferenceTransportError,
    TransportResponse,
    build_action_intent,
)
from assurance.controlspec.contracts import (
    Action,
    ActionIntent,
    Actor,
    ActorType,
    CanonicalAction,
    JsonValue,
    ReceiptStatus,
    Resource,
    Verdict,
)

NOW = "2026-09-05T16:00:00.000000Z"


class AppTransport:
    """In-process ASGI adapter exercising actual middleware and routes."""

    def __init__(self, app: FastAPI) -> None:
        self.app = app
        self.calls: list[tuple[str, str, bytes | None]] = []

    def __call__(
        self,
        *,
        method: str,
        url: str,
        body: bytes | None,
        timeout: float,
        max_response_bytes: int,
    ) -> TransportResponse:
        self.calls.append((method, url, body))
        parsed = urlsplit(url)
        messages: list[Message] = []
        scope: Scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": parsed.scheme,
            "path": unquote(parsed.path),
            "raw_path": parsed.path.encode(),
            "query_string": b"",
            "root_path": "",
            "headers": [(b"content-type", b"application/json")],
            "server": ("testserver", 80),
            "client": ("testclient", 1234),
        }

        async def receive() -> Message:
            return {"type": "http.request", "body": body or b"", "more_body": False}

        async def send(message: Message) -> None:
            messages.append(message)

        asyncio.run(self.app(scope, receive, send))
        start = next(message for message in messages if message["type"] == "http.response.start")
        headers = dict(start["headers"])
        data = b"".join(message.get("body", b"") for message in messages)
        return TransportResponse(start["status"], headers[b"content-type"].decode(), data)


@pytest.fixture
def connected() -> tuple[ControlSpecReferenceClient, AppTransport]:
    transport = AppTransport(create_default_controlspec_reference_app())
    return ControlSpecReferenceClient("http://testserver", transport=transport), transport


def intent(domain: str = "personal", *, changed: bool = False) -> ActionIntent:
    namespace = "personal.agent.spending" if domain == "personal" else "smb.sales.controls"
    context: dict[str, JsonValue] = (
        {
            "personal.spending.total_minor_units": 14200 if changed else 4200,
            "personal.spending.recurring": False,
        }
        if domain == "personal"
        else {"smb.sales.discount_basis_points": 1500 if changed else 800}
    )
    return build_action_intent(
        namespace=namespace,
        intent_id=f"new-{domain}",
        actor=Actor(
            namespace=namespace,
            actor_id="agent",
            version="1",
            type=ActorType.AGENT,
            owner_ref=None,
            lineage_refs=(),
            attributes={},
        ),
        action=Action(
            type=CanonicalAction.COMMIT if domain == "personal" else CanonicalAction.COMMUNICATE,
            domain_action="personal.purchase"
            if domain == "personal"
            else "smb.sales.offer_discount",
            requested_effect={"example.request": "simulation"},
        ),
        resource=Resource(
            namespace=namespace,
            resource_id="resource",
            version="1",
            type="personal.cart" if domain == "personal" else "smb.customer_email",
            business_id=None,
            attributes={},
        ),
        context=context,
        requested_at=NOW,
        idempotency_key=f"new-{domain}",
    )


def selection(client: ControlSpecReferenceClient, namespace: str) -> PackSelection:
    summary = next(item for item in client.list_packs().items if item.namespace == namespace)
    return PackSelection(catalog_id=summary.catalog_id, semantic_digest=summary.semantic_digest)


@pytest.mark.parametrize("domain", ["personal", "sales"])
def test_existing_app_all_seven_operations_and_changed_binding(
    connected: tuple[ControlSpecReferenceClient, AppTransport],
    domain: str,
) -> None:
    client, transport = connected
    original = intent(domain)
    selected = selection(client, original.namespace)
    pack = client.get_pack(selected.catalog_id)
    assert pack.summary.semantic_digest == selected.semantic_digest
    control = client.get_control(pack.control_catalog_ids[0])
    assert any(
        item.catalog_id == control.summary.catalog_id for item in client.list_controls().items
    )
    options = EvaluationOptions(reference_time=NOW)
    result = client.decide(
        DecideRequest(action_intent=original, selection=selected, options=options)
    )
    assert result.decision.verdict is (
        Verdict.ALLOW if domain == "personal" else Verdict.ALLOW_WITH_CONDITIONS
    )
    assert result.authority.may_authorize_external_effect is False
    assert result.decision.binding.intent_digest == original.intent_digest
    checked = client.recheck(
        RecheckRequest(
            original_action_intent=original,
            prior_decision=result.decision,
            current_action_intent=original,
            selection=selected,
            options=options,
        )
    )
    assert checked.recheck.valid is True
    changed = client.recheck(
        RecheckRequest(
            original_action_intent=original,
            prior_decision=result.decision,
            current_action_intent=intent(domain, changed=True),
            selection=selected,
            options=options,
        )
    )
    assert changed.recheck.valid is False
    assert changed.comparisons.context is ComparisonStatus.CHANGED
    assessed = client.assess_receipt(
        ReceiptAssessmentRequest(
            action_intent=original,
            decision=result.decision,
            selection=selected,
            reported_execution=ReferenceReportedExecution(
                actual_route=result.decision.route,
                execution_result="example.simulated_success",
                evidence_refs=(),
                business_outcome="example.simulated_outcome",
                occurred_at=NOW,
            ),
            options=ReferenceTimeOptions(reference_time=NOW),
        )
    )
    assert assessed.receipt.status is not ReceiptStatus.COMPLETE
    assert assessed.stored is False and assessed.durable is False
    assert assessed.assessment_basis == "caller_report_only"
    for method, _, body in transport.calls:
        if method == "POST":
            assert body is not None and canonical_json(json.loads(body)) == body


def test_builder_is_deterministic_strict_and_detaches_mutable_inputs() -> None:
    first = intent()
    assert first == intent() and verify_object_digest(first)
    context = dict(first.context)
    copied = build_action_intent(
        namespace=first.namespace,
        intent_id=first.intent_id,
        actor=first.actor,
        action=first.action,
        resource=first.resource,
        context=context,
        requested_at=NOW,
        idempotency_key=first.idempotency_key,
    )
    context["personal.spending.recurring"] = True
    first.actor.attributes["example.mutated"] = True
    assert copied.context["personal.spending.recurring"] is False
    assert copied.actor.attributes == {}
    assert verify_object_digest(copied)
    with pytest.raises(ValidationError):
        build_action_intent(
            namespace=first.namespace,
            intent_id=first.intent_id,
            actor=first.actor,
            action=first.action,
            resource=first.resource,
            context={},
            requested_at="2026-09-05T16:00:00Z",
            idempotency_key="test",
        )


def test_typed_server_errors_keep_status_and_never_replace_exact_selection(
    connected: tuple[ControlSpecReferenceClient, AppTransport],
) -> None:
    client, transport = connected
    with pytest.raises(ReferenceHttpError) as missing:
        client.get_pack("custom.example:unpublished@0.1.0")
    assert missing.value.status == 404
    assert missing.value.body.error.code is ControlSpecApiErrorCode.CATALOG_ITEM_NOT_FOUND
    original = intent()
    chosen = selection(client, original.namespace)
    bad = PackSelection(catalog_id=chosen.catalog_id, semantic_digest="sha256:" + "0" * 64)
    before = len(transport.calls)
    with pytest.raises(ReferenceHttpError) as mismatch:
        client.decide(DecideRequest(action_intent=original, selection=bad))
    assert mismatch.value.status == 409
    assert len(transport.calls) == before + 1
    with pytest.raises(ReferenceHttpError) as invalid:
        client.decide(
            DecideRequest(
                action_intent=original.model_copy(update={"intent_digest": "sha256:" + "0" * 64}),
                selection=chosen,
            )
        )
    assert invalid.value.status == 422


class FixedTransport:
    def __init__(self, response: TransportResponse) -> None:
        self.response = response
        self.calls: list[str] = []

    def __call__(
        self,
        *,
        method: str,
        url: str,
        body: bytes | None,
        timeout: float,
        max_response_bytes: int,
    ) -> TransportResponse:
        self.calls.append(url)
        return self.response


@pytest.mark.parametrize(
    "body",
    [
        b'{"items":[],"items":[]}',
        b'{"x":1.0}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":9223372036854775808}',
        b"[]",
        b"{",
        b"\xff",
        b'{"items":[],"catalog_digest":"sha256:bad"}',
    ],
)
def test_corrupt_json_is_explicit_error_without_retry(body: bytes) -> None:
    transport = FixedTransport(TransportResponse(200, "application/json", body))
    with pytest.raises(ReferenceProtocolError):
        ControlSpecReferenceClient(transport=transport).list_packs()
    assert len(transport.calls) == 1


@pytest.mark.parametrize("mutation", ["missing", "true", "zero", "wrong_mode", "unknown"])
def test_missing_or_non_reference_authority_is_rejected(
    connected: tuple[ControlSpecReferenceClient, AppTransport],
    mutation: str,
) -> None:
    client, _ = connected
    document = client.list_packs().model_dump(mode="json")
    if mutation == "missing":
        del document["authority"]
    elif mutation == "true":
        document["authority"]["may_authorize_external_effect"] = True
    elif mutation == "zero":
        document["authority"]["durable"] = 0
    elif mutation == "wrong_mode":
        document["authority"]["authority_mode"] = "production"
    else:
        document["authority"]["extra"] = False
    transport = FixedTransport(TransportResponse(200, "application/json", canonical_json(document)))
    with pytest.raises(ReferenceProtocolError):
        ControlSpecReferenceClient(transport=transport).list_packs()


@pytest.mark.parametrize(
    "status,content_type,body",
    [
        (307, "application/json", b"{}"),
        (201, "application/json", b"{}"),
        (500, "text/html", b"<html>error</html>"),
        (422, "application/json", b"{}"),
        (200, "text/plain", b"{}"),
    ],
)
def test_unexpected_status_or_malformed_error_is_explicit(
    status: int,
    content_type: str,
    body: bytes,
) -> None:
    transport = FixedTransport(TransportResponse(status, content_type, body))
    with pytest.raises(ReferenceProtocolError) as failed:
        ControlSpecReferenceClient(transport=transport).list_packs()
    assert failed.value.status == status
    assert len(transport.calls) == 1


def test_path_segment_encoding_and_both_body_bounds() -> None:
    transport = FixedTransport(TransportResponse(200, "application/json", b"{}"))
    client = ControlSpecReferenceClient(transport=transport, max_request_bytes=1)
    with pytest.raises(ReferenceProtocolError):
        client.get_pack("custom.example:a/b?x=1#fragment")
    assert transport.calls == [
        "http://127.0.0.1:8000/controlspec/v0/packs/custom.example%3Aa%2Fb%3Fx%3D1%23fragment",
    ]
    with pytest.raises(ReferenceClientError, match="not sent"):
        client.decide(
            DecideRequest(
                action_intent=intent(),
                selection=PackSelection(
                    catalog_id="personal.agent.spending:spending-baseline@0.1.0",
                    semantic_digest="sha256:" + "0" * 64,
                ),
            )
        )
    assert len(transport.calls) == 1
    with pytest.raises(ReferenceProtocolError, match="byte limit"):
        ControlSpecReferenceClient(transport=transport, max_response_bytes=1).list_packs()


@pytest.mark.parametrize(
    "url",
    [
        "file:///tmp/x",
        "http://u:p@localhost",
        "http://localhost/path",
        "http://localhost?x=1",
        "http://localhost/#x",
        "http://local\nhost",
    ],
)
def test_unsafe_origins_are_rejected(url: str) -> None:
    with pytest.raises(ValueError):
        ControlSpecReferenceClient(url)


@pytest.mark.parametrize("timeout", [0, -1, 61, float("inf"), float("nan"), True])
def test_timeout_is_bounded(timeout: float) -> None:
    with pytest.raises(ValueError):
        ControlSpecReferenceClient(timeout=timeout)


@pytest.mark.parametrize("failure", [TimeoutError(), URLError("offline")])
def test_default_transport_disables_proxies_and_does_not_retry_post(
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    calls: list[Any] = []

    class Opener:
        def open(self, request: Any, *, timeout: float) -> Any:
            calls.append((request, timeout))
            raise failure

    def opener(*handlers: Any) -> Opener:
        assert any(
            isinstance(handler, ProxyHandler) and handler.proxies == {} for handler in handlers
        )
        redirect = next(
            handler for handler in handlers if isinstance(handler, client_module._NoRedirect)
        )
        assert redirect.redirect_request(None, None, 307, "", {}, "http://other") is None
        return Opener()

    monkeypatch.setenv("HTTP_PROXY", "http://untrusted-proxy")
    monkeypatch.setattr(client_module, "build_opener", opener)
    with pytest.raises(ReferenceTransportError):
        client_module._UrllibTransport()(
            method="POST",
            url="http://localhost/controlspec/v0/decide",
            body=b"{}",
            timeout=2,
            max_response_bytes=100,
        )
    assert len(calls) == 1
    assert calls[0][0].get_header("Content-type") == "application/json"


def test_default_transport_http_error_read_is_bounded_and_redirect_not_followed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[int] = []
    calls: list[Any] = []

    class Body(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            reads.append(size)
            return super().read(size)

    class Opener:
        def open(self, request: Any, *, timeout: float) -> Any:
            calls.append(request)
            raise HTTPError(request.full_url, 307, "redirect", {}, Body(b"{}"))

    monkeypatch.setattr(client_module, "build_opener", lambda *args: Opener())
    with pytest.raises(ReferenceProtocolError, match="redirect/retry"):
        ControlSpecReferenceClient(max_response_bytes=2).list_packs()
    assert reads == [3] and len(calls) == 1
    with pytest.raises(ReferenceTransportError, match="byte limit"):
        ControlSpecReferenceClient(max_response_bytes=1).list_packs()
    assert reads == [3, 2] and len(calls) == 2


@pytest.mark.parametrize("corruption", ["digest", "intent_binding", "selection_binding"])
def test_decision_corruption_never_returns_a_verdict(
    connected: tuple[ControlSpecReferenceClient, AppTransport],
    corruption: str,
) -> None:
    client, _ = connected
    original = intent()
    request = DecideRequest(
        action_intent=original,
        selection=selection(client, original.namespace),
        options=EvaluationOptions(reference_time=NOW),
    )
    result = client.decide(request)
    document = result.model_dump(mode="json", by_alias=True)
    if corruption == "digest":
        document["decision"]["semantic_digest"] = "sha256:" + "0" * 64
    elif corruption == "selection_binding":
        document["catalog_binding"]["selection_digest"] = "sha256:" + "0" * 64
    else:
        from assurance.controlspec.canonical import finalize_object

        changed = result.decision.model_copy(
            update={
                "intent_ref": result.decision.intent_ref.model_copy(
                    update={"intent_id": "other-intent"}
                ),
            }
        )
        document["decision"] = finalize_object(changed).model_dump(mode="json", by_alias=True)
    transport = FixedTransport(TransportResponse(200, "application/json", canonical_json(document)))
    with pytest.raises(ReferenceProtocolError):
        ControlSpecReferenceClient(transport=transport).decide(request)
    assert len(transport.calls) == 1


def test_pack_digest_and_recheck_prior_reference_corruption(
    connected: tuple[ControlSpecReferenceClient, AppTransport],
) -> None:
    client, _ = connected
    original = intent()
    selected = selection(client, original.namespace)
    pack = client.get_pack(selected.catalog_id).model_dump(mode="json", by_alias=True)
    pack["pack"]["semantic_digest"] = "sha256:" + "0" * 64
    transport = FixedTransport(TransportResponse(200, "application/json", canonical_json(pack)))
    with pytest.raises(ReferenceProtocolError):
        ControlSpecReferenceClient(transport=transport).get_pack(selected.catalog_id)
    prior = client.decide(
        DecideRequest(
            action_intent=original,
            selection=selected,
            options=EvaluationOptions(reference_time=NOW),
        )
    ).decision
    request = RecheckRequest(
        original_action_intent=original,
        current_action_intent=original,
        prior_decision=prior,
        selection=selected,
        options=EvaluationOptions(reference_time=NOW),
    )
    result = client.recheck(request).model_dump(mode="json", by_alias=True)
    result["recheck"]["prior_decision_ref"]["decision_id"] = "different-decision"
    transport = FixedTransport(TransportResponse(200, "application/json", canonical_json(result)))
    with pytest.raises(ReferenceProtocolError):
        ControlSpecReferenceClient(transport=transport).recheck(request)


@pytest.mark.parametrize("corruption", ["receipt_digest", "stored_zero", "durable_missing"])
def test_receipt_corruption_is_explicit(
    connected: tuple[ControlSpecReferenceClient, AppTransport],
    corruption: str,
) -> None:
    client, _ = connected
    original = intent()
    selected = selection(client, original.namespace)
    decision = client.decide(
        DecideRequest(
            action_intent=original,
            selection=selected,
            options=EvaluationOptions(reference_time=NOW),
        )
    ).decision
    request = ReceiptAssessmentRequest(
        action_intent=original,
        decision=decision,
        selection=selected,
        reported_execution=ReferenceReportedExecution(
            actual_route=decision.route,
            execution_result="example.simulated_success",
            evidence_refs=(),
            business_outcome=None,
            occurred_at=NOW,
        ),
        options=ReferenceTimeOptions(reference_time=NOW),
    )
    document = client.assess_receipt(request).model_dump(mode="json", by_alias=True)
    if corruption == "receipt_digest":
        document["receipt"]["receipt_digest"] = "sha256:" + "0" * 64
    elif corruption == "stored_zero":
        document["stored"] = 0
    else:
        del document["durable"]
    transport = FixedTransport(TransportResponse(200, "application/json", canonical_json(document)))
    with pytest.raises(ReferenceProtocolError):
        ControlSpecReferenceClient(transport=transport).assess_receipt(request)


def test_fresh_example_journey_uses_the_real_app_without_external_effects(
    connected: tuple[ControlSpecReferenceClient, AppTransport],
) -> None:
    import runpy
    from pathlib import Path

    example = Path(__file__).resolve().parents[3] / "examples/controlspec/client_journey.py"
    client, transport = connected
    module = runpy.run_path(str(example))
    result = module["run_journey"](client, requested_at=NOW, idempotency_prefix="fresh-test")
    assert result["simulation_only"] is True
    for namespace in ("personal.agent.spending", "smb.sales.controls"):
        assert result[namespace]["same_binding_valid"] is True
        assert result[namespace]["changed_binding_valid"] is False
        assert result[namespace]["may_authorize_external_effect"] is False
        assert result[namespace]["stored"] is False
    assert all(url.startswith("http://testserver/controlspec/v0/") for _, url, _ in transport.calls)


@pytest.mark.parametrize("field", ["actor", "resource", "action", "domain_action"])
def test_rehashed_decision_cannot_contradict_explicit_request_binding(
    connected: tuple[ControlSpecReferenceClient, AppTransport],
    field: str,
) -> None:
    from assurance.controlspec.canonical import finalize_object

    client, _ = connected
    original = intent()
    request = DecideRequest(
        action_intent=original,
        selection=selection(client, original.namespace),
        options=EvaluationOptions(reference_time=NOW),
    )
    result = client.decide(request)
    binding = result.decision.binding
    if field == "actor":
        binding = binding.model_copy(
            update={"actor_ref": binding.actor_ref.model_copy(update={"actor_id": "another-agent"})}
        )
    elif field == "resource":
        binding = binding.model_copy(
            update={
                "resource_ref": binding.resource_ref.model_copy(
                    update={"resource_id": "another-resource"}
                )
            }
        )
    elif field == "action":
        binding = binding.model_copy(update={"action_type": CanonicalAction.COMMUNICATE})
    else:
        binding = binding.model_copy(update={"domain_action": "example.different_action"})
    result = result.model_copy(
        update={
            "decision": finalize_object(result.decision.model_copy(update={"binding": binding}))
        }
    )
    transport = FixedTransport(TransportResponse(200, "application/json", canonical_json(result)))
    with pytest.raises(ReferenceProtocolError):
        ControlSpecReferenceClient(transport=transport).decide(request)


@pytest.mark.parametrize("contradiction", ["reason", "comparison", "missing_current", "expiry"])
def test_inconsistent_successful_recheck_is_rejected(
    connected: tuple[ControlSpecReferenceClient, AppTransport],
    contradiction: str,
) -> None:
    client, _ = connected
    original = intent()
    selected = selection(client, original.namespace)
    decision = client.decide(
        DecideRequest(
            action_intent=original,
            selection=selected,
            options=EvaluationOptions(reference_time=NOW),
        )
    ).decision
    request = RecheckRequest(
        original_action_intent=original,
        current_action_intent=original,
        prior_decision=decision,
        selection=selected,
        options=EvaluationOptions(reference_time=NOW),
    )
    document = client.recheck(request).model_dump(mode="json", by_alias=True)
    if contradiction == "reason":
        document["recheck"]["reason_code"] = "controlspec.core.recheck.expired"
    elif contradiction == "comparison":
        document["comparisons"]["decision_window"] = "changed"
    elif contradiction == "missing_current":
        document["recheck"]["current_decision_ref"] = None
    else:
        request = request.model_copy(
            update={"options": EvaluationOptions(reference_time=decision.expires_at)}
        )
    transport = FixedTransport(TransportResponse(200, "application/json", canonical_json(document)))
    with pytest.raises(ReferenceProtocolError):
        ControlSpecReferenceClient(transport=transport).recheck(request)


def test_rehashed_complete_caller_report_cannot_claim_execution(
    connected: tuple[ControlSpecReferenceClient, AppTransport],
) -> None:
    from assurance.controlspec.canonical import finalize_object
    from assurance.controlspec.contracts import ExecutionOutcome, ReceiptOutcome

    client, _ = connected
    original = intent()
    selected = selection(client, original.namespace)
    decision = client.decide(
        DecideRequest(
            action_intent=original,
            selection=selected,
            options=EvaluationOptions(reference_time=NOW),
        )
    ).decision
    request = ReceiptAssessmentRequest(
        action_intent=original,
        decision=decision,
        selection=selected,
        reported_execution=ReferenceReportedExecution(
            actual_route=decision.route,
            execution_result="example.simulated_success",
            evidence_refs=(),
            business_outcome=None,
            occurred_at=NOW,
        ),
        options=ReferenceTimeOptions(reference_time=NOW),
    )
    result = client.assess_receipt(request)
    receipt = finalize_object(
        result.receipt.model_copy(
            update={
                "status": ReceiptStatus.COMPLETE,
                "execution_outcome": ExecutionOutcome.SUCCEEDED,
                "outcome": ReceiptOutcome.COMPLETED,
                "missing_evidence_requirement_ids": (),
            }
        )
    )
    result = result.model_copy(update={"receipt": receipt})
    transport = FixedTransport(TransportResponse(200, "application/json", canonical_json(result)))
    with pytest.raises(ReferenceProtocolError):
        ControlSpecReferenceClient(transport=transport).assess_receipt(request)
