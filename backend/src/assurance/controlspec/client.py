"""Typed, non-authoritative client for the seven existing reference operations.

Trace: changes/0009-controlspec-operational-transition/frame.md H04-H06.
This module never invokes an external target or interprets ALLOW as permission.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from http.client import HTTPException
from typing import Annotated, Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from pydantic import BaseModel, BeforeValidator, ValidationError

from assurance.contracts.canonical import canonical_json, sha256_digest
from assurance.controlspec.api_models import (
    ComparisonStatus,
    ControlDetailResponse,
    ControlListResponse,
    ControlSpecApiErrorBody,
    ControlSpecApiErrorResponse,
    ControlSpecValidationIssue,
    ControlSummary,
    DecideRequest,
    DecideResponse,
    PackDetailResponse,
    PackListResponse,
    PackSummary,
    ReceiptAssessmentRequest,
    ReceiptAssessmentResponse,
    RecheckRequest,
    RecheckResponse,
)
from assurance.controlspec.canonical import (
    canonical_context_hash,
    canonical_object_digest,
    finalize_object,
    verify_object_digest,
)
from assurance.controlspec.contracts import (
    Action,
    ActionIntent,
    Actor,
    Amount,
    EvidenceRef,
    ExecutionOutcome,
    JsonValue,
    ReceiptStatus,
    Resource,
    Route,
)


def _wire_array(value: Any) -> tuple[Any, ...]:
    if not isinstance(value, list | tuple):
        raise ValueError("wire sequence must be a JSON array")
    return tuple(value)


# In Pydantic 2.13 the inherited model before-validator loses JSON tuple handling.
# Normalize only the existing plain tuple fields; scalar and extra-field checks
# stay strict. These subclasses add no fields and do not change API contracts.
class _PackListWire(PackListResponse):
    items: Annotated[tuple[PackSummary, ...], BeforeValidator(_wire_array)]


class _ControlListWire(ControlListResponse):
    items: Annotated[tuple[ControlSummary, ...], BeforeValidator(_wire_array)]


class _IssueWire(ControlSpecValidationIssue):
    loc: Annotated[tuple[str | int, ...], BeforeValidator(_wire_array)]


class _ErrorBodyWire(ControlSpecApiErrorBody):
    issues: Annotated[tuple[_IssueWire, ...], BeforeValidator(_wire_array)] = ()


class _ErrorWire(ControlSpecApiErrorResponse):
    error: _ErrorBodyWire


def build_action_intent(
    *,
    namespace: str,
    intent_id: str,
    actor: Actor,
    action: Action,
    resource: Resource,
    context: dict[str, JsonValue],
    requested_at: str,
    idempotency_key: str,
    route: Route | None = None,
    evidence_refs: tuple[EvidenceRef, ...] = (),
    cost: Amount | None = None,
    retry_count: int | None = None,
) -> ActionIntent:
    """Build a fresh digest-valid intent; caller owns time and idempotency identity.

    Revalidate and detach nested mutable values before hashing. No time, actor,
    route or policy selection is inferred, and no policy is published.
    """
    intent = ActionIntent(
        schema="controlspec/v0/action-intent",
        namespace=namespace,
        intent_id=intent_id,
        actor=actor,
        action=action,
        resource=resource,
        context=context,
        requested_at=requested_at,
        idempotency_key=idempotency_key,
        requested_route=route,
        evidence_refs=evidence_refs,
        cost=cost,
        retry_count=retry_count,
        context_digest=canonical_context_hash(context),
    )
    detached = ActionIntent.model_validate_json(_model_bytes(intent), strict=True)
    return finalize_object(detached)


class ReferenceClientError(Exception):
    """The operation failed; this exception never represents an ALLOW verdict."""


class ReferenceTransportError(ReferenceClientError):
    """Network failure or exceeded response bound; requests are never retried."""


class ReferenceProtocolError(ReferenceClientError):
    """Unexpected HTTP status or invalid/ambiguous/non-reference response."""

    def __init__(self, message: str, *, status: int) -> None:
        super().__init__(message)
        self.status = status


class ReferenceHttpError(ReferenceClientError):
    """An explicit typed server failure, retaining its HTTP status and body."""

    def __init__(self, status: int, body: ControlSpecApiErrorResponse) -> None:
        super().__init__(f"ControlSpec HTTP {status}: {body.error.code.value}")
        self.status = status
        self.body = body


@dataclass(frozen=True)
class TransportResponse:
    status: int
    content_type: str
    body: bytes


class ReferenceTransport(Protocol):
    """Trusted HTTP seam for tests/embedding, never an action-execution hook.

    Implementations must enforce the supplied bounds and prohibit redirects and
    retries. The client also checks final size, status, and strict response shape.
    """

    def __call__(
        self,
        *,
        method: str,
        url: str,
        body: bytes | None,
        timeout: float,
        max_response_bytes: int,
    ) -> TransportResponse: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class _UrllibTransport:
    def __call__(
        self,
        *,
        method: str,
        url: str,
        body: bytes | None,
        timeout: float,
        max_response_bytes: int,
    ) -> TransportResponse:
        # Ignore environment/system proxies; forwarding reference input elsewhere
        # requires a separately reviewed transport. Standard TLS verification stays on.
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        request = Request(
            url,
            data=body,
            method=method,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        try:
            try:
                response = opener.open(request, timeout=timeout)
            except HTTPError as exc:
                response = exc
            with response:
                data = response.read(max_response_bytes + 1)
                if len(data) > max_response_bytes:
                    raise ReferenceTransportError("Reference response exceeds byte limit")
                return TransportResponse(
                    status=response.code,
                    content_type=response.headers.get("Content-Type", ""),
                    body=data,
                )
        except (OSError, URLError, HTTPException) as exc:
            raise ReferenceTransportError("Reference HTTP operation failed; not retried") from exc


def _model_bytes(value: BaseModel) -> bytes:
    return canonical_json(value.model_dump(mode="json", by_alias=True, exclude_none=False))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response JSON key")
        result[key] = value
    return result


def _reject_float(value: str) -> None:
    raise ValueError("floating-point response JSON is forbidden")


def _response_document(data: bytes) -> dict[str, Any]:
    document: Any = json.loads(
        data.decode("utf-8", errors="strict"),
        object_pairs_hook=_unique_object,
        parse_float=_reject_float,
        parse_constant=_reject_float,
    )
    if not isinstance(document, dict):
        raise ValueError("response must be an object")
    # Apply the same integer/string canonical profile used for request serialization.
    canonical_json(document)
    return document


def _require_reference_authority(document: dict[str, Any]) -> None:
    authority = document.get("authority")
    if not isinstance(authority, dict) or (
        authority.get("authority_mode") != "non_authoritative_reference"
        or any(
            authority.get(key) is not False
            for key in (
                "may_authorize_external_effect",
                "durable",
                "production_publication",
            )
        )
    ):
        raise ValueError("explicit non-authoritative reference flags are required")


def _verify_response(value: BaseModel, request: BaseModel | None, path: str) -> None:
    """Verify existing digest/reference contracts, without evaluating controls."""
    if isinstance(value, PackDetailResponse):
        pack = value.pack
        if (
            not verify_object_digest(pack)
            or pack.semantic_digest != value.summary.semantic_digest
            or path != "/packs/" + quote(value.summary.catalog_id, safe="")
        ):
            raise ValueError("pack response digest or identity mismatch")
        display = frozenset(
            item.key for item in pack.extension_requirements if item.classification == "display"
        )
        if any(
            control.semantic_digest
            != canonical_object_digest(
                control,
                display_extensions=display,
            )
            for control in pack.controls
        ):
            raise ValueError("pack control digest mismatch")
    elif isinstance(value, ControlDetailResponse):
        if (
            not verify_object_digest(value.control)
            or value.control.semantic_digest != value.summary.semantic_digest
            or path != "/controls/" + quote(value.summary.catalog_id, safe="")
        ):
            raise ValueError("control response digest or identity mismatch")
    if isinstance(request, DecideRequest | RecheckRequest | ReceiptAssessmentRequest):
        if not isinstance(value, DecideResponse | RecheckResponse | ReceiptAssessmentResponse):
            raise ValueError("response operation mismatch")
        if value.catalog_binding.selection_digest != sha256_digest(_model_bytes(request.selection)):
            raise ValueError("response does not bind the exact requested selection")
    if isinstance(value, DecideResponse) and isinstance(request, DecideRequest):
        decision, intent = value.decision, request.action_intent
        if (
            not verify_object_digest(decision)
            or decision.intent_ref.namespace != intent.namespace
            or decision.intent_ref.intent_id != intent.intent_id
            or decision.intent_ref.intent_digest != intent.intent_digest
            or decision.binding.intent_digest != intent.intent_digest
            or decision.binding.context_digest != intent.context_digest
            or decision.binding.actor_ref.namespace != intent.actor.namespace
            or decision.binding.actor_ref.actor_id != intent.actor.actor_id
            or decision.binding.actor_ref.version != intent.actor.version
            or decision.binding.resource_ref.namespace != intent.resource.namespace
            or decision.binding.resource_ref.resource_id != intent.resource.resource_id
            or decision.binding.resource_ref.version != intent.resource.version
            or decision.binding.resource_ref.type != intent.resource.type
            or decision.binding.action_type != intent.action.type
            or decision.binding.domain_action != intent.action.domain_action
        ):
            raise ValueError("decision digest or intent binding mismatch")
    elif isinstance(value, RecheckResponse) and isinstance(request, RecheckRequest):
        prior, ref = request.prior_decision, value.recheck.prior_decision_ref
        if (
            ref.namespace != prior.namespace
            or ref.decision_id != prior.decision_id
            or ref.semantic_digest != prior.semantic_digest
            or (
                value.recheck.valid
                and request.current_action_intent != request.original_action_intent
            )
        ):
            raise ValueError("recheck prior decision or unchanged intent binding mismatch")
        if value.recheck.valid and (
            value.recheck.reason_code != "controlspec.core.recheck.valid"
            or value.recheck.current_decision_ref != ref
            or any(
                item != ComparisonStatus.SAME for item in value.comparisons.model_dump().values()
            )
            or (
                request.options.reference_time is not None
                and request.options.reference_time >= prior.expires_at
            )
        ):
            raise ValueError("successful recheck contradicts reference binding or expiry")
    elif isinstance(value, ReceiptAssessmentResponse) and isinstance(
        request, ReceiptAssessmentRequest
    ):
        receipt, decision, intent = value.receipt, request.decision, request.action_intent
        if (
            not verify_object_digest(receipt)
            or receipt.status is ReceiptStatus.COMPLETE
            or receipt.execution_outcome is not ExecutionOutcome.NOT_EXECUTED
            or receipt.decision_ref.namespace != decision.namespace
            or receipt.decision_ref.decision_id != decision.decision_id
            or receipt.decision_ref.semantic_digest != decision.semantic_digest
            or receipt.intent_ref.namespace != intent.namespace
            or receipt.intent_ref.intent_id != intent.intent_id
            or receipt.intent_ref.intent_digest != intent.intent_digest
        ):
            raise ValueError("receipt digest or request binding mismatch")


class ControlSpecReferenceClient:
    """Reference HTTP client. No authentication, publication or execution API.

    timeout is a per-socket-operation timeout (not a whole-request deadline).
    The default transport disables environment proxies and never retries/redirects.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        *,
        timeout: float = 10.0,
        max_request_bytes: int = 1_048_576,
        max_response_bytes: int = 4_194_304,
        transport: ReferenceTransport | None = None,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or any(ord(char) <= 32 or ord(char) == 127 for char in base_url)
        ):
            raise ValueError("base_url must be an HTTP(S) origin without credentials")
        # Force malformed port detection before any transport invocation.
        _ = parsed.port
        if isinstance(timeout, bool) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ValueError("timeout must be finite and in (0, 60] seconds")
        for value, maximum in ((max_request_bytes, 1_048_576), (max_response_bytes, 16_777_216)):
            if type(value) is not int or not 0 < value <= maximum:
                raise ValueError("byte limit must be a positive bounded integer")
        self._base_url = base_url.rstrip("/") + "/controlspec/v0"
        self._timeout = float(timeout)
        self._max_request_bytes = max_request_bytes
        self._max_response_bytes = max_response_bytes
        self._transport = transport if transport is not None else _UrllibTransport()

    def _request[ResponseT: BaseModel](
        self,
        path: str,
        response_model: type[ResponseT],
        request: BaseModel | None = None,
    ) -> ResponseT:
        data = None if request is None else _model_bytes(request)
        if data is not None and len(data) > self._max_request_bytes:
            raise ReferenceClientError("Reference request exceeds byte limit; not sent")
        response = self._transport(
            method="GET" if request is None else "POST",
            url=self._base_url + path,
            body=data,
            timeout=self._timeout,
            max_response_bytes=self._max_response_bytes,
        )
        if len(response.body) > self._max_response_bytes:
            raise ReferenceProtocolError(
                "Reference response exceeds byte limit", status=response.status
            )
        if response.status != 200 and not 400 <= response.status <= 599:
            raise ReferenceProtocolError(
                "Unexpected status; redirect/retry prohibited",
                status=response.status,
            )
        try:
            if response.content_type.split(";", 1)[0].strip().lower() != "application/json":
                raise ValueError("response must have application/json media type")
            document = _response_document(response.body)
            if response.status != 200:
                error = _ErrorWire.model_validate_json(response.body, strict=True)
                raise ReferenceHttpError(response.status, error)
            _require_reference_authority(document)
            if response_model is ReceiptAssessmentResponse and any(
                document.get(key) is not False for key in ("stored", "durable")
            ):
                raise ValueError("receipt must explicitly be non-stored and non-durable")
            result = response_model.model_validate_json(response.body, strict=True)
            _verify_response(result, request, path)
            return result
        except (ValueError, ValidationError, RecursionError) as exc:
            raise ReferenceProtocolError(
                "Malformed or non-reference ControlSpec response",
                status=response.status,
            ) from exc

    def list_packs(self) -> PackListResponse:
        return self._request("/packs", _PackListWire)

    def get_pack(self, catalog_id: str) -> PackDetailResponse:
        return self._request("/packs/" + quote(catalog_id, safe=""), PackDetailResponse)

    def list_controls(self) -> ControlListResponse:
        return self._request("/controls", _ControlListWire)

    def get_control(self, catalog_id: str) -> ControlDetailResponse:
        return self._request("/controls/" + quote(catalog_id, safe=""), ControlDetailResponse)

    def decide(self, request: DecideRequest) -> DecideResponse:
        return self._request("/decide", DecideResponse, request)

    def recheck(self, request: RecheckRequest) -> RecheckResponse:
        return self._request("/recheck", RecheckResponse, request)

    def assess_receipt(self, request: ReceiptAssessmentRequest) -> ReceiptAssessmentResponse:
        return self._request("/receipts", ReceiptAssessmentResponse, request)
