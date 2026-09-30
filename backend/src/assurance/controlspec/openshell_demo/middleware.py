"""Pinned NVIDIA SupervisorMiddleware transport for an isolated synthetic target.

This adapter never changes core reference authority or grants access to real purchases.
The only mutation is an engine-issued execution ticket consumed by the demo target.
"""

import json
import re
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Literal

import grpc
from google.protobuf.json_format import MessageToDict

from .auth import AuthenticationError, ExtensionIdentity, ExtensionVerifier
from .engine import DemoDenied, DemoEngine
from .policy import PurchaseRequest, TrustedScope
from .proto import extension_pb2 as ext
from .proto import supervisor_middleware_pb2 as pb
from .proto import supervisor_middleware_pb2_grpc as rpc

CAPABILITY = "openshell.supervisor-middleware.contract"
REGISTRATION = "controlspec-demo"
MAX_BODY = 4096
EXPECTED_CONFIG = {"profile": "synthetic-purchases-v1"}


@dataclass(frozen=True)
class TargetBoundary:
    host: str = "host.openshell.internal"
    port: int = 18081
    scheme: str = "http"


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def parse_purchase(body: bytes) -> PurchaseRequest:
    if not body or len(body) > MAX_BODY:
        raise ValueError("unsupported body size")
    value = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object)
    return PurchaseRequest.model_validate(value, strict=True)


class ControlSpecMiddleware(rpc.SupervisorMiddlewareServicer):
    def __init__(
        self, engine: DemoEngine, verifier: ExtensionVerifier,
        boundary: TargetBoundary | None = None,
    ) -> None:
        self.engine = engine
        self.verifier = verifier
        self.boundary = boundary or TargetBoundary()

    def _identity(
        self, context: grpc.ServicerContext,
        kinds: tuple[Literal["gateway", "supervisor"], ...],
    ) -> ExtensionIdentity:
        values = [v for k, v in context.invocation_metadata() if k == "authorization"]
        try:
            if (len(values) != 1 or not isinstance(values[0], str)
                    or not values[0].startswith("Bearer ")):
                raise AuthenticationError("extension authentication required")
            identity = self.verifier.verify(values[0][7:])
            if identity.caller_kind not in kinds:
                raise AuthenticationError("extension caller cannot use this operation")
            return identity
        except AuthenticationError:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid extension identity")
            raise AssertionError("abort returned") from None

    def Describe(
        self, request: pb.MiddlewareDescribeRequest, context: grpc.ServicerContext,
    ) -> pb.MiddlewareManifest:
        # OpenShell v0.1.2 supervisor/src/lib.rs:connect_middleware_registry uses
        # supervisor credentials for the same Describe negotiation as the gateway.
        # Discovery is read-only; it does not grant transaction authority.
        self._identity(context, ("gateway", "supervisor"))
        gateway = request.gateway
        if (not request.HasField("gateway")
                or gateway.protocol_version.major != 1
                or not gateway.implementation_name
                or CAPABILITY not in gateway.supported_capabilities
                or set(gateway.required_capabilities) - {CAPABILITY}):
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, "unsupported extension protocol")
        return pb.MiddlewareManifest(
            name="ControlSpec synthetic purchase demonstration", service_version="0.1.2-preview",
            expected_audience=self.verifier.audience,
            extension=ext.PeerMetadata(
                protocol_version=ext.ProtocolVersion(major=1, minor=0),
                implementation_name="controlspec/synthetic-purchases",
                implementation_version="0.1.2-preview",
                supported_capabilities=[CAPABILITY], required_capabilities=[CAPABILITY],
            ),
            bindings=[pb.MiddlewareBinding(
                operation=pb.SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST,
                phase=pb.SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
                max_payload_bytes=MAX_BODY,
            )],
        )

    @staticmethod
    def _valid_config(request: pb.ValidateConfigRequest | pb.HttpRequestEvaluation) -> bool:
        return (request.middleware_name == REGISTRATION
                and MessageToDict(request.config) == EXPECTED_CONFIG)

    def ValidateConfig(
        self, request: pb.ValidateConfigRequest, context: grpc.ServicerContext,
    ) -> pb.ValidateConfigResponse:
        # Policy admission calls ValidateConfig from openshell-server/middleware.rs.
        self._identity(context, ("gateway",))
        valid = self._valid_config(request)
        return pb.ValidateConfigResponse(
            valid=valid, reason="" if valid else "only synthetic-purchases-v1 is supported",
        )

    def EvaluateHttpRequest(
        self, request: pb.HttpRequestEvaluation, context: grpc.ServicerContext,
    ) -> pb.HttpRequestResult:
        identity = self._identity(context, ("supervisor",))
        target = request.target
        if (not identity.sandbox_id or request.context.sandbox_id != identity.sandbox_id
                or not request.context.request_id or request.context.ByteSize() > 4096):
            return self._deny("identity_mismatch")
        if (not self._valid_config(request)
                or request.phase != pb.SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS):
            return self._deny("unsupported_configuration")
        if (target.host != self.boundary.host or target.port != self.boundary.port
                or target.scheme != self.boundary.scheme or target.method != "POST"
                or target.path != "/purchases" or target.query):
            return self._deny("unsupported_target")
        headers: dict[str, str] = {}
        for header in request.headers:
            name = header.name.lower()
            if (name in headers or len(request.headers) > 128
                    or any(c in header.value for c in "\r\n\x00")
                    or len(header.value) > 8192
                    or name.startswith("x-controlspec-")
                    or name in {"upgrade", "content-encoding", "transfer-encoding"}):
                return self._deny("unsupported_headers")
            headers[name] = header.value
        json_types = {"application/json", "application/json; charset=utf-8"}
        if headers.get("content-type") not in json_types:
            return self._deny("unsupported_content_type")
        # OpenShell normally omits framing headers; direct protocol clients must not
        # use inconsistent framing to obtain a ticket for a different downstream body.
        if "content-length" in headers and headers["content-length"] != str(len(request.body)):
            return self._deny("invalid_content_length")
        try:
            purchase = parse_purchase(request.body)
            scope = TrustedScope(gateway_id=identity.gateway_id, sandbox_id=identity.sandbox_id)
            ticket = self.engine.authorize(purchase, scope)
        except DemoDenied as exc:
            reason = exc.reason
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", reason):
                reason = "controlspec_denied"
            return self._deny(reason)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return self._deny("invalid_purchase")
        except Exception:
            # No exception, DB outage, or unrecognized engine response grants permission.
            return self._deny("controlspec_unavailable")
        return pb.HttpRequestResult(
            decision=pb.DECISION_ALLOW,
            reason="synthetic target reservation issued; execution not yet verified",
            header_mutations=[pb.HeaderMutation(write=pb.WriteHeader(
                name="x-controlspec-ticket", value=ticket,
                on_existing=pb.EXISTING_HEADER_ACTION_OVERWRITE,
            ))],
        )

    @staticmethod
    def _deny(reason: str) -> pb.HttpRequestResult:
        return pb.HttpRequestResult(decision=pb.DECISION_DENY, reason_code=reason)

    def EvaluateWebSocketSession(
        self, request_iterator: Iterator[pb.WebSocketSessionEvent], context: grpc.ServicerContext,
    ) -> Iterator[pb.WebSocketSessionEventResult]:
        self._identity(context, ("supervisor",))
        context.abort(grpc.StatusCode.PERMISSION_DENIED, "websockets are unsupported")
        return iter(())


def create_server(
    service: ControlSpecMiddleware, address: str, *,
    certificate_chain: bytes | None = None, private_key: bytes | None = None,
    loopback_protocol_test: bool = False,
) -> tuple[grpc.Server, int]:
    """TLS by default; explicit loopback test transport still requires signed JWTs."""
    server = grpc.server(ThreadPoolExecutor(max_workers=4), options=[
        ("grpc.max_receive_message_length", 131072), ("grpc.max_send_message_length", 131072),
    ])
    # grpcio-tools does not generate type annotations for registration helpers.
    rpc.add_SupervisorMiddlewareServicer_to_server(service, server)  # type: ignore[no-untyped-call]
    if bool(certificate_chain) != bool(private_key):
        raise ValueError("both TLS certificate and private key are required")
    if certificate_chain and private_key:
        port = server.add_secure_port(
            address, grpc.ssl_server_credentials([(private_key, certificate_chain)]),
        )
    elif loopback_protocol_test and address.startswith("127.0.0.1:"):
        port = server.add_insecure_port(address)
    else:
        raise ValueError("TLS credentials required outside explicit loopback protocol tests")
    if not port:
        raise ValueError("middleware listener could not bind")
    return server, port
