"""Real gRPC/protobuf boundary tests, not claims of a running OpenShell sandbox."""

import json
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import grpc
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from assurance.controlspec.openshell_demo.auth import ExtensionVerifier
from assurance.controlspec.openshell_demo.engine import DemoEngine
from assurance.controlspec.openshell_demo.middleware import (
    CAPABILITY,
    EXPECTED_CONFIG,
    REGISTRATION,
    ControlSpecMiddleware,
    create_server,
)
from assurance.controlspec.openshell_demo.policy import TrustedScope
from assurance.controlspec.openshell_demo.proto import extension_pb2 as ext
from assurance.controlspec.openshell_demo.proto import supervisor_middleware_pb2 as pb
from assurance.controlspec.openshell_demo.proto import supervisor_middleware_pb2_grpc as rpc

AUDIENCE = "urn:openshell:extension:middleware:controlspec-demo"


def token(key: Ed25519PrivateKey, kind: str = "supervisor", **changes: Any) -> str:
    now = int(time.time())
    claims = {"iss": "openshell-gateway:test", "aud": AUDIENCE, "iat": now-1, "exp": now+120,
              "jti": "fixture-only", "caller_kind": kind,
              "sub": "spiffe://openshell/sandbox/sandbox-a"}
    if kind == "supervisor":
        claims["sandbox_id"] = "sandbox-a"
    else:
        claims["sub"] = "openshell-gateway:test"
    claims.update(changes)
    return jwt.encode(claims, key, algorithm="EdDSA",
                      headers={"kid": "test-key", "typ": "openshell-ext+jwt"})


def metadata(value: str) -> tuple[tuple[str, str]]:
    return (("authorization", f"Bearer {value}"),)


def request(**changes: Any) -> Any:
    body = {"schema_version": "1", "action_id": "purchase-1", "amount_minor": 4200,
            "currency": "USD", "merchant": "demo-store", "recurring": False}
    body.update(changes)
    return pb.HttpRequestEvaluation(
        phase=pb.SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
        context=pb.RequestContext(request_id="http-1", sandbox_id="sandbox-a"),
        config=EXPECTED_CONFIG, middleware_name=REGISTRATION,
        target=pb.HttpRequestTarget(scheme="http", host="host.openshell.internal", port=18081,
                                   method="POST", path="/purchases"),
        headers=[pb.HttpHeader(name="content-type", value="application/json")],
        body=json.dumps(body).encode(),
    )


@pytest.fixture
def service(tmp_path: Path) -> Iterator[tuple[Any, Ed25519PrivateKey, DemoEngine]]:
    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    engine = DemoEngine(tmp_path / "authority.sqlite", b"t"*32, b"o"*32)
    verifier = ExtensionVerifier("test", AUDIENCE, {"test-key": pem})
    server, port = create_server(ControlSpecMiddleware(engine, verifier), "127.0.0.1:0",
                                 loopback_protocol_test=True)
    server.start()
    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    try:
        grpc.channel_ready_future(channel).result(timeout=5)
        yield rpc.SupervisorMiddlewareStub(channel), key, engine
    finally:
        channel.close()
        server.stop(0).wait()


def test_describe_negotiates_and_config_is_closed(service: Any) -> None:
    stub, key, _ = service
    peer = ext.PeerMetadata(protocol_version=ext.ProtocolVersion(major=1),
                            implementation_name="test/gateway",
                            supported_capabilities=[CAPABILITY], required_capabilities=[CAPABILITY])
    manifest = stub.Describe(pb.MiddlewareDescribeRequest(gateway=peer),
                             metadata=metadata(token(key, "gateway")))
    assert manifest.expected_audience == AUDIENCE
    assert len(manifest.bindings) == 1
    assert manifest.bindings[0].max_payload_bytes == 4096
    assert stub.ValidateConfig(pb.ValidateConfigRequest(config=EXPECTED_CONFIG,
                                                        middleware_name=REGISTRATION),
                               metadata=metadata(token(key, "gateway"))).valid
    assert not stub.ValidateConfig(pb.ValidateConfigRequest(config={"allow": True},
                                                            middleware_name=REGISTRATION),
                                   metadata=metadata(token(key, "gateway"))).valid
    peer.protocol_version.major = 2
    with pytest.raises(grpc.RpcError) as error:
        stub.Describe(pb.MiddlewareDescribeRequest(gateway=peer),
                      metadata=metadata(token(key, "gateway")))
    assert error.value.code() == grpc.StatusCode.FAILED_PRECONDITION


def test_supervisor_can_discover_but_cannot_admit_policy(service: Any) -> None:
    """Real supervisors negotiate the registry using their sandbox-scoped JWT."""
    stub, key, _ = service
    peer = ext.PeerMetadata(
        protocol_version=ext.ProtocolVersion(major=1), implementation_name="openshell/gateway",
        supported_capabilities=[CAPABILITY], required_capabilities=[CAPABILITY],
    )
    manifest = stub.Describe(
        pb.MiddlewareDescribeRequest(gateway=peer), metadata=metadata(token(key)),
    )
    assert manifest.expected_audience == AUDIENCE
    assert manifest.bindings[0].phase == pb.SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS
    with pytest.raises(grpc.RpcError) as error:
        stub.ValidateConfig(
            pb.ValidateConfigRequest(config=EXPECTED_CONFIG, middleware_name=REGISTRATION),
            metadata=metadata(token(key)),
        )
    assert error.value.code() == grpc.StatusCode.UNAUTHENTICATED
    # Read-only discovery cannot substitute for exact scoped action evaluation.
    assert stub.EvaluateHttpRequest(
        request(), metadata=metadata(token(key)),
    ).decision == pb.DECISION_ALLOW


def test_gateway_discovery_does_not_grant_action_execution(service: Any) -> None:
    stub, key, _ = service
    with pytest.raises(grpc.RpcError) as error:
        stub.EvaluateHttpRequest(request(), metadata=metadata(token(key, "gateway")))
    assert error.value.code() == grpc.StatusCode.UNAUTHENTICATED


@pytest.mark.parametrize("credentials", ["missing", "forged", "foreign_sandbox_subject"])
def test_describe_still_rejects_invalid_supervisor_credentials(
    service: Any, credentials: str,
) -> None:
    stub, key, _ = service
    peer = ext.PeerMetadata(
        protocol_version=ext.ProtocolVersion(major=1), implementation_name="openshell/gateway",
        supported_capabilities=[CAPABILITY], required_capabilities=[CAPABILITY],
    )
    creds = ()
    if credentials == "forged":
        creds = metadata(token(Ed25519PrivateKey.generate()))
    elif credentials == "foreign_sandbox_subject":
        creds = metadata(token(key, sub="spiffe://openshell/sandbox/other"))
    with pytest.raises(grpc.RpcError) as error:
        stub.Describe(pb.MiddlewareDescribeRequest(gateway=peer), metadata=creds)
    assert error.value.code() == grpc.StatusCode.UNAUTHENTICATED


def test_real_engine_permits_ticket_once_and_preserves_body(service: Any) -> None:
    stub, key, _ = service
    result = stub.EvaluateHttpRequest(request(), metadata=metadata(token(key)))
    assert result.decision == pb.DECISION_ALLOW
    assert not result.has_body and not result.body
    assert len(result.header_mutations) == 1
    assert result.header_mutations[0].write.name == "x-controlspec-ticket"
    replay = stub.EvaluateHttpRequest(request(), metadata=metadata(token(key)))
    assert replay.decision == pb.DECISION_DENY


def test_approval_required_then_operator_approval_is_reevaluated(service: Any) -> None:
    stub, key, engine = service
    pending = request(amount_minor=14200)
    result = stub.EvaluateHttpRequest(pending, metadata=metadata(token(key)))
    assert result.decision == pb.DECISION_DENY
    assert result.reason_code == "approval_required"
    engine.approve("purchase-1", TrustedScope(gateway_id="test", sandbox_id="sandbox-a"), "o"*32)
    allowed = stub.EvaluateHttpRequest(pending, metadata=metadata(token(key)))
    assert allowed.decision == pb.DECISION_ALLOW


@pytest.mark.parametrize("claims", [
    {"aud": "wrong"}, {"iss": "openshell-gateway:other"}, {"exp": 1},
    {"caller_kind": "gateway"}, {"sub": "spiffe://openshell/sandbox/other"},
    {"sandbox_id": None}, {"iat": "future"}, {"exp": "excessive_lifetime"},
    {"aud": [AUDIENCE]},
])
def test_invalid_signed_identity_cannot_evaluate(service: Any, claims: Any) -> None:
    stub, key, _ = service
    # Compute invalid time windows when this test runs, not during collection.
    # A slow integration suite must not age a future-iat fixture into validity.
    claims = dict(claims)
    now = int(time.time())
    if claims.get("iat") == "future":
        claims["iat"] = now + 120
    if claims.get("exp") == "excessive_lifetime":
        claims["exp"] = now + 7200
    with pytest.raises(grpc.RpcError) as error:
        stub.EvaluateHttpRequest(request(), metadata=metadata(token(key, **claims)))
    assert error.value.code() == grpc.StatusCode.UNAUTHENTICATED


def test_forgery_missing_credentials_and_duplicate_authentication(service: Any) -> None:
    stub, key, _ = service
    forged = token(Ed25519PrivateKey.generate())
    valid = metadata(token(key))
    for creds in [(), metadata(forged), valid+valid]:
        with pytest.raises(grpc.RpcError) as error:
            stub.EvaluateHttpRequest(request(), metadata=creds)
        assert error.value.code() == grpc.StatusCode.UNAUTHENTICATED


@pytest.mark.parametrize("field,value", [
    ("host", "localhost"), ("path", "/purchases/"), ("method", "GET"),
    ("scheme", "ws"), ("port", 443), ("query", "amount=1"),
])
def test_target_variants_fail_closed(service: Any, field: str, value: Any) -> None:
    stub, key, _ = service
    req = request()
    setattr(req.target, field, value)
    assert stub.EvaluateHttpRequest(req, metadata=metadata(token(key))).decision == pb.DECISION_DENY


@pytest.mark.parametrize("body", [
    b'{"amount_minor":1,"amount_minor":2}', b'[]', b'null', b'not-json', b'\xff', b' '*4097,
])
def test_ambiguous_and_oversized_bodies_fail_closed(service: Any, body: bytes) -> None:
    stub, key, _ = service
    req = request()
    req.body = body
    assert stub.EvaluateHttpRequest(req, metadata=metadata(token(key))).decision == pb.DECISION_DENY


@pytest.mark.parametrize("changes", [
    {"amount_minor": True}, {"amount_minor": "4200"}, {"amount_minor": 42.0},
    {"currency": "EUR"}, {"actor": "human"}, {"recurring": "false"}, {"recurring": True},
])
def test_strict_schema_and_recurring_fail_closed(service: Any, changes: Any) -> None:
    stub, key, _ = service
    result = stub.EvaluateHttpRequest(request(**changes), metadata=metadata(token(key)))
    assert result.decision == pb.DECISION_DENY


@pytest.mark.parametrize("name,value", [
    ("content-type", "application/json"), ("x-controlspec-ticket", "forged"),
    ("content-encoding", "gzip"), ("content-length", "0"), ("upgrade", "websocket"),
])
def test_duplicate_or_authority_or_unsupported_headers_denied(
    service: Any, name: str, value: str,
) -> None:
    stub, key, _ = service
    req = request()
    req.headers.append(pb.HttpHeader(name=name, value=value))
    assert stub.EvaluateHttpRequest(req, metadata=metadata(token(key))).decision == pb.DECISION_DENY


def test_signed_sandbox_cannot_impersonate_context(service: Any) -> None:
    stub, key, _ = service
    req = request()
    req.context.sandbox_id = "other"
    result = stub.EvaluateHttpRequest(req, metadata=metadata(token(key)))
    assert result.reason_code == "identity_mismatch"


def test_websocket_denied_and_plaintext_requires_explicit_loopback(service: Any) -> None:
    stub, key, engine = service
    with pytest.raises(grpc.RpcError) as error:
        list(stub.EvaluateWebSocketSession(iter([]), metadata=metadata(token(key))))
    assert error.value.code() == grpc.StatusCode.PERMISSION_DENIED
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    adapter = ControlSpecMiddleware(engine, ExtensionVerifier("test", AUDIENCE, {"k": public}))
    with pytest.raises(ValueError, match="TLS"):
        create_server(adapter, "127.0.0.1:0")
    with pytest.raises(ValueError, match="TLS"):
        create_server(adapter, "0.0.0.0:0", loopback_protocol_test=True)


def test_engine_outage_does_not_allow(service: Any, monkeypatch: Any) -> None:
    stub, key, engine = service
    def unavailable(*args: Any, **kwargs: Any) -> str:
        raise RuntimeError("synthetic outage")
    monkeypatch.setattr(engine, "authorize", unavailable)
    result = stub.EvaluateHttpRequest(request(), metadata=metadata(token(key)))
    assert result.decision == pb.DECISION_DENY
    assert result.reason_code == "controlspec_unavailable"


def test_tls_signed_protocol_roundtrip(tmp_path: Path) -> None:
    """A real TLS gRPC client, still explicitly not an OpenShell runtime run."""
    tls_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(tls_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
    private = tls_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
    jwt_key = Ed25519PrivateKey.generate()
    public = jwt_key.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    engine = DemoEngine(tmp_path / "tls.sqlite", b"t"*32, b"o"*32)
    verifier = ExtensionVerifier("test", AUDIENCE, {"test-key": public})
    adapter = ControlSpecMiddleware(engine, verifier)
    server, port = create_server(
        adapter, "127.0.0.1:0", certificate_chain=cert, private_key=private,
    )
    server.start()
    channel = grpc.secure_channel(f"localhost:{port}", grpc.ssl_channel_credentials(cert))
    try:
        grpc.channel_ready_future(channel).result(timeout=5)
        result = rpc.SupervisorMiddlewareStub(channel).EvaluateHttpRequest(
            request(), metadata=metadata(token(jwt_key)), timeout=5,
        )
        assert result.decision == pb.DECISION_ALLOW
    finally:
        channel.close()
        server.stop(0).wait()


@pytest.mark.parametrize("header", [
    {"typ": "JWT", "kid": "test-key"}, {"typ": "openshell-ext+jwt", "kid": "unknown"},
])
def test_wrong_token_profile_or_key_id_rejected(service: Any, header: Any) -> None:
    stub, key, _ = service
    claims = jwt.decode(token(key), options={"verify_signature": False})
    value = jwt.encode(claims, key, algorithm="EdDSA", headers=header)
    with pytest.raises(grpc.RpcError) as error:
        stub.EvaluateHttpRequest(request(), metadata=metadata(value))
    assert error.value.code() == grpc.StatusCode.UNAUTHENTICATED
