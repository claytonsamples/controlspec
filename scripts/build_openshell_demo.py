"""Record real TLS gRPC + HTTP synthetic-target observations; never fake an OpenShell run."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import grpc
import jwt
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from assurance.controlspec.openshell_demo.auth import ExtensionVerifier
from assurance.controlspec.openshell_demo.engine import DemoDenied, DemoEngine
from assurance.controlspec.openshell_demo.middleware import (
    CAPABILITY,
    EXPECTED_CONFIG,
    REGISTRATION,
    ControlSpecMiddleware,
    create_server,
)
from assurance.controlspec.openshell_demo.policy import PurchaseRequest, TrustedScope
from assurance.controlspec.openshell_demo.proto import extension_pb2 as ext
from assurance.controlspec.openshell_demo.proto import supervisor_middleware_pb2 as pb
from assurance.controlspec.openshell_demo.proto import supervisor_middleware_pb2_grpc as rpc
from assurance.controlspec.openshell_demo.target import SyntheticTarget, create_target_app

ROOT = Path(__file__).resolve().parents[1]
AUDIENCE = "urn:openshell:extension:middleware:controlspec-demo"
SCOPE = TrustedScope(gateway_id="recording-fixture", sandbox_id="scripted-agent")
RUNTIME_DETAIL = (
    "Not run: this recorder does not launch OpenShell. No OpenShell supervisor, "
    "native-policy result, or sandbox isolation result is observed. "
    "The protocol fixture below is not an OpenShell runtime."
)


def http_json(
    url: str, payload: dict[str, Any] | None = None, headers: dict[str, str] | None = None
) -> tuple[int, dict[str, Any]]:
    request = Request(
        url,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Content-Type": "application/json"} | (headers or {}),
    )
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


def tls_fixture() -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ControlSpec local test")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


class ProtocolFixture:
    """Explicit replacement for a supervisor in tests. It is not an isolation boundary."""

    def __init__(self, directory: Path) -> None:
        self.secret = secrets.token_bytes(32)
        self.operator = secrets.token_hex(32)
        self.engine = DemoEngine(directory / "engine.sqlite", self.secret, self.operator.encode())
        self.baseline = SyntheticTarget(directory / "baseline.sqlite", self.secret)
        self.key = Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        verifier = ExtensionVerifier(SCOPE.gateway_id, AUDIENCE, {"fixture-key": public})
        certificate, key = tls_fixture()
        self.server, port = create_server(
            ControlSpecMiddleware(self.engine, verifier),
            "127.0.0.1:0",
            certificate_chain=certificate,
            private_key=key,
        )
        self.server.start()
        self.channel = grpc.secure_channel(
            f"127.0.0.1:{port}", grpc.ssl_channel_credentials(certificate)
        )
        grpc.channel_ready_future(self.channel).result(timeout=5)
        self.stub = rpc.SupervisorMiddlewareStub(self.channel)
        peer = ext.PeerMetadata(
            protocol_version=ext.ProtocolVersion(major=1),
            implementation_name="controlspec/explicit-protocol-fixture",
            supported_capabilities=[CAPABILITY],
            required_capabilities=[CAPABILITY],
        )
        manifest = self.stub.Describe(
            pb.MiddlewareDescribeRequest(gateway=peer), metadata=self.metadata("gateway"), timeout=3
        )
        if manifest.expected_audience != AUDIENCE:
            raise AssertionError("audience negotiation failed")
        validated = self.stub.ValidateConfig(
            pb.ValidateConfigRequest(middleware_name=REGISTRATION, config=EXPECTED_CONFIG),
            metadata=self.metadata("gateway"),
            timeout=3,
        )
        if not validated.valid:
            raise AssertionError("configuration rejected")
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.url = f"http://127.0.0.1:{self.socket.getsockname()[1]}"
        app = create_target_app(directory / "target.sqlite", self.secret)
        self.http_server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
        self.thread = threading.Thread(
            target=self.http_server.run, kwargs={"sockets": [self.socket]}, daemon=True
        )
        self.thread.start()
        deadline = time.monotonic() + 5
        while (
            not self.http_server.started and self.thread.is_alive() and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        if not self.http_server.started:
            raise RuntimeError("synthetic HTTP target failed to start")

    def metadata(self, kind: str = "supervisor") -> tuple[tuple[str, str]]:
        now = int(time.time())
        claims = {
            "iss": f"openshell-gateway:{SCOPE.gateway_id}",
            "aud": AUDIENCE,
            "iat": now - 1,
            "exp": now + 120,
            "jti": secrets.token_hex(8),
            "caller_kind": kind,
            "sub": f"openshell-gateway:{SCOPE.gateway_id}",
        }
        if kind == "supervisor":
            claims.update(
                sub=f"spiffe://openshell/sandbox/{SCOPE.sandbox_id}", sandbox_id=SCOPE.sandbox_id
            )
        token = jwt.encode(
            claims,
            self.key,
            algorithm="EdDSA",
            headers={"kid": "fixture-key", "typ": "openshell-ext+jwt"},
        )
        return (("authorization", "Bearer " + token),)

    def state(self) -> dict[str, Any]:
        status, state = http_json(self.url + "/state")
        if status != 200:
            raise AssertionError("target state unavailable")
        return state

    def dispatch(
        self, purchase: PurchaseRequest, *, withhold_evidence: bool = False
    ) -> dict[str, Any]:
        call = pb.HttpRequestEvaluation(
            phase=pb.SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
            context=pb.RequestContext(request_id=secrets.token_hex(8), sandbox_id=SCOPE.sandbox_id),
            middleware_name=REGISTRATION,
            config=EXPECTED_CONFIG,
            target=pb.HttpRequestTarget(
                scheme="http",
                host="host.openshell.internal",
                port=18081,
                method="POST",
                path="/purchases",
            ),
            headers=[pb.HttpHeader(name="content-type", value="application/json")],
            body=purchase.model_dump_json().encode(),
        )
        start = time.perf_counter()
        try:
            result = self.stub.EvaluateHttpRequest(call, metadata=self.metadata(), timeout=2)
        except grpc.RpcError as error:
            return {
                "outcome": "not_forwarded",
                "reason": f"grpc_{error.code().name.lower()}",
                "forwarded": False,
                "reconciled": False,
                "transport": "TLS + signed fixture JWT",
            }
        elapsed = round((time.perf_counter() - start) * 1000, 3)
        if result.decision != pb.DECISION_ALLOW:
            return {
                "outcome": "denied",
                "reason": result.reason_code,
                "forwarded": False,
                "reconciled": False,
                "rpc_elapsed_ms": elapsed,
            }
        if result.has_body or len(result.header_mutations) != 1:
            raise AssertionError("unexpected middleware mutation")
        ticket = result.header_mutations[0].write.value
        status, receipt = http_json(
            self.url + "/purchases", purchase.model_dump(), {"X-ControlSpec-Ticket": ticket}
        )
        if status != 200:
            raise AssertionError(f"allowed request rejected by target: {receipt}")
        verified = self.engine.reconcile(purchase, SCOPE, None if withhold_evidence else receipt)
        return {
            "outcome": "committed" if verified else "effect_observed_evidence_missing",
            "reason": "target_receipt_verified" if verified else "completion_unverified",
            "forwarded": True,
            "reconciled": verified,
            "rpc_elapsed_ms": elapsed,
            "target_receipt": receipt,
        }

    def close(self) -> None:
        self.channel.close()
        self.server.stop(0).wait()
        self.http_server.should_exit = True
        self.thread.join(timeout=5)
        self.socket.close()


SCENES = (
    (
        "allowed",
        "A useful action proceeds",
        4200,
        "A one-time $42 purchase fits the synthetic $75 control.",
        "The gate lets a permitted action proceed and checks the target receipt.",
    ),
    (
        "approval",
        "Approve this exact $142 purchase",
        14200,
        "First denied. A simulated host operator approves the exact action, "
        "then the agent retries.",
        "Approval is a separate fact, bound to the request, actor, policy and decision.",
    ),
    (
        "overspend",
        "$142 without approval",
        14200,
        "The agent proposes a purchase above the synthetic threshold.",
        "A proposal can be valid JSON and still require someone else's authority.",
    ),
    (
        "changed",
        "Approved $142. Attempted $143.",
        14300,
        "A simulated operator approves $142; the subsequent request changes the amount.",
        "Changing the action invalidates the original approval.",
    ),
    (
        "self-approval",
        "The agent tries to approve",
        14200,
        "An invalid operator credential is offered for the pending action.",
        "The caller cannot turn a request into a host-operator approval.",
    ),
    (
        "replay",
        "Try the same purchase again",
        4200,
        "The request is delivered twice with the same action ID.",
        "The target is idempotent in both lanes; ControlSpec additionally denies "
        "a fresh reservation.",
    ),
    (
        "missing-proof",
        "The effect happened. Proof is missing.",
        4200,
        "The target commits, but the fixture withholds its receipt from reconciliation.",
        "Known target state and verified completion are separate observations.",
    ),
    (
        "outage",
        "The middleware goes offline",
        4200,
        "The fixture stops the gRPC service before attempting dispatch.",
        "The test dispatcher does not forward on RPC failure; "
        "OpenShell fail-closed behavior remains unrun.",
    ),
    (
        "direct",
        "Skip the middleware",
        4200,
        "A real smolagents Tool calls the controlled HTTP target without an execution ticket.",
        "The target itself rejects a ticketless call. "
        "This tests the target, not sandbox bypass resistance.",
    ),
)


def record_scene(directory: Path, definition: tuple[str, str, int, str, str]) -> dict[str, Any]:
    scene_id, title, amount, description, takeaway = definition
    fixture = ProtocolFixture(directory)
    purchase = PurchaseRequest(
        schema_version="1",
        action_id=scene_id,
        amount_minor=amount,
        currency="USD",
        merchant="demo-store",
        recurring=False,
    )
    try:
        before = fixture.state()
        baseline_before = fixture.baseline.state()
        baseline_receipt = fixture.baseline.commit_unguarded(purchase, SCOPE).model_dump()
        events = [{"kind": "intent", "message": f"Scripted request: {amount} USD cents."}]
        if scene_id in {"approval", "changed", "self-approval"}:
            original = PurchaseRequest(**(purchase.model_dump() | {"amount_minor": 14200}))
            first = fixture.dispatch(original)
            if first["reason"] != "approval_required":
                raise AssertionError("initial approval gate did not deny")
            events.append(
                {"kind": "decision", "message": "Initial request denied: approval_required."}
            )
            if scene_id == "self-approval":
                try:
                    fixture.engine.approve(scene_id, SCOPE, "not-an-operator-credential")
                    raise AssertionError("invalid operator credential was accepted")
                except DemoDenied as error:
                    events.append({"kind": "approval", "message": error.reason})
            else:
                fixture.engine.approve(scene_id, SCOPE, fixture.operator)
                events.append(
                    {
                        "kind": "approval",
                        "message": "Simulated host operator approved the exact $142 request; "
                        "no real human participated.",
                    }
                )
        if scene_id == "replay":
            initial = fixture.dispatch(purchase)
            if not initial["reconciled"]:
                raise AssertionError("first delivery did not reconcile")
            fixture.baseline.commit_unguarded(purchase, SCOPE)
            events.append(
                {"kind": "effect", "message": "First delivery committed once; now retrying."}
            )
        if scene_id == "outage":
            fixture.server.stop(0).wait()
        if scene_id == "direct":
            from assurance.controlspec.openshell_demo.smolagents_tool import SyntheticPurchaseTool

            tool = SyntheticPurchaseTool(fixture.url)
            tool_result = tool(action_id=scene_id, amount_minor=amount, recurring=False)
            if tool_result["http_status"] != 403:
                raise AssertionError("ticketless tool reached the target")
            observation = {
                "outcome": "denied",
                "reason": "target_requires_ticket",
                "forwarded": True,
                "reconciled": False,
                "smolagents_tool_result": tool_result,
            }
        else:
            observation = fixture.dispatch(purchase, withhold_evidence=scene_id == "missing-proof")
        after = fixture.state()
        events.append({"kind": "decision", "message": observation["reason"]})
        events.append(
            {"kind": "effect", "message": f"Target purchase count: {after['purchase_count']}."}
        )
        events.append(
            {
                "kind": "evidence",
                "message": "Signed target receipt reconciled."
                if observation["reconciled"]
                else "No verified completion for this attempt.",
            }
        )
        if not fixture.engine.ledger.verify():
            raise AssertionError("ledger chain invalid")
        return {
            "id": scene_id,
            "title": title,
            "description": description,
            "request": purchase.model_dump(),
            "takeaway": takeaway,
            "lanes": [
                {
                    "id": "unguarded",
                    "label": "Unguarded target",
                    "status": "observed",
                    "outcome": "committed",
                    "reason": "direct_synthetic_commit",
                    "before": baseline_before,
                    "after": fixture.baseline.state(),
                    "events": [
                        {
                            "kind": "effect",
                            "message": "Direct host call to a separate synthetic target.",
                        }
                    ],
                    "evidence": {
                        "target_receipt": baseline_receipt,
                        "transport": "direct Python call",
                        "target_idempotency": True,
                        "ticket_required": False,
                    },
                },
                {
                    "id": "native",
                    "label": "OpenShell native",
                    "status": "not_run",
                    "outcome": "not_run",
                    "reason": RUNTIME_DETAIL,
                    "before": None,
                    "after": None,
                    "events": [],
                    "evidence": {
                        "policy": "integrations/openshell/policy-native.yaml",
                        "note": (
                            "Pinned v0.1.2 native REST rules match method, path and query, "
                            "not this purchase JSON body. GraphQL, MCP and JSON-RPC "
                            "inspection are separate protocol features. "
                            "No native outcome is inferred here."
                        ),
                    },
                },
                {
                    "id": "combined",
                    "label": "ControlSpec protocol fixture",
                    "status": "observed",
                    "outcome": observation["outcome"],
                    "reason": observation["reason"],
                    "before": before,
                    "after": after,
                    "events": events,
                    "evidence": observation
                    | {
                        "ledger_events": fixture.engine.ledger.events(),
                        "ledger_chain_valid": True,
                        "transport": "TLS gRPC with signed fixture JWT; loopback HTTP target",
                        "supervisor": "explicit Python fixture, not NVIDIA OpenShell",
                        "ticket_required": True,
                    },
                },
            ],
        }
    finally:
        fixture.close()


def record() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="controlspec-recording-") as directory:
        scenes = [
            record_scene(Path(directory) / definition[0], definition) for definition in SCENES
        ]
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    return {
        "schema_version": "1",
        "generated_at": datetime.now(UTC).isoformat(),
        "source_revision": revision,
        "upstream": {"version": "v0.1.2", "commit": "6648bd0c290efbc41ba131ee9831ee45cd431f94"},
        "runtime": {"status": "not_run", "detail": RUNTIME_DETAIL},
        "verification": {
            "kind": "authenticated_grpc_and_synthetic_target",
            "detail": "Real TLS gRPC contract calls, real ControlSpec evaluation, SQLite state "
            "and loopback HTTP target. Scripted agent inputs and test operator identity. "
            "No LLM or real purchase.",
        },
        "scenes": scenes,
        "limitations": [
            "Actual OpenShell runtime, effective-policy admission, network isolation "
            "and bypass checks not run.",
            "The unguarded lane uses a direct Python target call; "
            "the controlled lane uses TLS gRPC + HTTP. "
            "They are illustrative arms, not latency benchmarks or a native OpenShell comparison.",
            "The controlled target requires a ticket; this extra defense is explicit "
            "and not attributed to OpenShell.",
            "The test operator is scripted. Host-only CLI is provided for manual approval; "
            "no production identity system.",
            "Reference decisions retain non-authoritative status. "
            "Synthetic permissions apply only to this fake target.",
            "Host administrators and the shared demo signing secret are trusted. "
            "Local hash chains are not tamper-proof.",
            "Replay protection is scoped to the same action ID. New IDs and cumulative "
            "budget limits require additional controls.",
            "Static replay cannot authorize anything. "
            "All amounts, identities and transactions are synthetic.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record-only", action="store_true")
    args = parser.parse_args()
    data = record()
    output = ROOT / "demo/space"
    encoded = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    (output / "openshell-traces.json").write_text(encoded, encoding="utf-8", newline="\n")
    if not args.record_only:
        template = (ROOT / "demo/openshell-template.html").read_text(encoding="utf-8")
        if template.count("__OPENSHELL_DATA__") != 1:
            raise ValueError("expected one embedded report placeholder")
        wire = json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")
        (output / "index.html").write_text(
            template.replace("__OPENSHELL_DATA__", wire), encoding="utf-8", newline="\n"
        )
    print(
        json.dumps(
            {
                "scenes": len(data["scenes"]),
                "runtime": data["runtime"]["status"],
                "trace_sha256": hashlib.sha256(encoded.encode()).hexdigest(),
            }
        )
    )


if __name__ == "__main__":
    main()
