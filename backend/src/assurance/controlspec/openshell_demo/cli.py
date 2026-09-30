"""Host operator commands for the isolated synthetic integration, never an agent tool."""

import argparse
import json
import secrets
from pathlib import Path

import uvicorn

from .auth import ExtensionVerifier
from .engine import DemoEngine
from .middleware import ControlSpecMiddleware, TargetBoundary, create_server
from .policy import TrustedScope
from .target import create_target_app


def engine_at(path: Path) -> DemoEngine:
    return DemoEngine(
        path / "decisions.sqlite",
        (path / "ticket.secret").read_bytes(),
        (path / "operator.secret").read_bytes(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Create fresh host-only synthetic secrets")
    target = commands.add_parser("target", help="Serve the synthetic target on loopback")
    target.add_argument("--port", type=int, default=18081)
    approval = commands.add_parser("approve", help="Inspect and approve an exact pending action")
    approval.add_argument("--gateway-id", required=True)
    approval.add_argument("--sandbox-id", required=True)
    approval.add_argument("--action-id", required=True)
    service = commands.add_parser("middleware", help="Serve authenticated TLS middleware")
    service.add_argument("--gateway-id", required=True)
    service.add_argument("--key-id", required=True)
    service.add_argument("--public-key", type=Path, required=True)
    service.add_argument("--tls-cert", type=Path, required=True)
    service.add_argument("--tls-key", type=Path, required=True)
    service.add_argument("--bind", default="127.0.0.1:50051")
    service.add_argument("--target-host", default="host.openshell.internal")
    service.add_argument("--target-port", type=int, default=18081)
    args = parser.parse_args()
    directory = args.state_dir.resolve()
    if args.command == "init":
        directory.mkdir(parents=True, exist_ok=False, mode=0o700)
        for name in ("ticket.secret", "operator.secret"):
            with (directory / name).open("x", encoding="ascii") as output:
                output.write(secrets.token_hex(32))
            (directory / name).chmod(0o600)
        print("Created synthetic secrets. Keep this directory outside agent access.")
    elif args.command == "target":
        app = create_target_app(
            directory / "target.sqlite", (directory / "ticket.secret").read_bytes()
        )
        uvicorn.run(app, host="127.0.0.1", port=args.port)
    elif args.command == "approve":
        engine = engine_at(directory)
        scope = TrustedScope(gateway_id=args.gateway_id, sandbox_id=args.sandbox_id)
        pending = engine.pending(args.action_id, scope)
        if pending is None:
            raise SystemExit("No pending action in that exact scope")
        print(json.dumps(pending, indent=2))
        expected = "APPROVE " + pending["request_digest"]
        if input("Type " + expected + " to approve this synthetic action: ") != expected:
            raise SystemExit("No approval recorded")
        result = engine.approve(
            args.action_id, scope, (directory / "operator.secret").read_text(encoding="ascii")
        )
        print(result.decision.model_dump_json(indent=2))
    else:
        verifier = ExtensionVerifier(
            args.gateway_id,
            "urn:openshell:extension:middleware:controlspec-demo",
            {args.key_id: args.public_key.read_bytes()},
        )
        middleware = ControlSpecMiddleware(
            engine_at(directory),
            verifier,
            TargetBoundary(args.target_host, args.target_port),
        )
        server, port = create_server(
            middleware,
            args.bind,
            certificate_chain=args.tls_cert.read_bytes(),
            private_key=args.tls_key.read_bytes(),
        )
        server.start()
        print(f"Synthetic ControlSpec middleware listening with TLS on port {port}")
        try:
            server.wait_for_termination()
        except KeyboardInterrupt:
            server.stop(2).wait()


if __name__ == "__main__":
    main()
