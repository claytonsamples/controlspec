"""Reproducible local OpenShell experiment, not a production deployment.

Run in the task-owned Linux controller, with /repo read-only and /state private.
The controller has no published host ports; its Docker socket is orchestration
authority and must never be mounted in a sandbox. No secrets are printed.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import ipaddress
import json
import os
import secrets
import shutil
import signal
import ssl
import subprocess
import sys
import tarfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.request import urlopen

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

STATE = Path("/state")
REPO = Path("/repo")
AUDIENCE = "urn:openshell:extension:middleware:controlspec-demo"
SANDBOX_IMAGE = (
    "ghcr.io/nvidia/openshell/sandbox@sha256:"
    "bf4797b6c511f2d8ba02955dbba4bf76c1f0dd6d83531420c5408d5f1fb9d72f"
)
BINARIES = {
    "openshell": (
        "openshell-x86_64-unknown-linux-musl.tar.gz",
        "7eb6917285331a09e3300266a0558616481a5e9927cae2612ea07c4045b6dd6f",
    ),
    "openshell-gateway": (
        "openshell-gateway-x86_64-unknown-linux-gnu.tar.gz",
        "218d887845b3a020ab7535c9985eb9c666d6938f144044957f8b82b42892aadb",
    ),
}


def install_binaries() -> None:
    """Install only exact upstream v0.1.2 binaries after archive hash verification."""
    for binary, (archive_name, expected) in BINARIES.items():
        url = f"https://github.com/NVIDIA/OpenShell/releases/download/v0.1.2/{archive_name}"
        with urlopen(url, timeout=90) as response:
            archive_bytes = response.read(100 * 1024 * 1024 + 1)
        if hashlib.sha256(archive_bytes).hexdigest() != expected:
            raise RuntimeError(f"Upstream archive checksum mismatch: {archive_name}")
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            members = archive.getmembers()
            if (
                len(members) != 1
                or members[0].name != binary
                or not members[0].isfile()
            ):
                raise RuntimeError("Unexpected upstream archive layout")
            source = archive.extractfile(members[0])
            if source is None:
                raise RuntimeError("Missing upstream binary")
            destination = Path("/usr/local/bin") / binary
            destination.write_bytes(source.read())
            destination.chmod(0o755)
        print(f"Verified and installed {binary} v0.1.2 ({expected})")


def private_file(path: Path, data: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o600)


def pem_key(key: object) -> bytes:
    return key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def prepare(
    controller_ip: str, workload_image: str, supervisor_image: str, namespace: str
) -> dict:
    address = ipaddress.IPv4Address(controller_ip)
    if address.is_loopback or address.is_unspecified:
        raise ValueError("controller IPv4 must be reachable from the supervisor")
    STATE.mkdir(exist_ok=True, mode=0o700)
    STATE.chmod(0o700)
    for name in ("logs", "jwt", "tls", "policies"):
        (STATE / name).mkdir(exist_ok=True, mode=0o700)
    metadata_path = STATE / "bootstrap.json"
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text())
        if metadata["controller_ip"] != controller_ip:
            raise RuntimeError("controller address changed; use fresh task-owned state")
        if metadata["workload_image"] != workload_image:
            raise RuntimeError("workload image changed; use fresh task-owned state")
        if (
            metadata["supervisor_image"] != supervisor_image
            or metadata["namespace"] != namespace
        ):
            raise RuntimeError(
                "runtime configuration changed; use fresh task-owned state"
            )
        return metadata

    gateway_id = "controlspec-runtime-" + secrets.token_hex(6)
    key_id = gateway_id + "-key"
    for name in ("ticket.secret", "operator.secret"):
        private_file(STATE / name, secrets.token_hex(32).encode("ascii"))
    signing_key = ed25519.Ed25519PrivateKey.generate()
    private_file(STATE / "jwt/signing.pem", pem_key(signing_key))
    private_file(
        STATE / "jwt/public.pem",
        signing_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    private_file(STATE / "jwt/kid", (key_id + "\n").encode())

    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "ControlSpec local runtime CA")]
    )
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "ControlSpec middleware")]
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(address),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    # Keep only the CA certificate: the ephemeral CA signing key is discarded.
    private_file(STATE / "tls/ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    private_file(
        STATE / "tls/server.pem", leaf.public_bytes(serialization.Encoding.PEM)
    )
    private_file(STATE / "tls/server-key.pem", pem_key(leaf_key))

    for source in ("policy-controlspec.yaml", "policy-native.yaml"):
        shutil.copyfile(
            REPO / "integrations/openshell" / source, STATE / "policies" / source
        )

    config = f'''[openshell]
version = 2

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "/state/jwt/signing.pem"
public_key_path = "/state/jwt/public.pem"
kid_path = "/state/jwt/kid"
gateway_id = "{gateway_id}"

[[openshell.supervisor.middleware]]
name = "controlspec-demo"
grpc_endpoint = "https://{controller_ip}:50051"
tls_ca_cert_path = "/state/tls/ca.pem"
audience = "{AUDIENCE}"
allow_insecure_transport = false
max_payload_bytes = 4096
timeout = "2s"

[openshell.drivers.docker]
sandbox_label = "{namespace}"
grpc_endpoint = "http://{controller_ip}:17670"
default_image = "{workload_image}"
supervisor_image = "{supervisor_image}"
sandbox_runtime_image = "{SANDBOX_IMAGE}"
image_pull_policy = "if_not_present"
app_armor_profile = "Unconfined"

[openshell.drivers.docker.resource_admission]
enabled = false
'''
    private_file(STATE / "gateway.toml", config.encode())
    metadata = {
        "gateway_id": gateway_id,
        "key_id": key_id,
        "audience": AUDIENCE,
        "controller_ip": controller_ip,
        "workload_image": workload_image,
        "supervisor_image": supervisor_image,
        "namespace": namespace,
        "synthetic_only": True,
        "middleware_tls": True,
        "target_origin": "https://host.openshell.internal:18081",
        "created_at": now.isoformat(),
    }
    private_file(metadata_path, (json.dumps(metadata, indent=2) + "\n").encode())
    return metadata


def child_environment() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        HOME="/state",
        XDG_DATA_HOME="/state/data",
        XDG_STATE_HOME="/state/state",
        XDG_CONFIG_HOME="/state/config",
        PYTHONPATH="/repo/backend/src:/repo/backend:/repo",
        PYTHONUNBUFFERED="1",
    )
    return env


def prepare_target_tls() -> None:
    """Add target-only TLS trust without replacing any existing signing secrets."""
    metadata_path = STATE / "bootstrap.json"
    metadata = json.loads(metadata_path.read_text())
    address = ipaddress.IPv4Address(metadata["controller_ip"])
    paths = [
        STATE / "tls" / name
        for name in ("target-ca.pem", "target.pem", "target-key.pem")
    ]
    if any(path.exists() for path in paths) and not all(
        path.exists() for path in paths
    ):
        raise RuntimeError(
            "Incomplete target TLS bundle; inspect state rather than overwrite keys"
        )
    if not all(path.exists() for path in paths):
        now = datetime.now(UTC)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "ControlSpec synthetic target CA")]
        )
        ca = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "host.openshell.internal")]
        )
        leaf = (
            x509.CertificateBuilder()
            .subject_name(leaf_name)
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("host.openshell.internal"),
                        x509.IPAddress(address),
                        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .sign(ca_key, hashes.SHA256())
        )
        private_file(paths[0], ca.public_bytes(serialization.Encoding.PEM))
        private_file(paths[1], leaf.public_bytes(serialization.Encoding.PEM))
        private_file(paths[2], pem_key(leaf_key))
        # CA private key is ephemeral; only this isolated target certificate can be issued.
    metadata["target_origin"] = "https://host.openshell.internal:18081"
    metadata["target_tls"] = True
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")


def serve_target() -> None:
    import uvicorn

    from assurance.controlspec.openshell_demo.target import create_target_app

    app = create_target_app(
        STATE / "target.sqlite", (STATE / "ticket.secret").read_bytes()
    )
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=18081,
        access_log=True,
        ssl_certfile=str(STATE / "tls/target.pem"),
        ssl_keyfile=str(STATE / "tls/target-key.pem"),
    )


def serve_middleware() -> None:
    from assurance.controlspec.openshell_demo.auth import ExtensionVerifier
    from assurance.controlspec.openshell_demo.cli import engine_at
    from assurance.controlspec.openshell_demo.middleware import (
        ControlSpecMiddleware,
        TargetBoundary,
        create_server,
    )

    metadata = json.loads((STATE / "bootstrap.json").read_text())
    verifier = ExtensionVerifier(
        metadata["gateway_id"],
        AUDIENCE,
        {metadata["key_id"]: (STATE / "jwt/public.pem").read_bytes()},
    )

    class ObservedMiddleware(ControlSpecMiddleware):
        def EvaluateHttpRequest(self, request, context):
            from google.protobuf.json_format import MessageToDict

            with (STATE / "rpc-targets.jsonl").open("a") as output:
                output.write(
                    json.dumps({"observed_target": MessageToDict(request.target)})
                    + "\n"
                )
            return super().EvaluateHttpRequest(request, context)

    server, port = create_server(
        ObservedMiddleware(engine_at(STATE), verifier, TargetBoundary(scheme="https")),
        "0.0.0.0:50051",
        certificate_chain=(STATE / "tls/server.pem").read_bytes(),
        private_key=(STATE / "tls/server-key.pem").read_bytes(),
    )
    server.start()
    print(f"Authenticated TLS middleware ready on port {port}", flush=True)
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: server.stop(2))
    server.wait_for_termination()


def spawn(name: str, command: list[str]) -> int:
    pid_path = STATE / f"{name}.pid"
    if pid_path.exists():
        previous = int(pid_path.read_text())
        try:
            os.kill(previous, 0)
        except ProcessLookupError:
            pass
        else:
            # PID 1 without an init process may retain exited children as zombies.
            status = (
                Path(f"/proc/{previous}/stat").read_text().rsplit(")", 1)[1].split()[0]
            )
            if status != "Z":
                raise RuntimeError(
                    f"{name} already has a live recorded process; inspect before restarting"
                )
    with (STATE / "logs" / f"{name}.log").open("ab", buffering=0) as output:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            env=child_environment(),
            start_new_session=True,
        )
    pid_path.write_text(str(process.pid))
    return process.pid


def wait_http(url: str, seconds: int, *, ca_file: Path | None = None) -> None:
    deadline = time.monotonic() + seconds
    context = ssl.create_default_context(cafile=str(ca_file)) if ca_file else None
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=1, context=context) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"Service not ready at {url}; inspect /state/logs")


def up() -> None:
    import grpc

    prepare_target_tls()
    metadata = json.loads((STATE / "bootstrap.json").read_text())
    script = str(Path(__file__).resolve())
    spawn("target", [sys.executable, script, "target"])
    wait_http("https://127.0.0.1:18081/state", 15, ca_file=STATE / "tls/target-ca.pem")
    spawn("middleware", [sys.executable, script, "middleware"])
    with grpc.secure_channel(
        "127.0.0.1:50051",
        grpc.ssl_channel_credentials((STATE / "tls/ca.pem").read_bytes()),
    ) as channel:
        grpc.channel_ready_future(channel).result(timeout=15)
    spawn(
        "gateway",
        [
            "/usr/local/bin/openshell-gateway",
            "--compute-driver",
            "docker",
            "--config",
            "/state/gateway.toml",
            "--bind-address",
            "0.0.0.0",
            "--port",
            "17670",
            "--health-port",
            "17671",
            "--metrics-port",
            "0",
            "--log-level",
            "info",
            "--disable-tls",
            "--db-url",
            "sqlite:/state/gateway.db?mode=rwc",
        ],
    )
    wait_http("http://127.0.0.1:17671/healthz", 45)
    print(
        json.dumps(
            {
                "status": "services_ready",
                "gateway_id": metadata["gateway_id"],
                "gateway_endpoint": "http://127.0.0.1:17670",
                "state": "/state",
                "middleware_transport": "TLS + signed exact-audience JWT",
            }
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=[
            "install-binaries",
            "prepare",
            "prepare-target-tls",
            "up",
            "target",
            "middleware",
        ],
    )
    parser.add_argument("--controller-ip")
    parser.add_argument(
        "--workload-image", default="controlspec-runtime-workload:local"
    )
    parser.add_argument("--supervisor-image")
    parser.add_argument("--namespace")
    args = parser.parse_args()
    if args.command == "prepare":
        if not (args.controller_ip and args.supervisor_image and args.namespace):
            parser.error(
                "prepare requires --controller-ip, --supervisor-image and --namespace"
            )
        import re

        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,40}", args.namespace):
            parser.error("namespace must contain lowercase letters, digits and hyphens")
        for value in (args.workload_image, args.supervisor_image):
            if not re.fullmatch(r"[a-zA-Z0-9_./:@-]+", value):
                parser.error("invalid image reference")
        prepare(
            args.controller_ip,
            args.workload_image,
            args.supervisor_image,
            args.namespace,
        )
        print(
            "Prepared private state, exact JWT trust, TLS certificates, and both policies in /state"
        )
    elif args.command == "install-binaries":
        install_binaries()
    elif args.command == "prepare-target-tls":
        prepare_target_tls()
        print(
            "Prepared separate target CA and HTTPS leaf in /state/tls; existing secrets preserved"
        )
    elif args.command == "up":
        up()
    elif args.command == "target":
        serve_target()
    else:
        serve_middleware()


if __name__ == "__main__":
    main()
