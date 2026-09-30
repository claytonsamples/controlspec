# NVIDIA OpenShell protocol provenance

The adapter targets **v0.1.2**, commit
`6648bd0c290efbc41ba131ee9831ee45cd431f94` of
[NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell/tree/6648bd0c290efbc41ba131ee9831ee45cd431f94).
This is a source pin, not a claim of a successful full OpenShell runtime deployment.
See the run evidence for the actual execution mode and limitations.

`proto/extension.proto` and `proto/supervisor_middleware.proto` are exact upstream
Git-blob byte copies, unaffected by checkout line-ending conversion. Their SHA-256
hashes and the copied Apache-2.0 license are recorded in
`proto/manifest.json`. Source copyright/SPDX notices remain intact. Only generated
Python imports are changed to package-relative imports; generated files use LF
line endings. The pinned upstream has no root `NOTICE` file. Its
`THIRD-PARTY-NOTICES` inventories dependencies of the full upstream application;
those application dependencies are not vendored here. Generation command:

```powershell
uv run --project backend --extra openshell --extra dev python integrations/openshell/generate_proto.py
```

The generator verifies vendored hashes before running the locked `grpcio-tools`
compiler. The generated files contain compiler/runtime version requirements;
`backend/uv.lock` fixes the actual dependencies. Generated code is third-party
protocol plumbing, not human policy authority.

## Identity source and transport

Authentication follows upstream `crates/openshell-extension-core/src/jwt.rs` and
`crates/openshell-server/src/auth/sandbox_jwt.rs`: EdDSA with an operator-pinned
Ed25519 public key, `typ=openshell-ext+jwt`, issuer `openshell-gateway:<id>`,
audience `urn:openshell:extension:middleware:controlspec-demo`, finite expiration
and at most one hour lifetime. Gateway calls have `caller_kind=gateway` and their
issuer as subject. Evaluation calls require `caller_kind=supervisor`, a signed
`sandbox_id`, and subject `spiffe://openshell/sandbox/<id>`. The signed sandbox ID
must equal protobuf `RequestContext.sandbox_id`. Display names and workspace
labels never supply authorization scope. Bootstrap tokens are not accepted.

Use TLS for registration; configure gateway-issued JWT signing and explicitly
provide the trusted key to the adapter. The adapter does not fetch keys from
request-provided URLs. Example gateway registration (operator-supplied paths):

```toml
[[openshell.supervisor.middleware]]
name = "controlspec-demo"
grpc_endpoint = "https://YOUR-MIDDLEWARE-HOST:50051"
tls_ca_cert_path = "/operator/controlspec-ca.pem"
audience = "urn:openshell:extension:middleware:controlspec-demo"
max_payload_bytes = 4096
timeout = "500ms"
```

No `allow_insecure_transport` production fallback is supplied. Explicit loopback
protocol tests use plaintext but still validate fixture-signed JWTs; those are
test identities, not evidence of a running OpenShell supervisor.

## Deliberately narrow boundary

The accompanying policies expose only `POST http://host.openshell.internal:18081/purchases`
from `/usr/bin/curl`. USD synthetic JSON purchases only. Unknown paths, methods,
hosts, ports, schemes, query strings, oversized/ambiguous bodies, and WebSockets
are denied by the adapter. Native policy restricts destinations before it runs.
`Describe` advertises only HTTP request / pre-credentials support; unsupported
RPCs cannot grant permission. Config is a fixed synthetic fixture profile.

ControlSpec is the only/final body-inspecting middleware in this policy. The
adapter preserves the original body and adds only a signed ticket. The controlled
synthetic target additionally requires and consumes that ticket; this target-side
defense must not be attributed to native OpenShell alone. Native comparison arms
must explicitly disclose their ticket-free synthetic target configuration.

Policy text alone does not prove enforcement. Retain the effective loaded policy,
runtime version, target state, and denied alternate-route observations when an
actual runtime is available. Local direct gRPC tests exercise the protocol
boundary but do not prove sandbox containment or middleware outage behavior in
OpenShell itself.
