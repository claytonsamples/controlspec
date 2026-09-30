# Implementation and verification ownership

The explicit September 30 build-and-publish request authorizes this bounded
experimental release. No operational policy or external communication is approved
by the demo. The 15 frame invariants remain acceptance constraints.

| Owner | Permitted scope | Dependency | Required evidence |
| --- | --- | --- | --- |
| Architect | Design only | Existing contracts, upstream v0.1.2 | Interfaces and trust boundaries |
| Engine builder | Demo policy, engine, ledger, target, models; engine tests | Design | Real evaluator, approval, expiry, replay/concurrency, immutable state |
| Adapter builder | Auth, middleware, protobuf; provenance, policies; RPC tests | Engine interface | Signed identity, TLS, strict boundary and gRPC tests |
| Presentation builder | HTML template and UI review | Report contract | Desktop/mobile, missing data, unavailable native lane |
| Root | CLI, smolagents tool, recorder, docs, CI, publication | Builder interfaces | Full suite, types/lint, recording and public artifacts |
| Read-only verifier | Inspection and reported evidence | Integrated implementation | Criterion mapping, adversarial probes, scoped PASS/BLOCK |

No parallel edits to core schemas, evaluator or evidence ledger. The existing
core and catalog fixtures are unchanged. The new local demo ledger has one owner.
The reference API remains non-authoritative. Reviewers are separate model
contexts within the same assistant lineage, not independent human certification.

## Deferred runtime criterion

The Docker engine crashed during startup while initializing its inference-manager
socket on this recording host. Actual OpenShell execution, native policy parity,
policy admission, network isolation and sandbox bypass probes are NOT RUN.
Release scope is an authenticated protocol and synthetic-target preview, as
allowed by the frame's explicit evidence requirement. No unavailable result is
converted into PASS. The recorder itself never launches or diagnoses Docker.
