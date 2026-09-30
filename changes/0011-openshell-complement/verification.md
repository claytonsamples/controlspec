# Read-only review: PASS for the experimental protocol preview

September 30, 2026. Separate verifier context; same assistant lineage as the
implementation. This is not independent human security certification. No native
OpenShell enforcement or production-readiness verdict is implied.

| Acceptance | Implementation and evidence | Result |
| --- | --- | --- |
| AC1 protocol and identity | Pinned upstream bytes/hashes, exact JWT source comparison, auth/middleware RPC tests including TLS | PASS |
| AC2 typed control authority | Real evaluator, synthetic published fixture, non-authoritative snapshot flags; draft/deterministic/composition/economics tests | PASS |
| AC3 approval and replay | Exact ApprovalFact, changed request/policy/scope, expiry/restart, eight concurrent reservations yield one ticket | PASS within synthetic identity model |
| AC4 effect and proof | HTTP target verifies ticket; eight deliveries yield one purchase; missing/forged evidence cannot reconcile | PASS for synthetic target |
| AC5 comparison honesty | Native NOT_RUN, body-aware native capability acknowledged, different transports/ticket requirement disclosed | PASS for explicit protocol-preview scope |
| AC6 static inspection | Nine recorded scenes, ten recording tests, escaped embedded data, runtime-conditioned lane headline | PASS; UI owner separately reviewed mobile/desktop |
| AC7 checks/publication | 62 engine/RPC + 55 existing invariant + 10 recording tests independently observed passing | Pre-publication PASS; release owner checks final provenance and deployment |

Additional independent probes passed: imperative source text did not grant
approval; an executor acting as prohibited evidence certifier produced
INCOMPLETE; both vendored protobufs and their license were byte-identical to
the pinned NVIDIA commit with matching manifest digests.

The review mapped all 15 invariants: human control and no policy-writing API;
published-only fixture snapshots; independent approval and evidence assessment;
typed determinism; exact context binding; required proof; safe missing inputs;
source digests; immutable policy inputs; cost cannot grant authority; append-only
history and corrupt-chain rejection; separated synthetic roles; scoped gateway/
sandbox identity; ticketless/forged/unsupported-route denial; observed/simulated/
unrun facts distinguished. Enterprise tenant identity and native sandbox bypass
resistance remain unimplemented/unverified, respectively.

Resolved finding: a stopped gRPC server can yield either UNAVAILABLE or
DEADLINE_EXCEEDED. The outage acceptance test now accepts both but requires zero
target effects, no forwarding and no reconciliation. Resolved presentation
findings: generic runtime NOT_RUN description on every reproduction; controlled
lane named protocol fixture when no runtime is observed.

Root integration checks before source commit: 320 tests passed, then all 10 new
recording tests passed; strict mypy passed 53 source files; targeted Ruff passed;
operator CLI help smoke passed. Final CI result and deployment are recorded in
the release/PR. Core evaluator and original reference catalogs are unchanged.

Retained limitations: synthetic operator registry, host-trusted shared HMAC,
single-origin adapter mapping, per-action-ID rather than aggregate budget state,
unrun native enforcement, and no production authorization. The release owner
must record final HTML/traces against committed source before publication.
