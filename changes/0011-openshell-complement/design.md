# ControlSpec / OpenShell synthetic integration design

Status: accepted-scope implementation design following the user's `Go DO IT!`
instruction. This document designs the synthetic integration only; it does not
publish enterprise policy or make the reference API production-authoritative.

## Decision and scope

Implement one version-pinned OpenShell supervisor middleware service for a
synthetic purchase API. Preserve the existing evaluator, reference API, and
personal fixture packs unchanged. Demonstrate three arms: an unguarded synthetic
target; that target behind an explicitly published OpenShell policy; the same
OpenShell policy with ControlSpec middleware. Publish the exact effective policy,
configuration, implementation revision, observations, and unavailable checks.

The supported public OpenShell seam is `HTTP_REQUEST` / `PRE_CREDENTIALS` via
`EvaluateHttpRequest`, with `Describe` and `ValidateConfig`. Inputs contain the
HTTP target, headers, body, and sandbox context. Allow or deny is synchronous;
there is no documented durable human-approval suspension result. A denial with
`approval_required` creates a separately retriable action. Never wait on a person
inside the gRPC evaluation deadline.

The deliverable must distinguish real OpenShell execution from direct protocol
tests and synthetic harness execution. If the actual runtime cannot launch,
record that limitation rather than emitting a successful integration observation.

## Modules and ownership boundaries

Suggested package: `examples/openshell/controlspec_openshell/`. Keep package code
isolated from `backend/src/assurance/controlspec/`.

1. Domain owner: `models.py`, `policy.py`, `engine.py`, `ledger.py`, `target.py`,
   and corresponding domain/ledger tests. Owns strict request mapping, fixture
   policy, evaluator facts, approval, reservations, and synthetic target state.
2. Transport owner: `middleware.py`, `auth.py`, generated `proto/` files, upstream
   pin/manifest, transport configuration and transport/auth tests. Depends on the
   domain interface below. No independent business-rule implementation.
3. Runner/presentation owner: CLI/runner, comparison configurations, documentation,
   recorded result export and static display. Depends on both prior interfaces.
   Display observed results; do not encode successful verdicts in presentation.
4. Independent verifier: read-only acceptance-to-code/test/observation review.

Names may be adapted by the implementation owner, but contracts and trust
boundaries below must remain explicit. Shared schema and persistence edits have
one owner. Root coordinates cross-owner changes.

## Strict typed input and mapping

`PurchaseRequest` has a fixed schema version, action/idempotency identifier,
strict positive integer `amount_minor`, `currency` restricted to USD for this
example, a synthetic merchant/cart identifier, and strict boolean `recurring`.
No floats, coercions, unknown fields, duplicate JSON object keys, or extra action
paths. Freeze exact field names in implementation tests. Limit body size and
require the supported JSON content type. Do not infer missing values. Do not
accept actor, role, tenant, policy, approval, clock, or authority supplied in body
or headers as trusted input.

`TrustedScope(gateway_id, sandbox_id)` comes from validated extension identity;
the body cannot choose it. Bind request context sandbox identity to the JWT.
Local harness scope must be explicitly marked simulated and unavailable through
the authenticated deployment mode. Scope every record, lookup, and key by both
gateway and sandbox identity. This is demo isolation, not an enterprise tenant
identity system.

Engine mapping creates an `ActionIntent` with an exact canonical context hash,
intent digest, action/resource identity, stable first-seen requested-at instant,
and idempotency key. A retry uses the stored intent rather than a newly timed
intent. A changed request under the same key is rejected before evaluation.
The full request digest and exact target method/path are bound to any execution
ticket. Unknown method/path/host/query variants must not reach permissive logic.

## Real evaluator and example policy

Use `ControlSpecEvaluator.evaluate(intent, snapshot, facts)` with finalized
objects and `SnapshotAuthorityMode.NON_AUTHORITATIVE_CONFORMANCE`. Keep the
result's non-authoritative extension. The synthetic adapter interprets a
permissive reference decision only within this isolated demo target.

The existing personal pack's over-limit effect is an unconditional
`require_approval` with no ApprovalRequirement. Adding an ApprovalFact cannot
make that effect allow. Do not bypass that result or edit the published fixture.
Instead, create an explicitly synthetic, separately named example control set:

- Nonrecurring purchase within the existing example threshold may allow.
- Over-limit purchase uses an allow effect with an ApprovalRequirement whose
  missing-fact failure is require_approval.
- Recurring purchases remain blocked or require their own explicitly modeled
  requirement; never accidentally inherit one-time purchase permission.
- Unknown facts fail closed. Unknown actions and missing matched controls cannot
  allow. No arbitrary policy code or model call makes the authorization decision.

Thresholds are borrowed example data, not assertions about the user's personal
or enterprise risk appetite. Record the example source and this explicit design
decision with the demo control set.

## Human approval boundary

Approval is a separate local operator CLI path, outside the sandbox. It requires
an operator secret or signing credential held outside agent mounts, environment,
request data, and outputs. Never implement `approved: true` on the agent API.
The CLI displays exact action, scope, digest, amount, policy digest and expiration
before the operator approves. Automated tests may use fixture operators but must
label them simulated; a scripted runner cannot claim a real human approval.

Construct a finalized `ApprovalFact` only after verifying operator authority.
It references the stored pending intent and basis decision, requirement ID and
scope digest. The configured human actor is distinct from the agent and its
lineage; caller-selected approver IDs/roles are forbidden. Fill lineage facts
only from the synthetic identity registry. Require a finite validity window,
current policy digest, and exact pending action; stale, foreign-scope, related,
or altered approvals do not grant execution. Reevaluate through the same core
evaluator with `EvaluationFacts.approval_basis_ref` and that ApprovalFact.

## Append-only state, reservations and replay

Use SQLite outside agent access, with a versioned schema, transactions, unique
scope/idempotency identities, and append-only event records. Retain canonical
request, intent, decision, trace, approval facts, timestamps and digests. An
event hash chain detects accidental modification but is not tamper-proof against
the host operator. Materialized state may be rebuilt from retained events.

Lifecycle: pending -> approved -> reserved -> committed. Denied and expired
events are retained. Reserved actions with unknown target outcome stay unresolved
until reconciliation; a timeout must not release authority or manufacture success.
Any permissive action (including one below the threshold) needs an atomic
reservation before its request is forwarded. Reserve checks exact request,
scope, policy, current time, prior consumption and approval atomically.

Return an authenticated, short-lived execution ticket bound to the exact request
digest, scope, policy/decision digest, reservation ID, and nonce. Store ticket
signing material outside the agent. Overwrite/reject agent-supplied ticket
headers. No second fresh reservation is issued for an already reserved key.
Duplicate same-body delivery at the target returns the prior result; same key
with altered body is rejected. Concurrent retry tests must prove at most one
target mutation.

The synthetic controlled target validates the ticket and atomically records
nonce consumption, purchase mutation, and target evidence. Target state is
authoritative only for this simulated purchase. A controlled target's requirement
for a ticket is explicit in the comparison report; do not misattribute this
additional defense to OpenShell alone. Comparison arms use separate clean
synthetic instances and disclose their authentication configuration.

Avoid cross-database atomicity claims: the middleware reservation and target
commit are separate transactions. Target evidence reconciles them. Preserve
unknown outcome across crashes; no blind automatic retry with a fresh key.

## OpenShell transport and deployment boundary

Pin an actual upstream commit/release, protobuf digests and generated-code tool
versions. Verify that selected protocol definitions match the installed runtime;
do not claim latest compatibility from a direct gRPC smoke test. Startup protocol
negotiation, Describe and ValidateConfig are real implementations.

Require TLS and gateway-issued extension JWTs for the documented authenticated
mode. Pin EdDSA, expected type, trusted issuer/key, audience, expiration,
caller_kind and sandbox ID. Reject a header/body identity that disagrees with the
authenticated scope. The gateway's extension JWT is not the business approval
token and does not authorize a purchase. Local plaintext fixtures must be a
separate explicit demo mode, never fallback after failed authentication.

Use `on_error: fail_closed`; service unavailability, invalid output, timeout,
schema error and oversized payload block forwarding. Configure ControlSpec as
the only request-mutating middleware or the final validator. No later stage may
change the authorized body. For this bounded example support HTTP JSON only;
deny WebSocket, binary, `tls: skip`, opaque tunnels, redirects/aliases and other
paths that would bypass inspection. Preserve OpenShell provider credentials
outside the agent; middleware runs before their injection.

No OpenShell gateway policy-writing credential is available to the agent.
Effective policy must be retained for the run; dynamic weakening is outside
demo scope and invalidates an enforcement claim. Gateway interceptors could
protect policy later, but are not necessary to this fixed-policy demonstration.

## Evidence and failure handling

Observations report separately: parsing, network policy, middleware decision,
reservation, target invocation, target mutation, and evidence reconciliation.
An allow is not execution success. A missing/failed response is not proof of
nonexecution. Record target-side before/after state and unique event references.
Correlate OpenShell OCSF output as supplemental evidence; its live buffer can
lose entries and is not the durable ledger. Report any known collection gaps.

Required tests: missing/extra/malformed facts; draft-policy exclusion; exact
approval and self/lineage rejection; expiry; policy change; altered action;
foreign sandbox/gateway; JWT mismatch; duplicate key/body; concurrent replay;
middleware outage; ticket forgery; target timeout/unknown outcome; ledger restart;
record reconstruction; and direct/alternate-route attempts in the actual runtime.
Do not label the last category passed when only an in-process test was run.

## Invariants and tradeoffs

Human example ownership, fixture-published authority separation, independent
approval, deterministic typed evaluation, exact pre-action binding, evidence
after action, safe failure, source links, no agent policy mutation, no economic
permission override, append-only history, separated roles, scoped isolation,
no demonstrated bypass, and observed-versus-simulated precision remain explicit.
This small example is not a production authorization system, authenticated
enterprise tenancy, complete risk authoring product, or proof of arbitrary
target integration. SQLite is chosen for reproducibility, not multi-region scale.
No migration touches existing core API state; the new demo DB starts at schema 1
and unknown schema versions fail startup without destructive conversion.

## Primary references

- https://docs.nvidia.com/openshell/latest/extensibility/supervisor-middleware
- https://docs.nvidia.com/openshell/latest/extensibility/supervisor-middleware/operations
- https://docs.nvidia.com/openshell/latest/extensibility/supervisor-middleware/configure
- https://docs.nvidia.com/openshell/latest/extensibility/overview#authenticating-extensions
- https://docs.nvidia.com/openshell/latest/observability/accessing-logs
- https://github.com/NVIDIA/OpenShell/blob/main/proto/supervisor_middleware.proto

These links describe the discovered integration seam, not a pinned compatibility
claim. The implementation's upstream manifest must record the exact tested pin.
