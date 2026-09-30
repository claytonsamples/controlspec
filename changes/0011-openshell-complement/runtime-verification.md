# Runtime follow-up: PASS within the recorded scope

September 30, 2026. Read-only reviewer in a separate agent context, sharing the
implementing assistant's lineage. This is not independent human certification.
The earlier protocol preview remains a separate experiment.

The fresh published Docker recipe booted the pinned OpenShell v0.1.2 gateway,
supervisor and sandbox. The documented strict JSON purchase command returned
HTTP 200 from the synthetic HTTPS target. The final recorder ran against clean
source `98f91d119db5f61c18f5743aee1802802ce030d2`.

| Evidence | Observed result |
| --- | --- |
| 14 real sandbox requests | All recorded status, reason and target-delta assertions passed |
| $42 permitted / $142 exact approval | One commit each; actual receipts reconciled |
| Missing approval, changed amount, recurrence, replay | Denied with no additional target effects |
| Missing receipt | Target effect occurred; completion remained unverified |
| Alternate path | Native L7 policy denied the request |
| Target IP / gateway port / middleware port | Each attempt correlates to a native `transparent_tcp_policy_denied` log inside its observation window |
| Middleware outage / recovery | Outage denied without effect; restart allowed one receipt-verified purchase under identical effective policy |
| Effective policy | REST `enforcement: enforce`, exact POST /purchases rule, fail-closed middleware |
| 77 focused tests | Passed; root executed and supplied results to the read-only reviewer |
| Lint / strict types | Passed; 53 source files checked by mypy |
| Runtime UI | All 14 observations checked on desktop and 390px mobile; no JavaScript errors or horizontal overflow |

The reviewer independently recomputed the raw report SHA-256:
`c0e375fd5b56c3e3185ed1a98880e70a87d68eea5ad3691dea327b6518eab414`.
All 24 exported ledger-event hashes are valid and contiguous from the recorded
prior anchor. All 15 retained decisions preserve non-authoritative flags. The
successful response receipts exactly match verified reconciliation events.

All 15 project invariants were reviewed. Draft exclusion, lineage separation,
determinism, missing-context behavior, conflicts, source-content isolation,
economics, scoped identities and append-only history retain their prior tests.
The runtime adds observed context binding, required receipt handling, safe
outage behavior, native denial of the tested alternate routes, and an unchanged
effective policy after recovery. Core evaluator, engine, ledger, policy and
target code were unchanged by this follow-up.

The report and supporting evidence are in
[`runtime-observations.json`](../../demo/space/runtime-observations.json) and
[`runtime-support.json`](../../demo/space/runtime-support.json). The support file
binds the original report hash and preserves image identities, selected supervisor
logs and recovery proof. Upstream text logs label inspected HTTPS requests as
`http`; the recorded curl commands use HTTPS with certificate verification.

Limits: scripted operator identities; synthetic transactions; shared host-trusted
HMAC; no aggregate budget or production tenant claim; no live LLM; no native-only
performance comparison. The Docker-socket controller and its plaintext,
unauthenticated gateway are trusted local orchestration. Sibling-container
isolation is not claimed. The recipe discloses AppArmor and resource-admission
settings. This review establishes only the routes exercised here.

Final full-suite CI, release and deployed Space checks belong to the release
owner and are recorded in the pull request and release.
