# Python reference client

The client constructs digest-valid ActionIntent objects and calls the seven
existing ControlSpec reference operations. It uses the Python backend package
and standard-library HTTP transport. It is not a separately distributed SDK.
It never executes an agent action or publishes policy.

## Run a fresh-input simulation

Follow the [README quickstart](../README.md) to install dependencies and start the
reference server. From the repository root:

```sh
uv run --project backend --locked python examples/controlspec/client_journey.py --base-url http://127.0.0.1:8765 --requested-at 2026-09-06T12:00:00.000000Z --idempotency-prefix my-simulation-001
```

The example constructs fresh personal-spending and SMB-sales inputs, discovers
exact pack IDs and digests, decides, rechecks unchanged and changed inputs, then
submits a simulated caller report for receipt assessment. No purchase, email or
other target operation occurs, and no receipt is stored durably.

Supply your own canonical UTC timestamp and idempotency identity for a new input.
The example uses that timestamp as caller reference time for reproducibility;
it does not assert current real-world authorization. Output explicitly includes
`simulation_only` and `may_authorize_external_effect: false`.

## Build an intent

Import `ControlSpecReferenceClient` and `build_action_intent` from
`assurance.controlspec.client`. Import Actor, Action, Resource and other contracts
from `assurance.controlspec.contracts`. The helper requires:

- Explicit namespace and intent ID.
- Strict Actor, Action and Resource objects.
- Context expressed using the existing portable JSON types.
- A canonical UTC `requested_at` with six fractional digits and uppercase `Z`.
- An explicit caller-owned `idempotency_key`.

Optional route, evidence references, cost and retry count retain their existing
contract types. The helper validates and detaches nested input values, computes
the canonical context digest, and finalizes the intent digest. It infers no time,
identity, route or policy. Returned nested dictionaries remain mutable Python
values: rebuild an intent after changes rather than mutating a hashed object.

See [client_journey.py](../examples/controlspec/client_journey.py) for the complete
typed construction and request sequence.

## Discover and select exact controls

Build PackSelection from the exact `catalog_id` and `semantic_digest` returned by
catalog discovery. Reuse that selection in DecideRequest, RecheckRequest and
ReceiptAssessmentRequest. Unknown custom packs produce errors; the client does
not install a pack, choose a replacement, or silently select the latest version.
Control-level discovery also supports the existing ControlSelection contract.

| Client method | Existing HTTP operation | Typed response |
|---|---|---|
| `list_packs()` | GET `/controlspec/v0/packs` | PackListResponse |
| `get_pack(catalog_id)` | GET `/controlspec/v0/packs/{catalog_id}` | PackDetailResponse |
| `list_controls()` | GET `/controlspec/v0/controls` | ControlListResponse |
| `get_control(catalog_id)` | GET `/controlspec/v0/controls/{catalog_id}` | ControlDetailResponse |
| `decide(request)` | POST `/controlspec/v0/decide` | DecideResponse |
| `recheck(request)` | POST `/controlspec/v0/recheck` | RecheckResponse |
| `assess_receipt(request)` | POST `/controlspec/v0/receipts` | ReceiptAssessmentResponse |

Catalog IDs are encoded as single path segments. Decisions and receipt assessments
retain explicit reference authority flags. An unchanged recheck confirms a
reference binding; it does not prove a tool was mediated or an action executed.

## Transport and errors

Pass `http://127.0.0.1:8765` for the quickstart server. The constructor's default
origin is `http://127.0.0.1:8000`. Origins must use HTTP(S) with no embedded
credentials, path, query or fragment. HTTPS certificate verification remains on.
Environment and system proxies are disabled. The default transport never follows
redirects or retries requests and has no action-execution callback interface.

The socket-operation timeout defaults to 10 seconds and must be finite, greater
than zero and at most 60 seconds. This is not an absolute whole-request deadline;
a slowly trickling peer can prolong total elapsed time. Request size defaults to
1 MiB, also its maximum. Response size defaults to 4 MiB, with a 16 MiB maximum.
The transport reads at most the response limit plus one byte and closes the response.
An injected ReferenceTransport is trusted testing infrastructure and must retain
these constraints; it is not a boundary against hostile transport code.

Requests use canonical JSON. Responses reject duplicate keys, floats, non-finite
numbers, invalid UTF-8, unsupported integers, unknown fields and wrong media types.
Strict models and available semantic digest checks validate exact request/selection
bindings and reject contradictory reference-authority or outcome claims. These
checks do not authenticate a server or independently prove policy publication.

- ReferenceHttpError retains `status` and typed `body.error` with the server code,
  detail code, message and validation issues.
- ReferenceProtocolError retains `status` for malformed responses, redirects and
  unexpected statuses.
- ReferenceTransportError reports network/read failures and oversized response reads.
- Oversized requests raise ReferenceClientError before sending. Construction errors
  remain ValueError or Pydantic validation errors.

Catching an error grants no permission and triggers no retry. The reference
service remains stateless, with no production identity, tenant isolation, custom
publication or target enforcement. Receipt assessment is caller-report only and
non-durable. See [SECURITY.md](../SECURITY.md) for the current boundary.
