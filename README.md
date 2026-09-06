# ControlSpec

**An experimental reference layer for agent decisions, binding rechecks, and outcome evidence.**

ControlSpec explores a portable contract between an agent's proposed action and
the controls that govern it: describe the actor, action, resource and context;
evaluate a specific control set; recheck the exact binding; assess what the
reported outcome actually proves.

The Python reference implementation demonstrates this across personal spending
and SMB sales. An enterprise supplier profile is optional. It runs deterministic
typed controls and exposes seven HTTP operations plus a typed Python client.

**This preview does not authorize or execute real actions.** It has no production
authentication, tenant isolation, custom policy publication, target enforcement,
or durable receipt storage. Reference `allow` results are not production permission.
Reported success is not verified execution evidence.

## Try it locally

You need Python 3.13 and [uv](https://docs.astral.sh/uv/getting-started/installation/).

```sh
git clone https://github.com/claytonsamples/controlspec.git
cd controlspec
uv sync --project backend --locked --extra dev
uv run --project backend --locked python -m uvicorn assurance.api.controlspec:create_default_controlspec_reference_app --factory --host 127.0.0.1 --port 8765
```

In another terminal, from the repository root:

```sh
uv run --project backend --locked python scripts/controlspec_example.py personal --base-url http://127.0.0.1:8765
uv run --project backend --locked python scripts/controlspec_example.py smb --base-url http://127.0.0.1:8765
```

These fixed simulations demonstrate spending thresholds, approval requirements,
sales constraints, changed bindings, and incomplete outcome evidence. They make
no purchases and send no messages. Add `--json` for the machine-readable results.
The local API documentation is at <http://127.0.0.1:8765/docs>.

To construct fresh inputs with the Python client:

```sh
uv run --project backend --locked python examples/controlspec/client_journey.py --base-url http://127.0.0.1:8765 --requested-at 2026-09-06T12:00:00.000000Z --idempotency-prefix my-simulation-001
```

That timestamp is explicit simulation reference time. Use your own canonical UTC
instant and idempotency identity for a new input. See the [Python client guide](docs/python-client.md)
for request construction, exact pack selection, transport limits and errors.

## What is here

- Portable typed contracts and [JSON schemas](specs/controlspec-v0.1/schemas).
- A deterministic evaluator with decisions, routes and exact binding rechecks.
- Immutable example catalogs for personal, SMB and optional enterprise scenarios.
- A stateless reference API and Python client with explicit non-authority flags.
- Receipt assessment that distinguishes caller reports from verified evidence.

The API supports `list/get packs`, `list/get controls`, `decide`, `recheck`, and
`assess receipt`. It has no catalog-write or action-execution endpoint. The supplied
example packs demonstrate behavior; they are not your organization's approved policy.

## Build with us

We are opening this preview to learn where a shared agent-control contract helps.
Try a domain, challenge an assumption, or propose a small reproducible example in
[GitHub Issues](https://github.com/claytonsamples/controlspec/issues).
Useful contributions include framework integration examples, clearer failure
cases, contract feedback, and adversarial tests.

Operational identity, human-controlled publication, durable evidence and enforced
target adapters are future work. Integration with an agent framework alone cannot
prevent bypass when the agent still has unrestricted target credentials.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and [SECURITY.md](SECURITY.md)
for reporting vulnerabilities. Licensed under [Apache License 2.0](LICENSE).
