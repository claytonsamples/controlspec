# Side-by-side agent action lab

This candidate is a recorded sandbox simulation using the real ControlSpec
reference API. It is separate from the published Space home page.

## Reproduce

From the repository root, start the reference API:

```sh
uv run --project backend --locked python -m uvicorn assurance.api.controlspec:create_default_controlspec_reference_app --factory --host 127.0.0.1 --port 18767
```

Then generate the paired sandbox runs:

```sh
uv run --project backend --locked python scripts/build_action_demo.py --base-url http://127.0.0.1:18767
uv run --project backend --locked python -m pytest backend/tests/controlspec/test_action_demo.py -q
uv run --project backend --locked python -m http.server 18768 --bind 127.0.0.1 --directory demo/space
```

Open http://127.0.0.1:18768/action-demo.html. Run the comparison, pause, step,
reset, or select one of six scenes. The JSON trace downloads beside the page.
The HTML also works offline when opened directly; keep action-traces.json beside
it for the download link.

## What the comparison establishes

The Python harness feeds the same scripted proposal into two fake target paths.
One dispatches directly. The other permits a fake target mutation only when the
reference verdict and binding recheck satisfy the harness's conservative gate.
Missing approval, self-approval, and a changed purchase binding demonstrate
different outcomes without any real purchase or customer write.

The browser only replays generated data. It does not call an LLM, evaluate new
policies, or authorize actions. The missing-proof scene withholds sandbox target
evidence in both lanes; a caller success report remains unverified. Even a
permitted sandbox action does not turn the reference receipt into verified
production evidence. The source commit and working-file hashes identify the
recorded candidate; the commit alone does not imply the new files were committed.

This is not a benchmark against another product or a claim that other agents
lack protections. The baseline isolates this layer's contribution. Real target
credential isolation, identity, tenant boundaries, publication, and durable
assurance remain separate implementation work.
