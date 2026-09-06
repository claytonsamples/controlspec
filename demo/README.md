# Static Hugging Face examples

Live: https://huggingface.co/spaces/claytonsamples/controlspec

The static Space displays seven recorded outputs from the real Python reference
API. The browser chooses among records; it contains no alternate evaluator and
does not authorize or execute actions. The changed-intent toggle shows the
recorded negative recheck for the $42 grocery case. All reference evaluations use
the explicit fixed time recorded in observations.json.

To regenerate, start the reference server on loopback port 18767, then run from
the repository root:

```sh
uv run --project backend --locked python scripts/build_static_demo.py
uv run --project backend --locked python -m pytest backend/tests/controlspec/test_static_demo.py
```

The generator runs the validated personal and SMB scenario journeys, records the
source commit and embeds the resulting data into template.html. Upload the three
files in space/ to the Hugging Face static Space root. No credentials belong in
this folder or the source repository.
