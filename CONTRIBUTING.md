# Contributing to ControlSpec

Thanks for trying this experimental reference implementation. Start with a small
issue or pull request describing the concrete problem, expected behavior, and a
reproducible example. Please identify which contract, scenario or code path is
affected and distinguish proposed behavior from behavior you observed.

## Local development

Use Python 3.13 and uv. From the repository root:

```sh
uv sync --project backend --locked --extra dev
cd backend
uv run --locked --extra dev python -m pytest tests -p no:cacheprovider
```

The lockfile is part of the reproducible environment. Dependency changes should
explain why they are needed and include the corresponding lockfile update.
Keep unrelated refactors out of a focused fix.

## Good first contributions

- A minimal example from another agent workflow, with explicit expected outcomes.
- Tests for missing context, changed bindings, conflicting controls or malformed responses.
- Improvements to setup instructions and error explanations.
- A proposed integration that states exactly which target operations it mediates.

Include relevant test commands and observed results with your pull request.
Executable behavior must remain deterministic and traceable to its contract or
explicitly documented decision. Do not quietly change sample policy semantics to
make a failing test pass. Proposals affecting publication, enforcement or authority
need explicit design discussion before implementation.

## Preserve the reference boundary

The current service is non-authoritative, stateless and local-reference oriented.
Do not treat an `allow` result as production permission, turn a simulated receipt
into proof of execution, introduce a hidden bypass, or add automatic retries for
potential external effects. New framework examples must explain their limits;
an agent-side wrapper alone cannot prevent direct target access.

Authentication, tenant isolation, human-owned policy publication, durable evidence,
and production target adapters are planned work, not capabilities supplied by this
preview. Discuss their contracts and failure handling before adding them.

Never include credentials, private organizational policies or personal data in
issues, fixtures, logs or pull requests. Use synthetic examples. For a suspected
vulnerability, follow [SECURITY.md](SECURITY.md).

Contributions are reviewed under the project's [Apache License 2.0](LICENSE).
