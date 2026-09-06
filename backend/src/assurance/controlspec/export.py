"""Change-local candidate schema export; not part of the legacy schema bundle."""

from __future__ import annotations

import json
from pathlib import Path

from assurance.controlspec.contracts import PORTABLE_OBJECTS


def export_candidate_schemas(target: Path) -> tuple[Path, ...]:
    target.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for model in PORTABLE_OBJECTS:
        path = target / f"{model.__name__}.schema.json"
        path.write_text(
            json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        written.append(path)
    return tuple(written)
