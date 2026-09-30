"""Render recorded OpenShell runtime observations without creating new observations."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MARKER = "__RUNTIME_DATA__"


def build(input_path: Path, template_path: Path, output_path: Path) -> None:
    if output_path.resolve() in {input_path.resolve(), template_path.resolve()}:
        raise ValueError("Output must not overwrite the observations or template")
    report: Any = json.loads(input_path.read_text(encoding="utf-8"))
    if (
        not isinstance(report, dict)
        or report.get("schema_version") != "1"
        or report.get("execution_mode") != "actual_openshell"
        or report.get("synthetic_only") is not True
        or not isinstance(report.get("observations"), list)
        or not report["observations"]
        or any(not isinstance(item, dict) for item in report["observations"])
    ):
        raise ValueError("Expected a version 1 synthetic OpenShell runtime observation report")
    template = template_path.read_text(encoding="utf-8")
    if template.count(MARKER) != 1:
        raise ValueError("Template must contain exactly one runtime-data marker")
    embedded = (
        json.dumps(report, ensure_ascii=False, allow_nan=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(template.replace(MARKER, embedded), encoding="utf-8", newline="\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input", type=Path, default=ROOT / "demo/space/runtime-observations.json"
    )
    parser.add_argument("--template", type=Path, default=ROOT / "demo/runtime-template.html")
    parser.add_argument("--output", type=Path, default=ROOT / "demo/space/runtime.html")
    args = parser.parse_args()
    build(args.input, args.template, args.output)
    print(f"Rendered recorded observations: {args.output}")


if __name__ == "__main__":
    main()
