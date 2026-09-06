"""Generate the static Space from validated real reference API observations."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from dataclasses import asdict
from pathlib import Path

from controlspec_example import observe

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:18767")
    args = parser.parse_args()
    data = {
        "mode": "recorded_reference_outputs",
        "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "reference_time": "2026-08-20T12:00:00.000000Z",
        "external_actions_executed": False,
        "domains": [
            asdict(observe(domain, args.base_url)) for domain in ("personal", "smb")
        ],
    }
    wire = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace(
        "<", "\\u003c"
    )
    template = (ROOT / "demo/template.html").read_text(encoding="utf-8")
    assert template.count("__CONTROL_SPEC_DATA__") == 1
    output = template.replace("__CONTROL_SPEC_DATA__", wire)
    target = ROOT / "demo/space/index.html"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(output, encoding="utf-8", newline="\n")
    (ROOT / "demo/space/observations.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(
        json.dumps(
            {
                "scenarios": sum(len(d["scenarios"]) for d in data["domains"]),
                "index_sha256": hashlib.sha256(output.encode()).hexdigest(),
            }
        )
    )


if __name__ == "__main__":
    main()
