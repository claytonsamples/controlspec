"""Keep the published static examples faithful to the reference observations."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_static_observations_match_reference_scenarios():
    data = json.loads((ROOT / "demo/space/observations.json").read_text(encoding="utf-8"))
    assert data["mode"] == "recorded_reference_outputs"
    assert data["external_actions_executed"] is False
    count = 0
    for domain in data["domains"]:
        folder = (
            "personal-agent-spending" if domain["domain"] == "personal" else "smb-sales-controls"
        )
        cases = json.loads((ROOT / f"examples/controlspec/{folder}/scenarios.json").read_text())
        expected = {row["id"]: row for row in cases["scenarios"]}
        assert len(domain["scenarios"]) == len(expected)
        for row in domain["scenarios"]:
            source = expected[row["scenario_id"]]
            assert row["verdict"] == source["expected"]["verdict"]
            assert row["receipt_status"] == source["expected"]["receipt_status"]
            assert row["recheck_valid"] is source["expected"]["recheck_valid"]
            assert row["changed_recheck_valid"] is source["changed_recheck_valid"]
            assert row["assessment_basis"] == "caller_report_only"
            assert row["verified_evidence_count"] == 0
            assert row["stored"] is False and row["durable"] is False
            assert row["route_substitution_rejected"] is True
            count += 1
    assert count == 7


def test_generated_page_embeds_exact_data_and_discloses_static_boundary():
    data = json.loads((ROOT / "demo/space/observations.json").read_text(encoding="utf-8"))
    wire = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")
    template = (ROOT / "demo/template.html").read_text(encoding="utf-8")
    page = (ROOT / "demo/space/index.html").read_text(encoding="utf-8")
    assert page == template.replace("__CONTROL_SPEC_DATA__", wire)
    assert "This static page does not evaluate new policies or execute actions." in page
    assert "recorded_reference_outputs" in page
    assert "fetch(" not in page and "XMLHttpRequest" not in page
    assert 'aria-live="polite"' in page
    assert "https://github.com/claytonsamples/controlspec" in page
