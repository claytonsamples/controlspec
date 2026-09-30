"""Observe the public recording through real TLS gRPC and a loopback HTTP target."""

import json
from typing import Any

import pytest
from scripts.build_openshell_demo import record


@pytest.fixture(scope="module")
def recording() -> dict[str, Any]:
    return record()


@pytest.mark.parametrize(
    "scene_id,count,reason",
    [
        ("allowed", 1, "target_receipt_verified"),
        ("approval", 1, "target_receipt_verified"),
        ("overspend", 0, "approval_required"),
        ("changed", 0, "action_changed"),
        ("self-approval", 0, "approval_required"),
        ("replay", 1, "action_already_reserved"),
        ("missing-proof", 1, "completion_unverified"),
        ("outage", 0, "grpc_unavailable"),
        ("direct", 0, "target_requires_ticket"),
    ],
)
def test_recorded_effect_and_reason(recording: Any, scene_id: str, count: int, reason: str) -> None:
    scene = next(scene for scene in recording["scenes"] if scene["id"] == scene_id)
    baseline, native, controlled = scene["lanes"]
    assert baseline["after"]["purchase_count"] == 1
    assert native["status"] == "not_run" and native["after"] is None
    assert controlled["after"]["purchase_count"] == count
    if scene_id == "outage":
        assert controlled["reason"] in {"grpc_unavailable", "grpc_deadline_exceeded"}
        assert controlled["evidence"]["forwarded"] is False
        assert controlled["evidence"]["reconciled"] is False
    else:
        assert controlled["reason"] == reason
    assert controlled["evidence"]["ledger_chain_valid"] is True


def test_recording_preserves_uncertainty_and_discloses_fixture(recording: Any) -> None:
    assert recording["runtime"]["status"] == "not_run"
    missing = next(s for s in recording["scenes"] if s["id"] == "missing-proof")["lanes"][2]
    assert missing["after"]["spent_minor"] == 4200
    assert missing["evidence"]["reconciled"] is False
    assert "fixture" in missing["evidence"]["supervisor"]
    wire = json.dumps(recording)
    assert "Bearer " not in wire and "PRIVATE KEY" not in wire
