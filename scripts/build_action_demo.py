"""Record real reference decisions and isolated fake-target effects for the action demo.

This is a simulation harness, not an execution adapter or runtime authority. Only
fixed reviewed fixtures are observed, via the unchanged loopback reference API.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, TypedDict

try:  # Both direct CLI and repository test imports.
    from .controlspec_example import (
        FOLDERS,
        INTENT_DIGESTS,
        ObservedRun,
        ScenarioObservation,
        asset,
        index,
        observe,
        require,
    )
except ImportError:
    from controlspec_example import (
        FOLDERS,
        INTENT_DIGESTS,
        ObservedRun,
        ScenarioObservation,
        asset,
        index,
        observe,
        require,
    )

ROOT = Path(__file__).resolve().parents[1]
REFERENCE_TIME = "2026-08-20T12:00:00.000000Z"


class TargetState(TypedDict):
    balance_minor_units: int
    quote_total_minor_units: int
    discount_basis_points: int


class Event(TypedDict):
    step: int
    kind: str
    message: str
    state: TargetState


class Lane(TypedDict):
    initial_state: TargetState
    final_state: TargetState
    intent: dict[str, Any]
    events: list[Event]
    mutated: bool
    target_evidence: list[dict[str, Any]]
    completion: str


@dataclass(frozen=True)
class SceneDefinition:
    id: str
    title: str
    description: str
    domain: str
    scenario_id: str
    changed: bool = False
    evidence_available: bool = True


SCENES = (
    SceneDefinition(
        "overspend",
        "The $142 purchase",
        "A purchase exceeds the example spending limit.",
        "personal",
        "groceries-142",
    ),
    SceneDefinition(
        "discount",
        "The 15% discount",
        "A sales agent proposes an offer needing approval.",
        "smb",
        "discount-15",
    ),
    SceneDefinition(
        "self-approval",
        "The agent approves itself",
        "The same proposed 15% offer includes direct self-approval.",
        "smb",
        "smb-discount-15-direct-self-approval",
    ),
    SceneDefinition(
        "changed-binding",
        "$42 becomes $43",
        "The exact action changes after its $42 decision. Reusing that decision fails.",
        "personal",
        "groceries-42",
        changed=True,
    ),
    SceneDefinition(
        "missing-proof",
        "Done is only a claim",
        "A fake purchase runs, but target evidence is withheld from both lanes.",
        "personal",
        "groceries-42",
        evidence_available=False,
    ),
    SceneDefinition(
        "allowed",
        "The $42 purchase proceeds",
        "An allowed, unchanged action reaches the fake target. Sandbox evidence is visible.",
        "personal",
        "groceries-42",
    ),
)


def initial_state() -> TargetState:
    """Invented demonstration balances; no customer data or real currency account."""
    return {
        "balance_minor_units": 50000,
        "quote_total_minor_units": 100000,
        "discount_basis_points": 0,
    }


def fake_target(intent: dict[str, Any], state: TargetState) -> TargetState:
    """Pure fake-target arithmetic; performs no I/O and evaluates no control rules."""
    result = state.copy()
    context = intent["context"]
    action = intent["action"]["domain_action"]
    if action == "personal.purchase":
        amount = context["personal.spending.total_minor_units"]
        require(type(amount) is int and amount >= 0, "invalid fake purchase amount")
        result["balance_minor_units"] -= amount
    elif action == "smb.sales.offer_discount":
        discount = context["smb.sales.discount_basis_points"]
        require(
            type(discount) is int and 0 <= discount <= 10000, "invalid fake discount"
        )
        result["discount_basis_points"] = discount
        result["quote_total_minor_units"] = (
            state["quote_total_minor_units"] * (10000 - discount) // 10000
        )
    else:
        raise ValueError("unsupported fake target action")
    return result


def simulate_lane(
    intent: dict[str, Any],
    observation: ScenarioObservation,
    *,
    controlled: bool,
    changed: bool = False,
    evidence_available: bool = True,
) -> Lane:
    """Apply validated observations to one isolated fake target, never a real action.

    An allow-with-conditions cannot execute here: this harness has no executor for
    such conditions. Reference receipt assessment always stays unverified, even
    when the separate fake target supplies sandbox evidence.
    """
    start = initial_state()
    state = start.copy()
    events: list[Event] = []

    def event(step: int, kind: str, message: str) -> None:
        events.append(
            {"step": step, "kind": kind, "message": message, "state": state.copy()}
        )

    event(
        0,
        "proposed",
        "Identical scripted intent received by an isolated fake target lane.",
    )
    if controlled:
        event(1, "decision", f"Real reference decision: {observation.verdict}.")
        binding = (
            observation.changed_recheck_valid if changed else observation.recheck_valid
        )
        expected_digest = (
            INTENT_DIGESTS["groceries-42-changed-intent"]
            if changed
            else observation.intent_digest
        )
        source_domain = next(
            (
                scene.domain
                for scene in SCENES
                if scene.scenario_id == observation.scenario_id
            ),
            None,
        )
        require(
            source_domain is not None, "observation is outside this fixed simulation"
        )
        expected_intent = (
            asset("personal", "requests/groceries-42-changed-intent.json")
            if changed
            else asset(source_domain, f"requests/{observation.scenario_id}.json")[
                "action_intent"
            ]
        )
        # A caller cannot retain a known digest while altering the target payload.
        # These are fixed fixtures validated by observe, not newly evaluated intents.
        binding_ok = (
            binding is True
            and intent.get("intent_digest") == expected_digest
            and intent == expected_intent
        )
        event(
            2,
            "recheck",
            f"Binding valid for proposed action: {str(binding_ok).lower()}.",
        )
        dispatch = (
            observation.verdict == "allow"
            and binding_ok
            and observation.route_kind == "continue"
            and observation.route_id == "continue"
        )
    else:
        event(
            1,
            "dispatch",
            "Comparison lane dispatches directly; this control layer is absent.",
        )
        event(2, "recheck", "No ControlSpec binding recheck in this comparison lane.")
        dispatch = True

    target_evidence: list[dict[str, Any]] = []
    if dispatch:
        state = fake_target(intent, state)
        event(3, "target", "Fake target changed. No external action occurred.")
        if evidence_available:
            target_evidence.append(
                {
                    "kind": "sandbox_target_event",
                    "scope": "fake_target_only",
                    "intent_digest": intent["intent_digest"],
                    "before": start.copy(),
                    "after": state.copy(),
                    "production_evidence": False,
                }
            )
    else:
        event(3, "target", "Dispatch held; fake target unchanged.")

    if controlled:
        completion = (
            "Sandbox action observed; reference completion remains unverified."
            if target_evidence
            else "Completion unverified; no sandbox target evidence received."
            if dispatch
            else "Action held; fake target unchanged."
        )
        event(
            4,
            "receipt",
            f"Reference receipt: {observation.receipt_status}; "
            f"verified evidence: {observation.verified_evidence_count}. "
            "Sandbox events do not upgrade this receipt.",
        )
    else:
        completion = (
            "Sandbox action observed."
            if target_evidence
            else "Caller reports done; target proof is absent."
        )
        event(4, "receipt", completion)
    return {
        "initial_state": start,
        "final_state": state,
        "intent": copy.deepcopy(intent),
        "events": events,
        "mutated": state != start,
        "target_evidence": target_evidence,
        "completion": completion,
    }


def build_scene(definition: SceneDefinition, run: ObservedRun) -> dict[str, Any]:
    require(run.domain == definition.domain, "observation domain mismatch")
    observation = next(
        row for row in run.scenarios if row.scenario_id == definition.scenario_id
    )
    scenario = next(
        row
        for row in index(definition.domain)["scenarios"]
        if row["id"] == definition.scenario_id
    )
    request = asset(definition.domain, scenario["request"])
    original = request["action_intent"]
    require(
        original["intent_digest"] == observation.intent_digest,
        "observation intent mismatch",
    )
    proposed = (
        asset(definition.domain, scenario["changed_intent"])
        if definition.changed
        else original
    )
    require(
        request["options"]["reference_time"] == REFERENCE_TIME, "reference time changed"
    )
    require(original["requested_at"] == REFERENCE_TIME, "request time changed")
    lanes = {
        name: simulate_lane(
            proposed,
            observation,
            controlled=controlled,
            changed=definition.changed,
            evidence_available=definition.evidence_available,
        )
        for name, controlled in (("without", False), ("controlled", True))
    }
    return {
        **asdict(definition),
        "observation": asdict(observation),
        "original_intent": original,
        "proposed_intent": proposed,
        "source": {
            "request": f"examples/controlspec/{FOLDERS[definition.domain]}/{scenario['request']}",
            "reference_test": scenario["source"],
            "selected_pack": request["selection"],
            "explanation_codes": scenario["expected"]["explanation_codes"],
            "explanation_basis": "reviewed fixture; observe validates exact API match",
        },
        "initial_state": initial_state(),
        "lanes": lanes,
    }


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def build_document(url: str, template: Path) -> dict[str, Any]:
    runs = {domain: observe(domain, url) for domain in ("personal", "smb")}
    source_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    return {
        "schema": "controlspec.action-demo.v1",
        "mode": "recorded_reference_outputs",
        "static": True,
        "non_authoritative": True,
        "may_authorize_external_effect": False,
        "external_actions_executed": False,
        "real_llm_run": False,
        "production_evidence": False,
        "reference_time": REFERENCE_TIME,
        "source_commit": source_commit,
        "provenance": {
            "harness_sha256": sha256(Path(__file__)),
            "template_sha256": sha256(template),
            "observer_sha256": sha256(ROOT / "scripts/controlspec_example.py"),
            "source_commit_note": "Base Git commit; explicit hashes identify demo working files.",
            "reference_inputs_sha256": {
                str(path.relative_to(ROOT)).replace("\\", "/"): sha256(path)
                for domain in ("personal", "smb")
                for path in sorted(
                    (ROOT / "examples/controlspec" / FOLDERS[domain]).rglob("*.json")
                )
            },
        },
        "scope": "Scripted intents; real reference decisions; simulated targets; recorded playback.",
        "domains": [asdict(run) for run in runs.values()],
        "scenes": [build_scene(scene, runs[scene.domain]) for scene in SCENES],
    }


def render_document(data: dict[str, Any], template: str) -> str:
    require(
        template.count("__ACTION_DATA__") == 1,
        "template must contain one data placeholder",
    )
    wire = json.dumps(data, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return template.replace("__ACTION_DATA__", wire.replace("<", "\\u003c"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:18767")
    args = parser.parse_args()
    template = ROOT / "demo/action-template.html"
    data = build_document(args.base_url, template)
    output = render_document(data, template.read_text(encoding="utf-8"))
    target = ROOT / "demo/space"
    target.mkdir(parents=True, exist_ok=True)
    (target / "action-demo.html").write_text(output, encoding="utf-8", newline="\n")
    (target / "action-traces.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        json.dumps(
            {
                "scenes": len(data["scenes"]),
                "html_sha256": sha256(target / "action-demo.html"),
            }
        )
    )


if __name__ == "__main__":
    main()
