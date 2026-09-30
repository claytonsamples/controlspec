"""Test fake-target mutation boundaries independently of presentation timers."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest
from scripts import build_action_demo as demo
from scripts.controlspec_example import ObservedRun, ScenarioObservation, asset

ROOT = Path(__file__).resolve().parents[3]


def recorded_run(domain: str) -> ObservedRun:
    document = json.loads((ROOT / "demo/space/observations.json").read_text(encoding="utf-8"))
    run = next(item for item in document["domains"] if item["domain"] == domain)
    return ObservedRun(
        **{
            **run,
            "scenarios": tuple(ScenarioObservation(**row) for row in run["scenarios"]),
        }
    )


def allowed_observation() -> ScenarioObservation:
    return recorded_run("personal").scenarios[0]


def purchase_intent() -> dict:
    return asset("personal", "requests/groceries-42.json")["action_intent"]


@pytest.mark.parametrize("definition", demo.SCENES, ids=lambda scene: scene.id)
def test_scene_pairs_share_intent_and_initial_state_but_separate_mutations(definition):
    scene = demo.build_scene(definition, recorded_run(definition.domain))
    direct = scene["lanes"]["without"]
    controlled = scene["lanes"]["controlled"]
    assert direct["intent"] == controlled["intent"] == scene["proposed_intent"]
    assert direct["initial_state"] == controlled["initial_state"] == scene["initial_state"]
    assert direct["mutated"] is True
    assert controlled["mutated"] is (definition.id in {"missing-proof", "allowed"})
    if not controlled["mutated"]:
        assert controlled["final_state"] == controlled["initial_state"]
        assert controlled["target_evidence"] == []
    direct["final_state"]["balance_minor_units"] = -123
    direct["intent"]["context"].clear()
    assert controlled["final_state"]["balance_minor_units"] >= 0
    assert controlled["intent"]["context"]


@pytest.mark.parametrize(
    "verdict", ["block", "require_approval", "allow_with_conditions", "unknown"]
)
def test_changed_observed_verdict_holds_target(verdict):
    observation = replace(allowed_observation(), verdict=verdict)
    lane = demo.simulate_lane(purchase_intent(), observation, controlled=True)
    assert lane["mutated"] is False
    assert lane["final_state"] == lane["initial_state"]


@pytest.mark.parametrize("binding", [False, None, 1, "true"])
def test_missing_invalid_or_nonboolean_recheck_cannot_dispatch(binding):
    observation = replace(allowed_observation(), recheck_valid=binding)
    assert not demo.simulate_lane(purchase_intent(), observation, controlled=True)["mutated"]


@pytest.mark.parametrize("change", [{"route_kind": "ask_user"}, {"route_id": "substituted"}])
def test_altered_observed_route_cannot_dispatch(change):
    observation = replace(allowed_observation(), **change)
    assert not demo.simulate_lane(purchase_intent(), observation, controlled=True)["mutated"]


def test_changed_action_reuses_only_changed_recheck_and_uses_real_43_dollar_fixture():
    observation = allowed_observation()
    intent = asset("personal", "requests/groceries-42-changed-intent.json")
    assert intent["context"]["personal.spending.total_minor_units"] == 4300
    assert observation.recheck_valid is True
    assert observation.changed_recheck_valid is False
    direct = demo.simulate_lane(intent, observation, controlled=False, changed=True)
    controlled = demo.simulate_lane(intent, observation, controlled=True, changed=True)
    assert direct["final_state"]["balance_minor_units"] == 45700
    assert controlled["final_state"]["balance_minor_units"] == 50000
    # Omitting the changed flag cannot disguise this new intent as the original.
    assert not demo.simulate_lane(intent, observation, controlled=True)["mutated"]


def test_missing_target_evidence_does_not_undo_action_or_create_verified_completion():
    observation = allowed_observation()
    intent = purchase_intent()
    present = demo.simulate_lane(intent, observation, controlled=True)
    missing = demo.simulate_lane(intent, observation, controlled=True, evidence_available=False)
    assert present["final_state"] == missing["final_state"]
    assert missing["final_state"]["balance_minor_units"] == 45800
    assert present["target_evidence"][0]["scope"] == "fake_target_only"
    assert present["target_evidence"][0]["production_evidence"] is False
    assert missing["target_evidence"] == []
    assert missing["completion"].startswith("Completion unverified")
    assert "reference completion remains unverified" in present["completion"]
    assert observation.receipt_status == "incomplete"
    assert observation.verified_evidence_count == 0


def test_payload_change_cannot_keep_digest_and_bypass_binding():
    intent = purchase_intent()
    intent["context"]["personal.spending.total_minor_units"] = 49000
    observation = allowed_observation()
    assert intent["intent_digest"] == observation.intent_digest
    assert not demo.simulate_lane(intent, observation, controlled=True)["mutated"]


def test_replay_inputs_and_returned_event_states_are_detached():
    intent = purchase_intent()
    before = copy.deepcopy(intent)
    first = demo.simulate_lane(intent, allowed_observation(), controlled=True)
    second = demo.simulate_lane(intent, allowed_observation(), controlled=True)
    assert first == second
    assert intent == before
    assert first["events"][0]["state"]["balance_minor_units"] == 50000
    assert first["events"][3]["state"]["balance_minor_units"] == 45800
    first["events"][3]["state"]["balance_minor_units"] = 0
    assert first["final_state"]["balance_minor_units"] == 45800
    assert second["events"][3]["state"]["balance_minor_units"] == 45800


def test_render_escapes_html_and_requires_exact_placeholder():
    assert demo.render_document({"label": "</script>"}, "__ACTION_DATA__") == (
        '{"label":"\\u003c/script>"}'
    )
    with pytest.raises(ValueError, match="one data placeholder"):
        demo.render_document({}, "__ACTION_DATA____ACTION_DATA__")


def test_generated_recording_is_reproducible_from_observations_and_source_hashes():
    data = json.loads((ROOT / "demo/space/action-traces.json").read_text(encoding="utf-8"))
    assert data["static"] is True and data["non_authoritative"] is True
    assert data["external_actions_executed"] is False
    assert data["may_authorize_external_effect"] is False
    assert data["real_llm_run"] is False and data["production_evidence"] is False
    assert data["reference_time"] == demo.REFERENCE_TIME
    provenance = data["provenance"]
    assert provenance["harness_sha256"] == demo.sha256(ROOT / "scripts/build_action_demo.py")
    assert provenance["template_sha256"] == demo.sha256(ROOT / "demo/action-template.html")
    assert provenance["observer_sha256"] == demo.sha256(ROOT / "scripts/controlspec_example.py")
    for path, digest in provenance["reference_inputs_sha256"].items():
        assert digest == demo.sha256(ROOT / path)
    runs = {
        run["domain"]: ObservedRun(
            **{
                **run,
                "scenarios": tuple(ScenarioObservation(**row) for row in run["scenarios"]),
            }
        )
        for run in data["domains"]
    }
    assert data["scenes"] == [demo.build_scene(scene, runs[scene.domain]) for scene in demo.SCENES]
    template = (ROOT / "demo/action-template.html").read_text(encoding="utf-8")
    assert (ROOT / "demo/space/action-demo.html").read_text(encoding="utf-8") == (
        demo.render_document(data, template)
    )
