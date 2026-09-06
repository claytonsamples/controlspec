from __future__ import annotations

import pytest

from assurance.controlspec.contracts import ControlStatus, Predicate
from assurance.controlspec.selection import SnapshotValidationError, select_controls
from tests.controlspec.test_t02_facts import control, intent, snapshot


def test_only_effective_published_controls_are_selected() -> None:
    draft = control(control_id="draft", status=ControlStatus.DRAFT)
    published = control(control_id="published")
    selected = select_controls(intent(), snapshot(draft, published))
    assert [item.control.control_id for item in selected] == ["published"]


def test_missing_context_applies_exact_unknown_failure() -> None:
    guarded = control(
        predicates=(
            Predicate(
                operator="lte",
                path="/context/personal.amount_minor",
                value=7500,
            ),
        )
    )
    selected = select_controls(intent({"personal.other": 1}), snapshot(guarded))
    assert selected[0].used_unknown_failure
    assert selected[0].outcome.verdict == "block"


def test_invalid_control_digest_rejects_complete_snapshot() -> None:
    valid = control()
    mutated = valid.model_copy(update={"description": "display only does not change digest"})
    assert select_controls(intent(), snapshot(mutated))
    semantic_mutation = valid.model_copy(update={"metadata": {"changed": True}})
    with pytest.raises(SnapshotValidationError, match="semantic digest"):
        select_controls(intent(), snapshot(semantic_mutation))
