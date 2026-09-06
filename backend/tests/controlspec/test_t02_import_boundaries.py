from __future__ import annotations

from pathlib import Path


def test_generic_controlspec_modules_have_no_riskspec_or_supplier_dependency() -> None:
    package = Path(__file__).parents[2] / "src" / "assurance" / "controlspec"
    generic = (
        "facts.py",
        "predicate.py",
        "selection.py",
        "requirements.py",
        "composition.py",
        "evaluator.py",
        "recheck.py",
        "receipt.py",
        "conformance.py",
    )
    forbidden = (
        "assurance.domain",
        "assurance.runtime",
        "controlspec.mapping",
        "supplier",
        "advance_supplier",
        "activate_supplier",
        "autonomous_supplier",
        "human_supplier_review",
    )
    for filename in generic:
        source = (package / filename).read_text(encoding="utf-8").lower()
        assert not any(token in source for token in forbidden), filename
