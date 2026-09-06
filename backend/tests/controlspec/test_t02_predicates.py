from __future__ import annotations

import pytest

from assurance.controlspec.contracts import Predicate
from assurance.controlspec.predicate import (
    PointerError,
    PredicateResult,
    evaluate_predicate,
    evaluation_document,
    resolve_pointer,
)
from tests.controlspec.test_t02_facts import intent


def test_pointer_distinguishes_missing_from_null_and_decodes_escapes() -> None:
    document = evaluation_document(intent({"personal.null_value": None}))
    document["context"]["personal.a/b"] = 7
    assert resolve_pointer(document, "/context/personal.null_value")[1] is None
    assert resolve_pointer(document, "/context/personal.a~1b")[1] == 7
    assert resolve_pointer(document, "/context/personal.missing")[0].value == "missing"


@pytest.mark.parametrize("path", ["context/x", "/other/x", "/context/a~2b"])
def test_malformed_pointer_is_rejected(path: str) -> None:
    with pytest.raises(PointerError):
        resolve_pointer(evaluation_document(intent()), path)


def test_predicates_are_type_exact_and_missing_is_unknown() -> None:
    document = evaluation_document(intent({"personal.value": 1, "personal.flag": True}))
    assert (
        evaluate_predicate(
            Predicate(operator="eq", path="/context/personal.value", value=1), document
        )
        is PredicateResult.TRUE
    )
    assert (
        evaluate_predicate(
            Predicate(operator="eq", path="/context/personal.value", value=True), document
        )
        is PredicateResult.FALSE
    )
    assert (
        evaluate_predicate(
            Predicate(operator="lt", path="/context/personal.flag", value=2), document
        )
        is PredicateResult.UNKNOWN
    )
    assert (
        evaluate_predicate(Predicate(operator="eq", path="/context/missing", value=1), document)
        is PredicateResult.UNKNOWN
    )
    assert (
        evaluate_predicate(
            Predicate(operator="exists", path="/context/missing", expected=False), document
        )
        is PredicateResult.TRUE
    )
