"""Additive ControlSpec v0 portable contracts and authoring helpers.

This package is a non-authoritative facade.  It does not participate in the
RiskSpec evaluator, lifecycle, execution gate, ledger, or API runtime.
"""

from assurance.controlspec.authoring import compile_yaml_control_pack, load_yaml_control_pack
from assurance.controlspec.canonical import (
    canonical_context_hash,
    canonical_object_bytes,
    canonical_object_digest,
    finalize_object,
    load_canonical_json_control_pack,
    verify_object_digest,
)
from assurance.controlspec.contracts import (
    ActionIntent,
    Actor,
    Approval,
    Control,
    ControlPack,
    Decision,
    Receipt,
    Resource,
    Route,
)
from assurance.controlspec.evaluator import ControlSpecEvaluator, EvaluationResult
from assurance.controlspec.facts import (
    EvaluationFacts,
    PublishedControlSnapshot,
    RecheckResult,
    TrustedExecutionObservation,
)
from assurance.controlspec.receipt import assess_receipt
from assurance.controlspec.recheck import recheck

__all__ = [
    "ActionIntent",
    "Actor",
    "Approval",
    "Control",
    "ControlPack",
    "ControlSpecEvaluator",
    "Decision",
    "EvaluationFacts",
    "EvaluationResult",
    "PublishedControlSnapshot",
    "Receipt",
    "RecheckResult",
    "Resource",
    "Route",
    "TrustedExecutionObservation",
    "assess_receipt",
    "canonical_context_hash",
    "canonical_object_bytes",
    "canonical_object_digest",
    "compile_yaml_control_pack",
    "finalize_object",
    "load_canonical_json_control_pack",
    "load_yaml_control_pack",
    "recheck",
    "verify_object_digest",
]
