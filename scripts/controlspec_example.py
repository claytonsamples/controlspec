"""Fixed local ControlSpec examples; no actions, policy evaluation, SDK, or authority."""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
TIMEOUT_SECONDS = 5
MAX_BODY_BYTES = 1_048_576
REVISION = "a6d0c2685a62eb9e21eef49355ed20687bdf9563"
CATALOG = "sha256:07e00e11176752146d402c31269d3c89dbe1f8ae200c98a91f7e4f34f7888322"
FOLDERS = {
    "personal": "personal-agent-spending",
    "smb": "smb-sales-controls",
    "enterprise": "enterprise-supplier",
}
MATRIX = {
    "personal": {
        "groceries-42": "allow",
        "groceries-142": "require_approval",
        "recurring-999": "require_approval",
    },
    "smb": {
        "draft": "allow",
        "discount-8": "allow_with_conditions",
        "discount-15": "require_approval",
        "smb-discount-15-direct-self-approval": "block",
    },
    "enterprise": {
        "enterprise-routine-supplier-advance": "allow",
        "enterprise-high-risk-missing-approval": "require_approval",
        "enterprise-attempted-self-approval": "require_approval",
    },
}
AUTHORITY = {
    "authority_mode": "non_authoritative_reference",
    "durable": False,
    "may_authorize_external_effect": False,
    "production_publication": False,
}
BINDING_KEYS = {
    "catalog_digest",
    "selection_digest",
    "fact_fixture_digest",
    "facts_digest",
    "semantic_input_digest",
    "selected_catalog_ids",
}
SCENARIO_KEYS = {
    "id",
    "request",
    "source",
    "expected",
    "changed_intent",
    "changed_recheck_valid",
}
EXPECTED_KEYS = {
    "verdict",
    "explanation_codes",
    "catalog_binding",
    "recheck_valid",
    "receipt_status",
    "missing_evidence_requirement_ids",
}
DECIDE_KEYS = {
    "schema",
    "schema_version",
    "decision",
    "matched_controls",
    "trace",
    "catalog_binding",
    "authority",
    "time_source",
    "explanation_codes",
}
RECHECK_KEYS = {
    "schema",
    "schema_version",
    "recheck",
    "comparisons",
    "catalog_binding",
    "authority",
    "explanation_codes",
}
RECEIPT_KEYS = {
    "schema",
    "schema_version",
    "receipt",
    "stored",
    "durable",
    "assessment_basis",
    "catalog_binding",
    "authority",
    "explanation_codes",
}
SCHEMAS = {
    "Actor",
    "Resource",
    "ActionIntent",
    "Control",
    "ControlPack",
    "Route",
    "Decision",
    "Approval",
    "Receipt",
}

# Exact identities copied from already reviewed assets; never computed here.
INTENT_DIGESTS = {
    "groceries-42": "sha256:eae71621e734dcf7b654a778562900935637da3b62384ac8a06802ede2d1c16d",
    "groceries-42-changed-intent": (
        "sha256:251fff20bf91e75d47b48b2bdce71bb8e41d14f9d5eda519d06d035f694d8d89"
    ),
    "groceries-142": "sha256:5b0a007d31cec073c4a6c8731e192c15cc7de7e0a0c4d96b64d4b23210afd1c0",
    "recurring-999": "sha256:bc82299648aa586ad4cb8da960d413c5cfbeaca046e58912a359714b7d0ec801",
    "draft": "sha256:c97b00a3ce7f1e71a27f90bab783f4490f1fe09286f137abaa5cf2cf2882b64d",
    "discount-8": "sha256:be0d497159b6110a72d0a6bea0c2db21f82202f40e6217ef586ae1f51bbac7d0",
    "discount-15": "sha256:ec4f4dee20b67ee8dd0b264dcbf60f185eda92d48fa48bbf2ed54f0ff090e5d4",
    "enterprise-attempted-self-approval": (
        "sha256:237408eec9ae78a12be91744b44222ec63e06d143bac55d8ae66ba3e448a24f9"
    ),
    "enterprise-high-risk-missing-approval": (
        "sha256:9c1399fd44b88615eb557c951dd3eb0d9701d88abb8f68794f499d459114c63d"
    ),
    "enterprise-routine-supplier-advance": (
        "sha256:65a75921aceb82de4b1ff8e9daf68ca53d05a6bf0d10c6d7bde679340bc8c071"
    ),
    "restricted-data-without-review": (
        "sha256:aa9975ce5f949c6adff965ef6392c442da005378ce9eedad6fc7773771b3e656"
    ),
    "smb-discount-15-direct-self-approval": (
        "sha256:c28c5920136a243b8256f8baaa59709217a8f7043e95dcec06013aaee3d1bf1a"
    ),
}

# Presentation copy is closed and bound to the accepted scenario identities. It
# is never read from an HTTP response and never influences a request or result.
SCENARIO_LABELS = {
    "groceries-42": "shopping-agent proposes a $42 grocery purchase",
    "groceries-142": "shopping-agent proposes a $142 grocery purchase",
    "recurring-999": "shopping-agent proposes a recurring $9.99 purchase",
    "draft": "sales-agent proposes drafting a customer email",
    "discount-8": "sales-agent proposes an 8% customer discount",
    "discount-15": "sales-agent proposes a 15% customer discount",
    "smb-discount-15-direct-self-approval": (
        "sales-agent proposes a 15% discount with direct self-approval"
    ),
    "enterprise-attempted-self-approval": (
        "enterprise agent proposes supplier activation with attempted self-approval"
    ),
    "enterprise-high-risk-missing-approval": (
        "enterprise agent proposes high-risk supplier activation without valid approval"
    ),
    "enterprise-routine-supplier-advance": (
        "enterprise agent proposes routine supplier activation"
    ),
    "restricted-data-without-review": (
        "enterprise restricted-binding negative probe lacks exact review facts"
    ),
}
EXPECTED_ROUTES = {
    "groceries-42": ("continue", "continue"),
    "groceries-142": ("ask_user", "ask-before-purchase"),
    "recurring-999": ("ask_user", "ask-before-recurring-purchase"),
    "draft": ("continue", "continue-draft"),
    "discount-8": ("continue", "continue-within-limit"),
    "discount-15": ("continue", "continue"),
    "smb-discount-15-direct-self-approval": ("block", "fail-closed-block"),
    "enterprise-attempted-self-approval": ("continue", "riskspec-autonomous_supplier"),
    "enterprise-high-risk-missing-approval": ("continue", "riskspec-autonomous_supplier"),
    "enterprise-routine-supplier-advance": ("continue", "riskspec-autonomous_supplier"),
    "restricted-data-without-review": ("block", "fail-closed"),
}
DOMAIN_ORDER = {
    "personal": ("groceries-42", "groceries-142", "recurring-999"),
    "smb": ("draft", "discount-8", "discount-15", "smb-discount-15-direct-self-approval"),
    "enterprise": (
        "enterprise-attempted-self-approval",
        "enterprise-high-risk-missing-approval",
        "enterprise-routine-supplier-advance",
        "restricted-data-without-review",
    ),
}


@dataclass(frozen=True, slots=True)
class ScenarioObservation:
    """Already validated facts available to the terminal-only renderer."""

    scenario_id: str
    intent_digest: str
    pack_catalog_id: str
    verdict: str
    route_kind: str
    route_id: str
    recheck_valid: bool
    changed_recheck_valid: bool | None
    receipt_status: str
    missing_evidence_count: int
    verified_evidence_count: int
    assessment_basis: str
    stored: bool
    durable: bool
    route_substitution_rejected: bool


@dataclass(frozen=True, slots=True)
class ObservedRun:
    """Complete validated run; rendering occurs only after construction."""

    domain: str
    release_id: str
    catalog_digest: str
    scenarios: tuple[ScenarioObservation, ...]
    machine_summary: dict[str, Any]


class ExampleFailure(ValueError):
    """A transport, shape, provenance, or expected-result mismatch."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ExampleFailure(message)


def encoded(value: Any) -> bytes:
    """Transport JSON only: no semantic hashes, decisions, or fact construction."""
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()


def same(left: Any, right: Any) -> bool:
    # JSON comparison distinguishes booleans from integers; it is not a semantic digest.
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _reject_number(_: str) -> Any:
    raise ExampleFailure("non-integer JSON number")


def _integer(raw: str) -> int:
    number = int(raw)
    require(-(2**63) <= number < 2**63, "integer outside canonical range")
    return number


def strict_json(raw: bytes) -> Any:
    require(len(raw) <= MAX_BODY_BYTES, "JSON body too large")
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_float=_reject_number,
            parse_constant=_reject_number,
            parse_int=_integer,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ExampleFailure("invalid strict JSON") from exc


def object_keys(value: Any, keys: set[str]) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, "closed object shape mismatch")
    return dict(value)


def strings(value: Any) -> None:
    require(
        type(value) is list and all(type(item) is str for item in value), "string array expected"
    )


def digest(value: Any) -> None:
    require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        "full digest expected",
    )


def _shape(value: Any, schema: dict[str, Any], root: dict[str, Any], depth: int = 0) -> None:
    """Validate only the unchanged schema vocabulary used by the nine wire objects.

    No rule predicates/effects are executed. Unsupported validation keywords fail
    closed, so future schema expansion requires a separately reviewed distribution.
    """
    require(depth < 96, "wire object nesting too deep")
    allowed = {
        "$defs",
        "$ref",
        "type",
        "title",
        "default",
        "const",
        "enum",
        "properties",
        "required",
        "additionalProperties",
        "patternProperties",
        "items",
        "anyOf",
        "oneOf",
        "discriminator",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "minLength",
        "maxLength",
        "pattern",
    }
    require(set(schema) <= allowed, "unsupported stable wire schema keyword")
    if "$ref" in schema:
        ref = schema["$ref"]
        require(type(ref) is str and ref.startswith("#/$defs/"), "nonlocal schema reference")
        _shape(value, root["$defs"][ref.removeprefix("#/$defs/")], root, depth + 1)
        return
    for keyword in ("anyOf", "oneOf"):
        if keyword in schema:
            matches = 0
            for choice in schema[keyword]:
                try:
                    _shape(value, choice, root, depth + 1)
                    matches += 1
                except ExampleFailure:
                    pass
            require(matches == 1 if keyword == "oneOf" else matches > 0, "wire union mismatch")
    if "const" in schema:
        require(same(value, schema["const"]), "wire constant mismatch")
    if "enum" in schema:
        require(any(same(value, item) for item in schema["enum"]), "wire enum mismatch")
    kind = schema.get("type")
    types = {
        "object": dict,
        "array": list,
        "string": str,
        "integer": int,
        "boolean": bool,
        "null": type(None),
    }
    if kind is not None:
        require(kind in types and type(value) is types[kind], "wire scalar/container type mismatch")
    if type(value) is dict:
        properties = schema.get("properties", {})
        require(set(schema.get("required", [])) <= set(value), "wire required field missing")
        if schema.get("additionalProperties") is False:
            require(set(value) == set(properties), "complete closed wire fields required")
        for key, item in value.items():
            if key in properties:
                _shape(item, properties[key], root, depth + 1)
            else:
                matched = False
                for pattern, child in schema.get("patternProperties", {}).items():
                    if re.search(pattern, key):
                        _shape(item, child, root, depth + 1)
                        matched = True
                extra = schema.get("additionalProperties", True)
                if not matched and isinstance(extra, dict):
                    _shape(item, extra, root, depth + 1)
                elif not matched:
                    require(extra is not False, "unknown wire field")
    if type(value) is list and "items" in schema:
        for item in value:
            _shape(item, schema["items"], root, depth + 1)
    if type(value) is str:
        require(len(value) >= schema.get("minLength", 0), "wire string too short")
        require(len(value) <= schema.get("maxLength", MAX_BODY_BYTES), "wire string too long")
        if "pattern" in schema:
            require(re.search(schema["pattern"], value) is not None, "wire string pattern mismatch")
    if type(value) is int:
        require(value >= schema.get("minimum", -(2**63)), "wire integer below minimum")
        require(value <= schema.get("maximum", 2**63 - 1), "wire integer above maximum")
        if "exclusiveMinimum" in schema:
            require(value > schema["exclusiveMinimum"], "wire integer below exclusive minimum")


def wire(value: Any, name: str, definition: str | None = None) -> None:
    require(name in SCHEMAS, "unrecognized wire schema")
    root = strict_json((ROOT / f"specs/controlspec-v0.1/schemas/{name}.schema.json").read_bytes())
    schema = root if definition is None else root["$defs"][definition]
    _shape(value, schema, root)


def base_url(value: str) -> str:
    require(
        type(value) is str
        and not any(ch.isspace() or ord(ch) < 32 for ch in value)
        and "\\" not in value
        and "%" not in value,
        "invalid base URL characters",
    )
    try:
        parsed = urlsplit(value)
        require(
            parsed.scheme == "http"
            and parsed.path == ""
            and not parsed.query
            and not parsed.fragment
            and parsed.username is None
            and parsed.password is None,
            "base URL must be plain loopback HTTP without path or credentials",
        )
        if parsed.hostname is None:
            raise ExampleFailure("literal loopback host required")
        address = ipaddress.ip_address(parsed.hostname)
        require(address.is_loopback, "non-loopback URL rejected")
        require(parsed.port is not None and 1 <= parsed.port <= 65535, "explicit port required")
    except ValueError as exc:
        raise ExampleFailure("invalid literal loopback base URL") from exc
    return value


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def request_json(
    url: str, operation: str, body: Any = None, expected_status: int = 200
) -> tuple[Any, bytes]:
    safe_base = base_url(url)
    require(
        re.fullmatch(
            r"(?:packs|controls)(?:/[A-Za-z0-9%._~-]+)?|decide|recheck|receipts", operation
        )
        is not None,
        "non-fixed API path",
    )
    data = None if body is None else encoded(body)
    require(data is None or len(data) <= MAX_BODY_BYTES, "request body too large")
    request = Request(
        safe_base + "/controlspec/v0/" + operation,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="GET" if body is None else "POST",
    )
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        try:
            response = opener.open(request, timeout=TIMEOUT_SECONDS)
        except HTTPError as error:
            response = error
        with response:
            require(response.status == expected_status, f"unexpected HTTP status {response.status}")
            require(response.headers.get_content_type() == "application/json", "non-JSON response")
            raw = response.read(MAX_BODY_BYTES + 1)
        return strict_json(raw), raw
    except (OSError, URLError, TimeoutError) as exc:
        raise ExampleFailure("loopback HTTP request failed or timed out") from exc


def reference_authority(value: Any) -> None:
    require(same(value, AUTHORITY), "reference authority envelope changed")


def binding(value: Any, expected: Any | None = None) -> None:
    fields = object_keys(value, BINDING_KEYS)
    for name in BINDING_KEYS - {"selected_catalog_ids"}:
        digest(fields[name])
    strings(fields["selected_catalog_ids"])
    require(fields["catalog_digest"] == CATALOG, "catalog release changed")
    if expected is not None:
        require(same(fields, expected), "exact catalog/fact/semantic binding changed")


def envelope(value: Any, keys: set[str], name: str, expected_binding: Any) -> None:
    fields = object_keys(value, keys)
    require(fields["schema"] == f"controlspec/api/v0/{name}", "response schema changed")
    require(fields["schema_version"] == "0.1.0", "wire version changed")
    reference_authority(fields["authority"])
    binding(fields["catalog_binding"], expected_binding)
    strings(fields["explanation_codes"])


def summary(value: Any, kind: str, profile_kind: str | None = None) -> None:
    fields = object_keys(
        value,
        {
            "catalog_id",
            "namespace",
            f"{kind}_id",
            "version",
            "semantic_digest",
            "status",
            "title",
            "metadata",
        },
    )
    for key in set(fields) - {"metadata"}:
        require(type(fields[key]) is str, "catalog summary string expected")
    require(
        fields["catalog_id"]
        == (f"{fields['namespace']}:{fields[f'{kind}_id']}@{fields['version']}"),
        "catalog ID mismatch",
    )
    digest(fields["semantic_digest"])
    metadata = object_keys(
        fields["metadata"],
        {
            "example_only",
            "non_authoritative",
            "reference_evaluation_enabled",
            "profile_kind",
            "source",
        },
    )
    require(
        metadata["example_only"] is True and metadata["non_authoritative"] is True,
        "catalog authority changed",
    )
    require(type(metadata["reference_evaluation_enabled"]) is bool, "invalid enabled flag")
    require(
        metadata["profile_kind"] in {"portable_core", "riskspec_enterprise"}, "unknown profile kind"
    )
    require(type(metadata["source"]) is str and bool(metadata["source"]), "source missing")
    if profile_kind is not None:
        require(metadata["profile_kind"] == profile_kind, "profile boundary crossed")


def asset(domain: str, relative: str) -> Any:
    require(domain in FOLDERS, "unknown example domain")
    require(
        re.fullmatch(r"requests/[a-z0-9-]+\.json", relative) is not None,
        "fixed asset path required",
    )
    folder = ROOT / "examples/controlspec" / FOLDERS[domain]
    path = (folder / relative).resolve()
    require(
        path.is_relative_to(folder.resolve()) and path.is_relative_to(ROOT.resolve()),
        "asset escaped domain",
    )
    return strict_json(path.read_bytes())


def index(domain: str) -> dict[str, Any]:
    require(domain in FOLDERS, "unknown example domain")
    path = ROOT / "examples/controlspec" / FOLDERS[domain] / "scenarios.json"
    document = object_keys(
        strict_json(path.read_bytes()),
        {
            "schema",
            "domain",
            "release_id",
            "source_revision",
            "catalog_digest",
            "scenarios",
            "probes",
        },
    )
    require(
        document["schema"] == "controlspec/distribution/v1/scenarios"
        and document["domain"] == domain
        and document["release_id"] == "v0.1.1"
        and document["source_revision"] == REVISION
        and document["catalog_digest"] == CATALOG,
        "scenario source identity changed",
    )
    require(
        type(document["scenarios"]) is list and type(document["probes"]) is list,
        "scenario arrays required",
    )
    require(len(document["scenarios"]) == len(MATRIX[domain]), "scenario count changed")
    require(
        {row["id"]: row["expected"]["verdict"] for row in document["scenarios"]} == MATRIX[domain],
        "fixed scenario matrix changed",
    )
    expected_probes = ["restricted-data-without-review"] if domain == "enterprise" else []
    require([row["id"] for row in document["probes"]] == expected_probes, "probe inventory changed")
    for row in document["scenarios"] + document["probes"]:
        fields = object_keys(row, SCENARIO_KEYS)
        require(fields["request"] == f"requests/{fields['id']}.json", "scenario path changed")
        source = object_keys(fields["source"], {"path", "symbol", "revision"})
        require(source["revision"] == REVISION, "source revision changed")
        require(
            type(source["path"]) is str and type(source["symbol"]) is str, "source strings needed"
        )
        expected = object_keys(fields["expected"], EXPECTED_KEYS)
        binding(expected["catalog_binding"])
        strings(expected["explanation_codes"])
        strings(expected["missing_evidence_requirement_ids"])
        require(
            expected["receipt_status"] in {"incomplete", "failed"}, "complete receipt forbidden"
        )
        require(expected["recheck_valid"] is True, "unchanged recheck expectation changed")
        if fields["id"] == "groceries-42":
            require(
                fields["changed_intent"] == "requests/groceries-42-changed-intent.json"
                and fields["changed_recheck_valid"] is False,
                "changed binding probe changed",
            )
        else:
            require(
                fields["changed_intent"] is None and fields["changed_recheck_valid"] is None,
                "unapproved changed intent",
            )
    return document


def validate_decide(value: Any, payload: Any, expected: Any) -> None:
    envelope(value, DECIDE_KEYS, "decide-response", expected["catalog_binding"])
    decision = value["decision"]
    wire(decision, "Decision")
    require(decision["verdict"] == expected["verdict"], "unexpected decision verdict")
    require(
        value["explanation_codes"] == expected["explanation_codes"], "explanation codes changed"
    )
    require(
        decision["explanation_codes"] == value["explanation_codes"], "decision explanations differ"
    )
    require(value["time_source"] == "caller_reference", "fixed reference time lost")
    intent = payload["action_intent"]
    require(decision["namespace"] == intent["namespace"], "decision namespace changed")
    require(
        same(
            decision["intent_ref"],
            {
                "namespace": intent["namespace"],
                "intent_id": intent["intent_id"],
                "intent_digest": intent["intent_digest"],
            },
        ),
        "decision intent binding changed",
    )
    require(
        decision["binding"]["intent_digest"] == intent["intent_digest"]
        and decision["binding"]["context_digest"] == intent["context_digest"],
        "decision context binding changed",
    )
    require(
        same(
            decision["binding"]["actor_ref"],
            {key: intent["actor"][key] for key in ("namespace", "actor_id", "version")},
        ),
        "decision actor binding changed",
    )
    require(
        same(
            decision["binding"]["resource_ref"],
            {
                key: intent["resource"][key]
                for key in ("namespace", "resource_id", "version", "type")
            },
        ),
        "decision resource binding changed",
    )
    require(
        decision["binding"]["domain_action"] == intent["action"]["domain_action"]
        and decision["binding"]["action_type"] == intent["action"]["type"],
        "decision action binding changed",
    )
    require(
        decision["evaluated_at"] == payload["options"]["reference_time"],
        "decision reference time changed",
    )
    require(type(value["matched_controls"]) is list, "matched controls array expected")
    for control in value["matched_controls"]:
        wire(control, "Decision", "ControlRef")
    require(same(value["matched_controls"], decision["applied_controls"]), "control trace mismatch")
    trace = object_keys(
        value["trace"],
        {
            "snapshot_digest",
            "facts_digest",
            "evaluated_controls",
            "final_verdict",
            "final_route",
            "explanation_codes",
        },
    )
    digest(trace["snapshot_digest"])
    require(
        trace["facts_digest"] == expected["catalog_binding"]["facts_digest"], "trace facts changed"
    )
    require(
        trace["final_verdict"] == decision["verdict"]
        and same(trace["final_route"], decision["route"])
        and trace["explanation_codes"] == value["explanation_codes"],
        "trace outcome changed",
    )
    require(type(trace["evaluated_controls"]) is list, "trace controls array expected")
    for item in trace["evaluated_controls"]:
        object_keys(item, {"control_ref", "selection", "predicate_results", "emitted_code"})
        wire(item["control_ref"], "Decision", "ControlRef")
        require(item["selection"] in {"effect", "unknown_failure"}, "trace selection changed")
        strings(item["predicate_results"])
        require(
            all(result in {"true", "false", "unknown"} for result in item["predicate_results"]),
            "predicate observation invalid",
        )
        require(type(item["emitted_code"]) is str, "trace code string expected")


def decision_ref(decision: Any) -> dict[str, Any]:
    # Copy actual returned identity; no digest or Decision is synthesized.
    return {key: decision[key] for key in ("namespace", "decision_id", "semantic_digest")}


def validate_recheck(value: Any, decided: Any, expected: Any, changed: bool = False) -> None:
    envelope(
        value, RECHECK_KEYS, "recheck-response", None if changed else expected["catalog_binding"]
    )
    checked = object_keys(
        value["recheck"],
        {
            "valid",
            "prior_decision_ref",
            "reason_code",
            "current_decision_ref",
        },
    )
    require(
        checked["valid"] is (False if changed else expected["recheck_valid"]),
        "unexpected recheck validity",
    )
    require(same(checked["prior_decision_ref"], decision_ref(decided)), "prior decision changed")
    require(type(checked["reason_code"]) is str, "recheck code missing")
    if checked["current_decision_ref"] is not None:
        wire(checked["current_decision_ref"], "Decision", "DecisionRef")
    comparisons = object_keys(
        value["comparisons"],
        {
            "actor",
            "action",
            "resource",
            "context",
            "controls",
            "decision_window",
        },
    )
    require(
        all(item in {"same", "changed", "invalid"} for item in comparisons.values()),
        "invalid comparison status",
    )
    if changed:
        require(comparisons["context"] == "changed", "changed context not detected")
    else:
        require(all(item == "same" for item in comparisons.values()), "unchanged binding differed")
        require(
            same(checked["current_decision_ref"], decision_ref(decided)),
            "unchanged recheck current identity changed",
        )


def validate_receipt(value: Any, decided: Any, expected: Any, substituted: bool = False) -> None:
    envelope(value, RECEIPT_KEYS, "receipt-assessment-response", expected["catalog_binding"])
    require(
        value["stored"] is False
        and value["durable"] is False
        and value["assessment_basis"] == "caller_report_only",
        "receipt gained authority",
    )
    receipt = value["receipt"]
    wire(receipt, "Receipt")
    require(receipt["status"] in {"incomplete", "failed"}, "successful assurance forbidden")
    require(
        receipt["execution_outcome"] == "not_executed" and receipt["verified_evidence_refs"] == [],
        "caller claims became verified execution",
    )
    require(
        same(receipt["decision_ref"], decision_ref(decided)), "receipt decision binding changed"
    )
    require(same(receipt["intent_ref"], decided["intent_ref"]), "receipt intent binding changed")
    require(
        "controlspec.reference.execution_unverified" in value["explanation_codes"],
        "unverified execution warning missing",
    )
    if substituted:
        require(
            "controlspec.reference.route_mismatch" in value["explanation_codes"],
            "caller route substitution not rejected",
        )
    else:
        require(receipt["status"] == expected["receipt_status"], "receipt result changed")
        require(
            receipt["missing_evidence_requirement_ids"]
            == (expected["missing_evidence_requirement_ids"]),
            "missing evidence changed",
        )
        require(same(receipt["actual_route"], decided["route"]), "receipt route changed")


def observe(domain: str, url: str) -> ObservedRun:
    """Perform the unchanged fixed journey and return only after every check passes."""
    document = index(domain)
    base_url(url)
    packs, _ = request_json(url, "packs")
    controls, _ = request_json(url, "controls")
    for listing, kind in ((packs, "pack"), (controls, "control")):
        object_keys(listing, {"items", "catalog_digest", "authority"})
        reference_authority(listing["authority"])
        require(
            listing["catalog_digest"] == CATALOG and type(listing["items"]) is list,
            "catalog list identity changed",
        )
        for item in listing["items"]:
            summary(item, kind)
    observed: list[dict[str, Any]] = []
    scenario_observations: list[ScenarioObservation] = []
    for row in document["scenarios"] + document["probes"]:
        payload = object_keys(
            asset(domain, row["request"]),
            {
                "schema",
                "schema_version",
                "action_intent",
                "selection",
                "options",
            },
        )
        require(
            payload["schema"] == "controlspec/api/v0/decide-request"
            and payload["schema_version"] == "0.1.0",
            "request schema changed",
        )
        wire(payload["action_intent"], "ActionIntent")
        require(
            payload["action_intent"]["intent_digest"] == INTENT_DIGESTS[row["id"]],
            "fixed intent identity changed",
        )
        object_keys(payload["options"], {"include_trace", "reference_time"})
        require(
            payload["options"]["include_trace"] is True
            and payload["options"]["reference_time"] == "2026-08-20T12:00:00.000000Z",
            "fixed options changed",
        )
        selected = object_keys(payload["selection"], {"kind", "catalog_id", "semantic_digest"})
        require(selected["kind"] == "pack", "non-pack selection")
        digest(selected["semantic_digest"])
        candidates = [
            item for item in packs["items"] if item["catalog_id"] == selected["catalog_id"]
        ]
        require(len(candidates) == 1, "exact selected pack absent or ambiguous")
        pack_summary = candidates[0]
        profile = "riskspec_enterprise" if domain == "enterprise" else "portable_core"
        summary(pack_summary, "pack", profile)
        require(
            pack_summary["semantic_digest"] == selected["semantic_digest"], "pack digest changed"
        )
        require(
            pack_summary["namespace"] == payload["action_intent"]["namespace"],
            "request crossed profile namespace",
        )
        require(
            pack_summary["status"] == "published"
            and pack_summary["metadata"]["reference_evaluation_enabled"] is True,
            "reference pack is not enabled and published",
        )
        detail, _ = request_json(url, "packs/" + quote(selected["catalog_id"], safe=""))
        object_keys(
            detail, {"pack", "summary", "control_catalog_ids", "catalog_digest", "authority"}
        )
        reference_authority(detail["authority"])
        require(
            detail["catalog_digest"] == CATALOG and same(detail["summary"], pack_summary),
            "pack detail identity changed",
        )
        wire(detail["pack"], "ControlPack")
        strings(detail["control_catalog_ids"])
        require(bool(detail["control_catalog_ids"]), "pack contains no controls")
        require(
            detail["pack"]["semantic_digest"] == selected["semantic_digest"], "pack object changed"
        )
        control_id = detail["control_catalog_ids"][0]
        matching_controls = [item for item in controls["items"] if item["catalog_id"] == control_id]
        require(len(matching_controls) == 1, "selected control absent")
        control_detail, _ = request_json(url, "controls/" + quote(control_id, safe=""))
        object_keys(
            control_detail,
            {
                "control",
                "summary",
                "containing_pack_catalog_ids",
                "catalog_digest",
                "authority",
            },
        )
        reference_authority(control_detail["authority"])
        require(
            control_detail["catalog_digest"] == CATALOG
            and same(control_detail["summary"], matching_controls[0]),
            "control identity changed",
        )
        strings(control_detail["containing_pack_catalog_ids"])
        require(
            selected["catalog_id"] in control_detail["containing_pack_catalog_ids"],
            "control/pack membership changed",
        )
        wire(control_detail["control"], "Control")
        decided, first = request_json(url, "decide", payload)
        validate_decide(decided, payload, row["expected"])
        expected_route = EXPECTED_ROUTES[row["id"]]
        require(
            (
                decided["decision"]["route"]["kind"],
                decided["decision"]["route"]["route_id"],
            )
            == expected_route,
            "fixed route changed",
        )
        repeated, second = request_json(url, "decide", payload)
        validate_decide(repeated, payload, row["expected"])
        require(first == second, "fixed request response is not byte-identical")
        check_body = {
            "schema": "controlspec/api/v0/recheck-request",
            "schema_version": "0.1.0",
            "original_action_intent": payload["action_intent"],
            "prior_decision": decided["decision"],
            "current_action_intent": payload["action_intent"],
            "selection": payload["selection"],
            "options": payload["options"],
        }
        checked, _ = request_json(url, "recheck", check_body)
        validate_recheck(checked, decided["decision"], row["expected"])
        changed_valid: bool | None = None
        if row["changed_intent"] is not None:
            changed_body = {
                **check_body,
                "current_action_intent": asset(domain, row["changed_intent"]),
            }
            wire(changed_body["current_action_intent"], "ActionIntent")
            require(
                changed_body["current_action_intent"]["intent_digest"]
                == INTENT_DIGESTS["groceries-42-changed-intent"],
                "changed-context probe identity changed",
            )
            changed, _ = request_json(url, "recheck", changed_body)
            validate_recheck(changed, decided["decision"], row["expected"], changed=True)
            changed_valid = changed["recheck"]["valid"]
        receipt_body = {
            "schema": "controlspec/api/v0/receipt-assessment-request",
            "schema_version": "0.1.0",
            "action_intent": payload["action_intent"],
            "decision": decided["decision"],
            "selection": payload["selection"],
            "reported_execution": {
                "actual_route": decided["decision"]["route"],
                "execution_result": payload["action_intent"]["namespace"]
                + ".execution.reported_success",
                "evidence_refs": [],
                "business_outcome": None,
                "occurred_at": payload["options"]["reference_time"],
            },
            "options": {"reference_time": payload["options"]["reference_time"]},
        }
        assessed, _ = request_json(url, "receipts", receipt_body)
        validate_receipt(assessed, decided["decision"], row["expected"])
        # Deliberately false caller report only. No action is taken and no Decision
        # is changed; this negative probe must never become a selected execution route.
        substituted = copy.deepcopy(receipt_body)
        substituted["reported_execution"]["actual_route"] = {
            **decided["decision"]["route"],
            "route_id": "caller-substitution",
        }
        mismatch, _ = request_json(url, "receipts", substituted)
        validate_receipt(mismatch, decided["decision"], row["expected"], substituted=True)
        observed.append(
            {
                "id": row["id"],
                "verdict": decided["decision"]["verdict"],
                "recheck_valid": checked["recheck"]["valid"],
                "receipt_status": assessed["receipt"]["status"],
                "non_authoritative": True,
                "deterministic_repeat": True,
                "route_substitution_rejected": True,
            }
        )
        scenario_observations.append(
            ScenarioObservation(
                scenario_id=row["id"],
                intent_digest=payload["action_intent"]["intent_digest"],
                pack_catalog_id=selected["catalog_id"],
                verdict=decided["decision"]["verdict"],
                route_kind=decided["decision"]["route"]["kind"],
                route_id=decided["decision"]["route"]["route_id"],
                recheck_valid=checked["recheck"]["valid"],
                changed_recheck_valid=changed_valid,
                receipt_status=assessed["receipt"]["status"],
                missing_evidence_count=len(
                    assessed["receipt"]["missing_evidence_requirement_ids"]
                ),
                verified_evidence_count=len(assessed["receipt"]["verified_evidence_refs"]),
                assessment_basis=assessed["assessment_basis"],
                stored=assessed["stored"],
                durable=assessed["durable"],
                route_substitution_rejected=True,
            )
        )
    machine_summary = {
        "status": "ok",
        "scope": "local_reference_examples",
        "domain": domain,
        "release_id": "v0.1.1",
        "catalog_digest": CATALOG,
        "observed": observed,
        "scenario_count": len(document["scenarios"]),
        "probe_count": len(document["probes"]),
        "operations": [
            "GET packs",
            "GET packs/{id}",
            "GET controls",
            "GET controls/{id}",
            "POST decide",
            "POST recheck",
            "POST receipts",
        ],
        "external_actions_executed": False,
        "receipts_stored": False,
    }
    return ObservedRun(
        domain=domain,
        release_id=document["release_id"],
        catalog_digest=document["catalog_digest"],
        scenarios=tuple(scenario_observations),
        machine_summary=machine_summary,
    )


def run(domain: str, url: str) -> dict[str, Any]:
    """Compatibility facade returning the exact Change 0006 machine summary."""
    return observe(domain, url).machine_summary


def render_json(observed: ObservedRun) -> str:
    """Project a completed run to the exact legacy JSON record."""
    return json.dumps(observed.machine_summary, sort_keys=True)


def _scenario_note(scenario_id: str) -> str:
    notes = {
        "groceries-42": "the selected personal ControlPack permits groceries under $75",
        "smb-discount-15-direct-self-approval": (
            "direct self-approval fails independence and the result is block"
        ),
        "enterprise-attempted-self-approval": (
            "attempted self-approval is rejected; independent approval remains unsatisfied"
        ),
        "enterprise-high-risk-missing-approval": (
            "valid independent approval is missing, so approval remains required"
        ),
        "restricted-data-without-review": (
            "the exact profile facts are unavailable, so the probe fails closed"
        ),
    }
    return notes.get(scenario_id, "the accepted fixed example produced this result")


def _boolean(value: bool) -> str:
    require(type(value) is bool, "boolean observation expected")
    return "true" if value else "false"


def render_human(observed: ObservedRun) -> str:
    """Render fixed ASCII copy from a fully validated observation; perform no I/O."""
    require(observed.domain in FOLDERS, "unknown observed domain")
    require(
        tuple(item.scenario_id for item in observed.scenarios)
        == DOMAIN_ORDER[observed.domain],
        "observed scenario order changed",
    )
    packs = tuple(dict.fromkeys(item.pack_catalog_id for item in observed.scenarios))
    domain_boundary = (
        "Portable ControlSpec example: no optional enterprise profile is used."
        if observed.domain in {"personal", "smb"}
        else (
            "Optional enterprise profile / RiskSpec-authored supplier example: "
            "riskspec.enterprise.* is namespaced, riskspec_enterprise, profile-bound, "
            "and non-widening; supplier is not a ControlSpec primitive."
        )
    )
    lines = [
        "ControlSpec local reference journey",
        (
            "ControlSpec externalizes deterministic controls from prompts and is called "
            "before an agent acts."
        ),
        (
            "ControlPack: one exact, immutable version of controls selected for an "
            "intended action; "
            "selecting this reference pack grants no authority."
        ),
        "Loop: ActionIntent -> Decision -> Recheck -> Execution boundary -> Receipt Assessment",
        f"Reference release: {observed.release_id}",
        f"Catalog digest: {observed.catalog_digest}",
        "Selected pack(s): " + ", ".join(packs),
        domain_boundary,
        (
            "Boundary: fixed-time local non-authoritative reference; no external action, "
            "production permission, persistence, or certification."
        ),
        "",
    ]
    for number, item in enumerate(observed.scenarios, start=1):
        require(
            item.verdict == MATRIX[observed.domain].get(item.scenario_id, "block"),
            "verdict changed",
        )
        require(
            (item.route_kind, item.route_id) == EXPECTED_ROUTES[item.scenario_id],
            "route changed",
        )
        require(item.assessment_basis == "caller_report_only", "assessment basis changed")
        require(item.stored is False and item.durable is False, "receipt storage changed")
        require(item.verified_evidence_count == 0, "verified evidence changed")
        lines.extend(
            [
                f"Scenario {number}: {SCENARIO_LABELS[item.scenario_id]} [{item.scenario_id}]",
                f"  Intent: proposed and bound as {item.intent_digest}.",
                (
                    f"  Decision observed: verdict={item.verdict}; "
                    f"route={item.route_kind}/{item.route_id}; {_scenario_note(item.scenario_id)}. "
                    "Reference result only; not production permission."
                ),
                (
                    f"  Binding recheck: valid={_boolean(item.recheck_valid)}; actor, action, "
                    "resource, context, controls, and decision window remain unchanged."
                ),
            ]
        )
        if item.changed_recheck_valid is not None:
            lines.append(
                f"  Changed-intent check: valid={_boolean(item.changed_recheck_valid)}; "
                "changed amount or context invalidates the prior binding."
            )
        lines.extend(
            [
                (
                    "  Simulated caller report: caller reports success; this is untrusted "
                    "and no action occurred."
                ),
                (
                    f"  Receipt assessment: status={item.receipt_status}; "
                    f"missing_evidence={item.missing_evidence_count}; "
                    f"verified_evidence={item.verified_evidence_count}; "
                    f"basis={item.assessment_basis}; stored={_boolean(item.stored)}; "
                    f"durable={_boolean(item.durable)}."
                ),
                (
                    "  Route-substitution check: "
                    f"rejected={_boolean(item.route_substitution_rejected)} by assessment; "
                    "it creates no alternate permission."
                ),
                "",
            ]
        )
    lines.extend(
        [
            (
                "The caller reported success. ControlSpec did not verify execution. "
                "Missing evidence "
                "cannot complete assurance. This local reference stores nothing."
            ),
            (
                "Raw provenance: rerun with --json; inspect GET /controlspec/v0/packs; "
                "see docs/controlspec/source-map.md."
            ),
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run fixed local reference examples; no actions.")
    parser.add_argument("domain", choices=tuple(FOLDERS))
    parser.add_argument("--base-url", default="http://127.0.0.1:8765")
    parser.add_argument("--json", action="store_true", help="emit the exact legacy machine summary")
    args = parser.parse_args(argv)
    try:
        observed = observe(args.domain, args.base_url)
    except (ExampleFailure, OSError, KeyError, TypeError, RecursionError) as exc:
        print(
            json.dumps(
                {"status": "error", "scope": "local_reference_examples", "message": str(exc)}
            ),
            file=sys.stderr,
        )
        return 1
    print(render_json(observed) if args.json else render_human(observed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
