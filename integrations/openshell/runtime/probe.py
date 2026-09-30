"""Recorded probes through the real OpenShell sandbox and synthetic HTTPS target.

Run inside the isolated controller. The final probe stops only the recorded
middleware process; the operator must restart it after collecting observations.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import signal
import socket
import ssl
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.request import urlopen

from assurance.controlspec.openshell_demo.cli import engine_at
from assurance.controlspec.openshell_demo.policy import PurchaseRequest, TrustedScope

STATE = Path("/state")
PIN = "6648bd0c290efbc41ba131ee9831ee45cd431f94"
EXPECTED_DENIALS = {
    "replay_same_action": ("middleware_denied", "action_already_reserved"),
    "over_limit_without_approval": ("middleware_denied", "approval_required"),
    "exact_before_approval": ("middleware_denied", "approval_required"),
    "changed_before_approval": ("middleware_denied", "approval_required"),
    "changed_amount_after_approval": ("middleware_denied", "action_changed"),
    "recurring_purchase": ("middleware_denied", "policy_denied"),
    "alternate_path": ("policy_denied", None),
    "middleware_outage": ("middleware_failed", None),
}


def instant() -> str:
    return datetime.now(UTC).isoformat()


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise AssertionError(detail)


def parse_http(stdout: str) -> dict[str, Any]:
    text = stdout.replace("\r\n", "\n")
    matches = list(re.finditer(r"(?m)^HTTP/\S+ (\d{3})[^\n]*\n", text))
    if not matches:
        return {"status": None, "headers": {}, "body": None}
    status = matches[-1]
    end = text.find("\n\n", status.end())
    headers: dict[str, str] = {}
    body = ""
    if end != -1:
        for line in text[status.end():end].splitlines():
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.lower()] = value.strip()
        body = text[end+2:].strip()
    try:
        parsed: Any = json.loads(body)
    except ValueError:
        parsed = body
    return {"status": int(status.group(1)), "headers": headers, "body": parsed}


class RuntimeProbe:
    def __init__(self, sandbox: str, sandbox_id: str, prefix: str) -> None:
        self.bootstrap = json.loads((STATE / "bootstrap.json").read_text())
        self.engine = engine_at(STATE)
        self.scope = TrustedScope(
            gateway_id=self.bootstrap["gateway_id"], sandbox_id=sandbox_id,
        )
        self.prefix = prefix
        self.sandbox = sandbox
        self.trust = ssl.create_default_context(cafile=str(STATE / "tls/target-ca.pem"))
        self.output = STATE / "runtime-observations.json"
        require(not self.output.exists(), "Preserve existing evidence before starting a new run")
        self.document: dict[str, Any] = {
            "schema_version": "1", "started_at": instant(), "execution_mode": "actual_openshell",
            "openshell_source_pin": PIN, "synthetic_only": True,
            "operator_approvals": "scripted host fixture, not a human approval observation",
            "claims": [
                "Actual sandbox exec and upstream-signed extension JWTs; no fixture-issued JWTs",
                "HTTPS synthetic purchases only; no real financial effects",
                "Reference evaluator decisions remain non-authoritative outside this demo",
                "Native policy restricts host/path/binary; ControlSpec adds business conditions",
                "ControlSpec target additionally validates signed tickets",
                "Supervisor image adds the synthetic root CA; NVIDIA executable unchanged",
            ],
            "gateway_id": self.scope.gateway_id, "sandbox_id": sandbox_id,
            "sandbox_name": sandbox, "action_prefix": prefix,
            "observations": [], "status": "running", "middleware_stopped": False,
        }

    def provenance(self) -> None:
        source: dict[str, Any] = {"revision": None, "dirty": None}
        commands = {
            "revision": ["git", "-c", "safe.directory=/repo", "-C", "/repo", "rev-parse", "HEAD"],
            "worktree_status": ["git", "-c", "safe.directory=/repo", "-C", "/repo",
                                "status", "--porcelain"],
            "openshell_version": ["openshell", "--version"],
            "effective_policy": ["openshell", "--gateway-endpoint", "http://127.0.0.1:17670",
                                 "policy", "get", self.sandbox, "--full", "--output", "json"],
        }
        records: dict[str, Any] = {}
        for label, command in commands.items():
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=30,
                                        check=False)
                records[label] = {"command": command, "exit_code": result.returncode,
                                  "stdout": result.stdout, "stderr": result.stderr}
                if label == "revision" and result.returncode == 0:
                    source["revision"] = result.stdout.strip()
                if label == "worktree_status" and result.returncode == 0:
                    source["dirty"] = bool(result.stdout.strip())
            except (OSError, subprocess.TimeoutExpired) as exc:
                records[label] = {"command": command, "error": type(exc).__name__}
        self.document["source"] = source
        self.document["provenance_commands"] = records
        require(all(record.get("exit_code") == 0 for record in records.values()),
                "Required source, version or policy provenance unavailable")
        require(source["dirty"] is False, "Commit source before recording runtime evidence")
        require(records["openshell_version"]["stdout"].strip() == "openshell 0.1.2",
                "Unexpected OpenShell version")
        effective = json.loads(records["effective_policy"]["stdout"])
        require(effective["status"] == "effective", "Policy is not effective")
        endpoint = effective["policy"]["network_policies"]["synthetic-purchase"]["endpoints"][0]
        require(endpoint["host"] == "host.openshell.internal"
                and endpoint["port"] == 18081 and endpoint["protocol"] == "rest"
                and endpoint["enforcement"] == "enforce"
                and endpoint["rules"] == [{"allow": {"method": "POST", "path": "/purchases"}}],
                "Unexpected effective native boundary")
        middleware = effective["policy"]["network_middlewares"]["controlspec-purchases"]
        require(middleware["middleware"] == "controlspec-demo"
                and middleware["on_error"] == "fail_closed"
                and middleware["config"] == {"profile": "synthetic-purchases-v1"},
                "Unexpected effective middleware policy")
        self.document["effective_policy"] = effective

    def state(self) -> dict[str, Any]:
        with urlopen("https://127.0.0.1:18081/state", context=self.trust, timeout=5) as response:
            state = json.load(response)
        return {
            "observed_at": instant(), "purchase_count": state["purchase_count"],
            "spent_minor": state["spent_minor"], "balance_minor": state["balance_minor"],
            "run_purchases": [p for p in state["purchases"]
                              if p["action_id"].startswith(self.prefix)],
        }

    def persist(self) -> None:
        self.document["recorded_at"] = instant()
        self.document["decision_ledger_events"] = [
            event for event in self.engine.ledger.events()
            if event["action_id"].startswith(self.prefix) and event["scope"] == self.scope.key
        ]
        self.document["decision_ledger_hash_chain_valid"] = self.engine.ledger.verify()
        self.output.write_text(json.dumps(self.document, indent=2) + "\n", encoding="utf-8")

    def purchase(self, name: str, amount: int = 4200, recurring: bool = False) -> PurchaseRequest:
        return PurchaseRequest(schema_version="1", action_id=f"{self.prefix}-{name}",
                               amount_minor=amount, currency="USD", merchant="demo-store",
                               recurring=recurring)

    def send(
        self, name: str, purchase: PurchaseRequest, *, expected_status: int | None,
        expected_delta: int, url: str | None = None, method: str = "POST",
    ) -> dict[str, Any]:
        before = self.state()
        command = [
            "openshell", "--gateway-endpoint", "http://127.0.0.1:17670", "sandbox", "exec",
            "--name", self.sandbox, "--no-tty", "--no-login-shell", "--", "/usr/bin/curl",
            "-sS", "-i", "--max-time", "12",
            url or "https://host.openshell.internal:18081/purchases",
        ]
        if method == "POST":
            command += ["--header", "content-type: application/json",
                        "--data", purchase.model_dump_json()]
        started = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True, timeout=45, check=False)
        after = self.state()
        http = parse_http(result.stdout)
        observation = {
            "scenario": name, "timestamp": instant(), "action_id": purchase.action_id,
            "command": command, "exit_code": result.returncode,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "stdout": result.stdout, "stderr": result.stderr, "http": http,
            "target_before": before, "target_after": after,
            "target_purchase_delta": after["purchase_count"] - before["purchase_count"],
            "target_spend_delta_minor": after["spent_minor"] - before["spent_minor"],
            "expected_status": expected_status, "expected_purchase_delta": expected_delta,
        }
        self.document["observations"].append(observation)
        self.persist()
        require(observation["target_purchase_delta"] == expected_delta,
                f"{name}: unexpected target mutation count")
        require(observation["target_spend_delta_minor"] == purchase.amount_minor*expected_delta,
                f"{name}: unexpected target spend mutation")
        if expected_status is not None:
            require(http["status"] == expected_status,
                    f"{name}: expected HTTP {expected_status}, observed {http['status']}")
            require(result.returncode == 0, f"{name}: CLI/curl did not complete successfully")
        else:
            # A native policy may reject before completing the TLS handshake.
            # Exact policy attribution is corroborated with supervisor logs by the operator.
            require(http["status"] == 403 or result.returncode != 0,
                    f"{name}: alternate route was not rejected")
            observation["policy_attribution"] = "requires corroborating supervisor log"
        if name in EXPECTED_DENIALS:
            expected_error, expected_reason = EXPECTED_DENIALS[name]
            observation["expected_error"] = expected_error
            observation["expected_reason_code"] = expected_reason
            body = http["body"]
            require(isinstance(body, dict) and body.get("error") == expected_error,
                    f"{name}: denial did not originate from the expected control layer")
            if expected_reason is not None:
                require(body.get("reason_code") == expected_reason,
                        f"{name}: denial reason differs from the expected control")
            observation["denial_attribution_verified"] = True
            observation.pop("policy_attribution", None)
        if expected_status == 200:
            require(isinstance(http["body"], dict) and http["body"].get("status") == "committed",
                    f"{name}: successful response did not contain a committed target receipt")
        observation["assertions_passed"] = True
        self.persist()
        return observation

    def reconcile(
        self, purchase: PurchaseRequest, observation: dict[str, Any], missing: bool = False,
    ) -> None:
        receipt = None if missing else observation["http"]["body"]
        verified = self.engine.reconcile(purchase, self.scope, receipt)
        observation["receipt_supplied"] = not missing
        observation["completion_verified"] = verified
        self.persist()
        require(verified is (not missing), "Unexpected evidence reconciliation result")

    def approve(self, purchase: PurchaseRequest) -> None:
        evaluation = self.engine.approve(
            purchase.action_id, self.scope, (STATE / "operator.secret").read_text(encoding="ascii"),
        )
        self.document.setdefault("scripted_operator_actions", []).append({
            "action_id": purchase.action_id, "observed_at": instant(),
            "operator_kind": "scripted synthetic fixture outside sandbox",
            "decision": evaluation.decision.model_dump(mode="json"),
        })
        self.persist()
        require(evaluation.allowed, "Exact synthetic approval did not reevaluate to permission")

    def stop_middleware(self) -> None:
        pid = int((STATE / "middleware.pid").read_text())
        require(pid > 1, "Invalid recorded middleware PID")
        cmd = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        require(any(p.endswith(b"bootstrap.py") for p in cmd) and b"middleware" in cmd,
                "Recorded PID does not identify the task middleware")
        os.kill(pid, signal.SIGTERM)
        self.document["middleware_stopped"] = True
        self.document["middleware_stop_timestamp"] = instant()
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", 50051), timeout=0.2):
                    pass
            except OSError:
                self.document["middleware_listener_closed"] = True
                self.persist()
                return
            time.sleep(0.2)
        raise AssertionError("Middleware listener did not stop")

    def run(self) -> None:
        try:
            self.provenance()
            self.document["initial_target_state"] = self.state()
            self.persist()
            allowed = self.purchase("allowed")
            observed = self.send("allowed_42", allowed, expected_status=200, expected_delta=1)
            self.reconcile(allowed, observed)
            self.send("replay_same_action", allowed, expected_status=403, expected_delta=0)

            over = self.purchase("over", 14200)
            self.send("over_limit_without_approval", over, expected_status=403, expected_delta=0)

            exact = self.purchase("exact", 14200)
            self.send("exact_before_approval", exact, expected_status=403, expected_delta=0)
            self.approve(exact)
            observed = self.send(
                "exact_after_approval", exact, expected_status=200, expected_delta=1,
            )
            self.reconcile(exact, observed)

            changed = self.purchase("changed", 14200)
            self.send("changed_before_approval", changed, expected_status=403, expected_delta=0)
            self.approve(changed)
            altered = self.purchase("changed", 14300)
            self.send(
                "changed_amount_after_approval", altered, expected_status=403, expected_delta=0,
            )

            self.send("recurring_purchase", self.purchase("recurring", 999, True),
                      expected_status=403, expected_delta=0)
            missing = self.purchase("missing")
            observed = self.send("missing_receipt", missing, expected_status=200, expected_delta=1)
            self.reconcile(missing, observed, missing=True)

            self.send("alternate_path", self.purchase("path"), expected_status=None,
                      expected_delta=0, method="GET",
                      url="https://host.openshell.internal:18081/state")
            self.send("direct_ip_attempt", self.purchase("ip"), expected_status=None,
                      expected_delta=0,
                      url=f"https://{self.bootstrap['controller_ip']}:18081/purchases")
            self.send("gateway_control_plane_attempt", self.purchase("gateway"),
                      expected_status=None, expected_delta=0, method="GET",
                      url=f"http://{self.bootstrap['controller_ip']}:17670/"
                          ".well-known/openid-configuration")
            self.send("middleware_control_plane_attempt", self.purchase("middleware"),
                      expected_status=None, expected_delta=0, method="GET",
                      url=f"https://{self.bootstrap['controller_ip']}:50051/")

            self.stop_middleware()
            self.send("middleware_outage", self.purchase("outage"),
                      expected_status=403, expected_delta=0)
            self.document["status"] = "passed"
        except Exception as exc:
            self.document["status"] = "failed"
            self.document["failure"] = {"type": type(exc).__name__, "message": str(exc)}
            raise
        finally:
            self.document["completed_at"] = instant()
            self.document["final_target_state"] = self.state()
            self.persist()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sandbox", default="cs-runtime-tls")
    parser.add_argument("--sandbox-id", required=True)
    args = parser.parse_args()
    probe = RuntimeProbe(args.sandbox, args.sandbox_id, "runtime-" + secrets.token_hex(5))
    probe.run()
    print(json.dumps({"status": probe.document["status"], "evidence": str(probe.output),
                      "observations": len(probe.document["observations"]),
                      "middleware_stopped": probe.document["middleware_stopped"]}))


if __name__ == "__main__":
    main()
