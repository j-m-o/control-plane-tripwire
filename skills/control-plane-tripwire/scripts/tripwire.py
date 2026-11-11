#!/usr/bin/env python3
"""Control-Plane Tripwire: deterministic verdict engine.

Compares a baseline snapshot of safety controls against a current snapshot,
using a policy that is held independently of the agents being monitored.
Every control gets one verdict with the evidence that produced it.

Read-only. Standard library only. No network access.

Control-Plane Tripwire, created by Jessica Mosley | LinkedIn: https://www.linkedin.com/in/jessmosley/ | GitHub: https://github.com/j-m-o/
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

TAMPER = {"UNAUTHORIZED_WEAKENING", "SELF_APPROVED", "UNATTRIBUTED_CHANGE"}
SEVERITY = {
    "UNCHANGED": "none",
    "SAFE_CHANGE": "none",
    "APPROVED_EXCEPTION": "low",
    "PREEXISTING_VIOLATION": "medium",
    "UNVERIFIABLE": "medium",
    "UNATTRIBUTED_CHANGE": "high",
    "UNAUTHORIZED_WEAKENING": "critical",
    "SELF_APPROVED": "critical",
}
MISSING = object()


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compliant(rule: dict, value) -> bool:
    """True when a value satisfies its policy rule."""
    kind = rule["kind"]
    if kind == "min":
        return isinstance(value, (int, float)) and value >= rule["min"]
    if kind == "safe_bool":
        return value is rule["safe_value"]
    if kind == "must_include":
        return isinstance(value, list) and set(rule["must_include"]) <= set(value)
    if kind == "allowed_values":
        return value in rule["allowed_values"]
    raise ValueError(f"Unknown rule kind: {kind}")


def weakens(rule: dict, before, after) -> bool:
    """True when a change moves a control in the less-safe direction."""
    kind = rule["kind"]
    if kind == "min":
        return after < before
    if kind == "safe_bool":
        return before is rule["safe_value"] and after is not rule["safe_value"]
    if kind == "must_include":
        return bool(set(before) - set(after))
    if kind == "allowed_values":
        return before in rule["allowed_values"] and after not in rule["allowed_values"]
    return True


def is_agent(actor: dict | None) -> bool:
    return bool(actor) and actor.get("type") in {"agent", "bot", "automation"}


def judge(control: dict, policy: dict, baseline: dict, current: dict, events: dict) -> dict:
    cid = control["id"]
    before = baseline.get(cid, MISSING)
    after = current.get(cid, MISSING)
    event = events.get(cid)
    out = {
        "control_id": cid,
        "system": control["system"],
        "resource": control["resource"],
        "baseline": None if before is MISSING else before,
        "current": None if after is MISSING else after,
        "rule": control["rule"],
        "change_event": event,
    }

    def verdict(name: str, why: str) -> dict:
        out.update(verdict=name, severity=SEVERITY[name], tamper=name in TAMPER, rationale=why)
        return out

    if after is MISSING:
        return verdict("UNVERIFIABLE", "Collector returned no value for this control. Unknown is not safe; verify manually.")
    if before is MISSING:
        return verdict("UNVERIFIABLE", "No baseline for this control. Establish a baseline before trusting the result.")

    if before == after:
        if compliant(control["rule"], after):
            return verdict("UNCHANGED", "Value matches baseline and satisfies policy.")
        return verdict("PREEXISTING_VIOLATION", "Unchanged, but the baseline itself already violates policy.")

    if event is None:
        return verdict("UNATTRIBUTED_CHANGE", "Value changed with no matching change event. Something modified this control outside the audited path.")

    if not weakens(control["rule"], before, after) and compliant(control["rule"], after):
        return verdict("SAFE_CHANGE", "Change keeps or strengthens the control and is attributed.")

    approval = event.get("approval")
    actor = event.get("actor") or {}
    if not approval:
        return verdict("UNAUTHORIZED_WEAKENING", "Control weakened with no recorded approval.")
    approver = approval.get("approver") or {}
    if approver.get("id") == actor.get("id") or is_agent(approver):
        return verdict("SELF_APPROVED", "Approval came from the actor itself or from an automated identity. Agents cannot authorize changes to their own guardrails.")
    authorized = policy["approvers"].get(control["system"], [])
    if approver.get("id") not in authorized:
        return verdict("UNAUTHORIZED_WEAKENING", f"Approver '{approver.get('id')}' is not an authorized owner for {control['system']} controls.")
    return verdict("APPROVED_EXCEPTION", "Weakening approved by an authorized human owner. Surfaced for awareness and expiry tracking.")


def run(policy_path: Path, baseline_path: Path, current_path: Path, events_path: Path, expected_sha: str | None) -> dict:
    actual_sha = sha256(policy_path)
    if expected_sha and actual_sha != expected_sha:
        return {
            "status": "POLICY_INTEGRITY_FAILURE",
            "policy_sha256": actual_sha,
            "expected_sha256": expected_sha,
            "message": "Policy file does not match the pinned hash. Stopping: a modified policy cannot be used to judge controls.",
            "results": [],
        }
    policy = load(policy_path)
    baseline = load(baseline_path)
    current = load(current_path)
    events = {e["control_id"]: e for e in load(events_path)}
    results = [judge(c, policy, baseline, current, events) for c in policy["controls"]]
    tampered = [r for r in results if r["tamper"]]
    counts: dict[str, int] = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return {
        "status": "TAMPER_DETECTED" if tampered else "NO_TAMPER_DETECTED",
        "policy_sha256": actual_sha,
        "summary": counts,
        "tamper_count": len(tampered),
        "results": results,
        "human_decision_required": [r["control_id"] for r in results if r["severity"] in {"critical", "high", "medium"}],
    }


def to_markdown(report: dict) -> str:
    lines = ["# Control-Plane Tripwire Report", "", f"**Status:** {report['status']}  "]
    lines.append(f"**Policy SHA-256:** `{report['policy_sha256'][:16]}...`")
    if report["status"] == "POLICY_INTEGRITY_FAILURE":
        lines += ["", report["message"]]
        return "\n".join(lines) + "\n"
    lines += ["", "| Control | Verdict | Severity | Baseline | Current | Why |", "| --- | --- | --- | --- | --- | --- |"]
    order = list(SEVERITY)
    for r in sorted(report["results"], key=lambda x: -order.index(x["verdict"])):
        lines.append(f"| `{r['control_id']}` | {r['verdict']} | {r['severity']} | `{json.dumps(r['baseline'])}` | `{json.dumps(r['current'])}` | {r['rationale']} |")
    lines += ["", "## Needs a named human owner", ""]
    lines += [f"- `{c}`" for c in report["human_decision_required"]] or ["- Nothing"]
    lines += ["", "_The tripwire reports. It does not restore controls. Restoration and exceptions belong to the platform or security owner._"]
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--policy", required=True, type=Path)
    p.add_argument("--baseline", required=True, type=Path)
    p.add_argument("--current", required=True, type=Path)
    p.add_argument("--events", required=True, type=Path)
    p.add_argument("--expected-policy-sha256", default=None)
    p.add_argument("--format", choices=["json", "markdown"], default="markdown")
    a = p.parse_args()
    report = run(a.policy, a.baseline, a.current, a.events, a.expected_policy_sha256)
    print(json.dumps(report, indent=2) if a.format == "json" else to_markdown(report))
    return {"NO_TAMPER_DETECTED": 0, "TAMPER_DETECTED": 2, "POLICY_INTEGRITY_FAILURE": 3}[report["status"]]


if __name__ == "__main__":
    sys.exit(main())
