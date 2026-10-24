"""JARVIS WORKS evidence declaration validator; it cannot authenticate test claims.

Only Python stdlib; no network or database access. Never produces release approval.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

GATES = ("code_environment", "functionality", "regression_recovery", "ui_ux", "operations_security")
STATUSES = frozenset(("PASS", "PARTIAL", "FAIL", "BLOCKED", "NOT RUN", "NOT MEASURED"))
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def validate(report: Any) -> list[str]:
    issues: list[str] = []
    if not isinstance(report, dict):
        return ["report must be an object"]

    if report.get("project") != "JARVIS-WORKS":
        issues.append("project must be JARVIS-WORKS")
    if report.get("change_mode") != "review_only":
        issues.append("change_mode must be review_only; this checker never authorizes release")
    if not isinstance(report.get("source_commit"), str) or not HEX40.fullmatch(report["source_commit"]):
        issues.append("source_commit must be an exact 40-char lowercase Git SHA")
    if not isinstance(report.get("baseline_commit"), str) or not HEX40.fullmatch(report["baseline_commit"]):
        issues.append("baseline_commit must be an exact 40-char lowercase Git SHA")

    gates = report.get("gates")
    if not isinstance(gates, dict) or set(gates) != set(GATES):
        issues.append("gates must declare exactly the five official gates")
    else:
        for name in GATES:
            gate = gates[name]
            if not isinstance(gate, dict):
                issues.append(f"{name} must be an object")
                continue
            state = gate.get("status")
            if state not in STATUSES:
                issues.append(f"{name} has invalid status")
            evidence = gate.get("evidence")
            if not isinstance(evidence, list):
                issues.append(f"{name} evidence must be a list")
                continue
            if state == "PASS" and not evidence:
                issues.append(f"{name} claims PASS without evidence")
            for item in evidence:
                if not isinstance(item, dict) or not isinstance(item.get("kind"), str) or not item["kind"].strip() or not isinstance(item.get("ref"), str) or not item["ref"].strip():
                    issues.append(f"{name} has malformed evidence pointer")

    release = report.get("release")
    if not isinstance(release, dict) or release.get("status") not in ("BLOCKED", "REVIEW_CANDIDATE"):
        issues.append("release must be BLOCKED or REVIEW_CANDIDATE; never production approved")
    else:
        if release.get("production_deployed") is not False:
            issues.append("cannot claim production deployment from this review-only evidence")
        if not isinstance(release.get("remaining_blockers"), list):
            issues.append("release.remaining_blockers must be a list")
        if release.get("status") == "REVIEW_CANDIDATE":
            if not isinstance(gates, dict) or any(not isinstance(gates.get(k), dict) or gates[k].get("status") != "PASS" for k in GATES):
                issues.append("REVIEW_CANDIDATE requires all five verified PASS declarations")
            if release.get("remaining_blockers"):
                issues.append("REVIEW_CANDIDATE cannot have unresolved blockers")

    result = report.get("test_results")
    if not isinstance(result, dict):
        issues.append("test_results must be an object")
    else:
        for key in ("passed", "failed", "skipped"):
            if type(result.get(key)) is not int or result[key] < 0:
                issues.append(f"test_results.{key} must be a nonnegative integer")
        if not isinstance(result.get("run_ref"), str) or not result["run_ref"].strip():
            issues.append("test_results.run_ref required")
        if release and isinstance(release, dict) and release.get("status") == "REVIEW_CANDIDATE" and (result.get("failed") != 0 or result.get("skipped") != 0):
            issues.append("REVIEW_CANDIDATE cannot have failed or skipped tests")

    rollback = report.get("rollback")
    if not isinstance(rollback, dict) or not isinstance(rollback.get("method"), str) or not rollback.get("method", "").strip() or rollback.get("tested") not in (True, False):
        issues.append("rollback.method and rollback.tested are required")
    return issues


def verify_project(root: Path) -> list[str]:
    required = (
        "AGENTS.md",
        "GLOSSARY.md",
        "docs/agents/JW_CURATED_SKILLS_V90.md",
        ".agents/skills/jw-verified-delivery/SKILL.md",
        ".agents/skills/jw-evidence-retro/SKILL.md",
        "tests/test_jw_evidence_gate.py",
    )
    issues = [f"missing navigation file: {name}" for name in required if not (root / name).is_file()]
    if not issues:
        guide = (root / "AGENTS.md").read_text(encoding="utf-8")
        for token in ("J1", "J5", "GLOSSARY.md", "main", "BLOCKED"):
            if token not in guide:
                issues.append(f"AGENTS.md missing protected policy marker: {token}")
    return issues


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", type=Path, help="validate an evidence JSON, not its factual truth")
    g.add_argument("--check-project", type=Path, help="validate agent workflow file wiring")
    a = ap.parse_args()
    if a.check_project:
        problems = verify_project(a.check_project)
    else:
        try:
            payload = json.loads(a.check.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            print(f"FAIL: evidence unreadable: {type(exc).__name__}")
            return 1
        problems = validate(payload)
    for p in problems:
        print("FAIL: " + p)
    if problems:
        return 1
    print("PASS: evidence FORMAT/agent navigation only; external test results NOT independently verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
