"""Negative-contract tests: reject invented gates and unjustified release claims."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from scripts.jw_evidence_gate import GATES, validate, verify_project


SHA = "a" * 40


def example(status="PASS"):
    return {
        "project": "JARVIS-WORKS", "change_mode": "review_only",
        "source_commit": SHA, "baseline_commit": "b" * 40,
        "gates": {gate: {"status": status, "evidence": [{"kind": "ci", "ref": "https://github.com/test/runs/1"}]} for gate in GATES},
        "release": {"status": "REVIEW_CANDIDATE", "remaining_blockers": [], "production_deployed": False},
        "test_results": {"passed": 3, "failed": 0, "skipped": 0, "run_ref": "https://github.com/test/runs/1"},
        "rollback": {"method": "git revert reviewed branch", "tested": True},
    }


def errors(v):
    return "\n".join(validate(v))


def test_all_gate_shapes_in_review_candidate_are_accepted():
    assert errors(example()) == ""


@pytest.mark.parametrize("change", [
    lambda d: d.update(project="OTHER"),
    lambda d: d.update(change_mode="production"),
    lambda d: d.update(source_commit="abbrev"),
    lambda d: d.update(baseline_commit="Z" * 40),
    lambda d: d.pop("gates"),
    lambda d: d["gates"].pop("operations_security"),
    lambda d: d["gates"]["code_environment"].update(status="GREEN"),
    lambda d: d["gates"]["code_environment"].update(evidence=[]),
    lambda d: d["gates"]["code_environment"].update(evidence=[{"kind": "ci"}]),
    lambda d: d["release"].update(status="APPROVED"),
    lambda d: d["release"].update(production_deployed=True),
    lambda d: d["release"].update(remaining_blockers=["TLS unknown"]),
    lambda d: d["test_results"].update(failed=1),
    lambda d: d["test_results"].update(skipped=1),
    lambda d: d["test_results"].update(passed=True),
    lambda d: d["rollback"].update(tested="yes"),
])
def test_false_claims_are_rejected(change):
    d = example()
    change(d)
    assert errors(d)


def test_partial_gate_blocks_review_candidate():
    d = example()
    d["gates"]["ui_ux"].update(status="PARTIAL", evidence=[])
    assert "REVIEW_CANDIDATE" in errors(d)


def test_blocked_release_with_incomplete_gates_is_allowed_as_honest_report():
    d = example()
    d["release"] = {"status": "BLOCKED", "remaining_blockers": ["actual HTTPS TLS"], "production_deployed": False}
    d["gates"]["ui_ux"] = {"status": "NOT RUN", "evidence": []}
    d["test_results"]["skipped"] = 2
    assert errors(d) == ""


def test_empty_evidence_for_not_run_may_be_truthful():
    d = example()
    d["release"]["status"] = "BLOCKED"
    d["release"]["remaining_blockers"] = ["browser"]
    d["gates"]["operations_security"] = {"status": "NOT MEASURED", "evidence": []}
    assert errors(d) == ""


def test_format_guard_is_not_release_approval():
    d = example()
    d["release"]["status"] = "PRODUCTION_READY"
    assert "release must be BLOCKED" in errors(d)


def test_navigation_contract_exists_in_repo():
    root = Path(__file__).resolve().parents[1]
    assert verify_project(root) == []


def test_navigation_contract_rejects_missing_root(tmp_path):
    assert len(verify_project(tmp_path)) >= 1


def test_unknown_extra_gate_is_rejected():
    d = example()
    d["gates"]["fantasy_score"] = {"status": "PASS", "evidence": [{"kind":"claim","ref":"self"}]}
    assert "exactly the five" in errors(d)
