"""Exact-provenance secret-scanner review; zero broad suppressions.

Never mark a finding PASS because it merely resides in tests/.
The historical commit, path, line, Git blob SHA AND synthetic source syntax must
ALL match; changed or new findings are unreviewed and fail-closed.
"""
from __future__ import annotations
import json
from pathlib import Path
import pytest
from scripts import ci_cinema_pg_history_classifier as h

def fixture_row(key):
    rule,commit,path,line=key
    return {"RuleID":rule,"Commit":commit,"File":path,"StartLine":line,
            "Secret":"***REDACTED***"}

def test_review_registry_contains_exactly_five_individually_pinned_findings():
    assert len(h.REVIEWED)==5
    assert {key[0] for key in h.REVIEWED}=={"generic-api-key"}
    assert {v[1] for v in h.REVIEWED.values()}=={
        "git_blob_sha_constant",
        "synthetic_invalid_test_account",
        "password_verifier_monkeypatch",
        "semantic_source_reference",
    }
    assert all(len(blob)==40 for blob,_ in h.REVIEWED.values())

@pytest.mark.parametrize("key",list(h.REVIEWED))
def test_all_five_gitleaks_findings_are_independently_reproducible(key):
    assert h.exact_classification(fixture_row(key)) == h.REVIEWED[key][1]

def test_unrelated_path_never_exempted():
    row=fixture_row(next(iter(h.REVIEWED)))
    row["File"]="app/private_credentials.py"
    assert h.exact_classification(row) is None

def test_unrelated_commit_never_exempted():
    row=fixture_row(next(iter(h.REVIEWED)))
    row["Commit"]="a"*40
    assert h.exact_classification(row) is None

def test_wrong_line_never_exempted():
    row=fixture_row(next(iter(h.REVIEWED)))
    row["StartLine"]+=1
    assert h.exact_classification(row) is None

def test_wrong_rule_never_exempted():
    row=fixture_row(next(iter(h.REVIEWED)))
    row["RuleID"]="aws-access-key"
    assert h.exact_classification(row) is None

def test_malicious_or_new_secret_in_same_historical_file_is_still_rejected():
    row=fixture_row(next(iter(h.REVIEWED)))
    row["StartLine"]+=100
    assert h.exact_classification(row) is None

def test_same_historic_fixture_line_sha_is_required(monkeypatch):
    key=next(iter(h.REVIEWED))
    class Dummy:
        stdout="0000000000000000000000000000000000000000"
    monkeypatch.setattr(h.subprocess, "run", lambda *args,**kw:Dummy())
    assert h.exact_classification(fixture_row(key)) is None

def test_safe_exact_four_findings_can_be_classified_without_leaking_data(tmp_path):
    report=tmp_path/"scan.json"
    report.write_text(json.dumps([fixture_row(k) for k in h.REVIEWED]))
    ok,summary=h.classify_report(report,1)
    assert ok
    assert summary["reviewed_exact_historical_false_positives"]==len(h.REVIEWED)
    assert summary["unreviewed_findings"]==0
    assert "Secret" not in json.dumps(summary)

def test_one_new_finding_blocks_entire_scan(tmp_path):
    report=tmp_path/"scan.json"
    data=[fixture_row(k) for k in h.REVIEWED]+[{"RuleID":"generic-api-key",
          "Commit":"a"*40,"File":"app/unknown.py","StartLine":2,
          "Secret":"NEVER_PRINT"}]
    report.write_text(json.dumps(data))
    ok,summary=h.classify_report(report,1)
    assert not ok and summary["unreviewed_findings"]==1
    assert "NEVER_PRINT" not in json.dumps(summary)

def test_duplicate_finding_is_treated_as_unreviewed(tmp_path):
    row=fixture_row(next(iter(h.REVIEWED)))
    report=tmp_path/"scan.json"
    report.write_text(json.dumps([row,row]))
    ok,summary=h.classify_report(report,1)
    assert not ok and summary["unreviewed_findings"]==1

@pytest.mark.parametrize("scan_rc",[0,1,2,3])
def test_scanner_and_report_must_agree_on_exit_status(tmp_path,scan_rc):
    report=tmp_path/"scan.json"
    report.write_text(json.dumps([fixture_row(next(iter(h.REVIEWED)))]))
    ok,_=h.classify_report(report,scan_rc)
    assert ok is (scan_rc==1)

def test_missing_report_never_passes(tmp_path):
    assert h.classify_report(tmp_path/"no.json",0)[0] is False

def test_malformed_report_never_passes(tmp_path):
    report=tmp_path/"malformed.json"
    report.write_text('{"not":"list"}')
    assert h.classify_report(report,1)[0] is False

def test_rule_specific_semantic_review_does_not_accept_arbitrary_fixtures():
    for kind in ("git_blob_sha_constant","synthetic_invalid_test_account",
                 "password_verifier_monkeypatch"):
        assert not h.semantic_fixture_guard(kind,"untrusted-extra-context")
        assert not h.semantic_fixture_guard(kind,"")


def test_classification_does_not_depend_on_the_callers_working_directory(tmp_path, monkeypatch):
    """Regression: run from outside the repository, every reviewed finding used to become 'unreviewed' (BLOCKED)."""
    monkeypatch.chdir(tmp_path)
    for key in h.REVIEWED:
        assert h.exact_classification(fixture_row(key)) == h.REVIEWED[key][1]
    report = tmp_path / "scan.json"
    report.write_text(json.dumps([fixture_row(k) for k in h.REVIEWED]))
    ok, summary = h.classify_report(report, 1)
    assert ok and summary["status"] == "PASS" and summary["unreviewed_findings"] == 0


def test_unreachable_repository_still_fails_closed(tmp_path, monkeypatch):
    """The fix must not turn a missing history into a pass."""
    monkeypatch.setattr(h, "REPO_ROOT", tmp_path)          # not a git repository
    for key in h.REVIEWED:
        assert h.exact_classification(fixture_row(key)) is None
    report = tmp_path / "scan.json"
    report.write_text(json.dumps([fixture_row(k) for k in h.REVIEWED]))
    ok, summary = h.classify_report(report, 1)
    assert not ok and summary["status"] == "BLOCKED" and summary["unreviewed_findings"] == len(h.REVIEWED)
