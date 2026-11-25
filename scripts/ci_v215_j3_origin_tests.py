"""J3 verified evidence regression: manipulated SHA, CI run, gate or origin must fail."""
from __future__ import annotations

import unittest
from copy import deepcopy
from urllib.error import URLError

from scripts.jw_evidence_gate import GATES
from scripts.jw_j3_origin_gate import REPO, verify_report

SOURCE = "7289aeb7d670dbd41161a371bcfb861c9ddbe1cb"
BASELINE = "56453d680eb5db59f071adc938cc452471706b2e"
RUN_ID = 41415951016
RUN = f"https://github.com/{REPO}/actions/runs/{RUN_ID}"


def example() -> dict:
    return {
        "project": "JARVIS-WORKS",
        "change_mode": "review_only",
        "source_commit": SOURCE,
        "baseline_commit": BASELINE,
        "gates": {g: {"status": "PASS", "evidence": [{"kind": "ci", "ref": RUN}]} for g in GATES},
        "release": {"status": "REVIEW_CANDIDATE", "remaining_blockers": [], "production_deployed": False},
        "test_results": {"passed": 4, "failed": 0, "skipped": 0, "run_ref": RUN},
        "rollback": {"method": "git revert review commit", "tested": True},
    }


def authentic(path: str) -> dict:
    if path == f"commits/{SOURCE}":
        return {"sha": SOURCE}
    if path == f"commits/{BASELINE}":
        return {"sha": BASELINE}
    if path == f"actions/runs/{RUN_ID}":
        return {"repository": {"full_name": REPO}, "id": RUN_ID,
                "head_sha": SOURCE, "status": "completed",
                "conclusion": "success", "html_url": RUN}
    raise ValueError(path)


class AttestationGateTests(unittest.TestCase):
    def test_known_commit_and_successful_run_provenance(self):
        self.assertEqual(verify_report(example(), authentic), [])

    def test_nonexistent_source_commit(self):
        report = example()
        report["source_commit"] = "0" * 40
        self.assertTrue(verify_report(report, authentic))

    def test_nonexistent_baseline_commit(self):
        report = example()
        report["baseline_commit"] = "f" * 40
        self.assertTrue(verify_report(report, authentic))

    def test_github_run_sha_replay(self):
        def old_run(path):
            result = authentic(path)
            if path.startswith("actions/runs/"):
                return {**result, "head_sha": BASELINE}
            return result
        self.assertTrue(verify_report(example(), old_run))

    def test_github_run_other_repository(self):
        def other_repo(path):
            result = authentic(path)
            if path.startswith("actions/runs/"):
                return {**result, "repository": {"full_name": "attacker/fake"}}
            return result
        self.assertTrue(verify_report(example(), other_repo))

    def test_failed_run_cannot_be_forged_as_pass(self):
        def failed_run(path):
            result = authentic(path)
            if path.startswith("actions/runs/"):
                return {**result, "conclusion": "failure"}
            return result
        self.assertTrue(verify_report(example(), failed_run))

    def test_pending_run_cannot_be_claimed_pass(self):
        def pending_run(path):
            result = authentic(path)
            if path.startswith("actions/runs/"):
                return {**result, "status": "in_progress", "conclusion": None}
            return result
        self.assertTrue(verify_report(example(), pending_run))

    def test_missing_origin_fails_closed(self):
        def offline(path):
            raise URLError("offline")
        self.assertTrue(verify_report(example(), offline))

    def test_malformed_run_url_fails_before_fetch(self):
        report = example()
        report["gates"]["ui_ux"]["evidence"][0]["ref"] = "https://evil.invalid/runs/1"
        self.assertTrue(verify_report(report, authentic))

    def test_fake_url_query_suffix_fails(self):
        report = example()
        report["test_results"]["run_ref"] += "?ref=trusted"
        self.assertTrue(verify_report(report, authentic))

    def test_mismatched_run_id_fails(self):
        def wrong_id(path):
            result = authentic(path)
            if path.startswith("actions/runs/"):
                return {**result, "id": 1}
            return result
        self.assertTrue(verify_report(example(), wrong_id))

    def test_blocked_gate_not_upgradable_to_pass(self):
        report = example()
        report["gates"]["ui_ux"]["status"] = "BLOCKED"
        self.assertTrue(verify_report(report, authentic))

    def test_skipped_tests_fail(self):
        report = example()
        report["test_results"]["skipped"] = 1
        self.assertTrue(verify_report(report, authentic))

    def test_no_successful_test_fails(self):
        report = example()
        report["test_results"]["passed"] = 0
        self.assertTrue(verify_report(report, authentic))

    def test_fake_evidence_ref_without_ci_kind_fails(self):
        report = example()
        report["gates"]["code_environment"]["evidence"][0]["kind"] = "claim"
        self.assertTrue(verify_report(report, authentic))

    def test_release_blocked_not_laundered_into_acceptance(self):
        report = example()
        report["release"]["status"] = "BLOCKED"
        report["release"]["remaining_blockers"] = ["PG TLS"]
        self.assertTrue(verify_report(report, authentic))

    def test_untested_rollback_fails(self):
        report = example()
        report["rollback"]["tested"] = False
        self.assertTrue(verify_report(report, authentic))

    def test_rejects_response_url_mismatch(self):
        def mismatch(path):
            result = authentic(path)
            if path.startswith("actions/runs/"):
                return {**result, "html_url": "https://github.com/fake"}
            return result
        self.assertTrue(verify_report(example(), mismatch))


if __name__ == "__main__":
    unittest.main()
