"""V21.6 negative proof cases: run origin, workflow path, actual CLI and errors."""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scripts.jw_j3_origin_gate import REPO, main, verify_run_provenance

SOURCE = "b26b624f41127f0e1ba906a2a5ba5e11c2430cc2"
BASE = "7289aeb7d670dbd41161a371bcfb861c9ddbe1cb"
RUN_ID = 41432122556
RUN = f"https://github.com/{REPO}/actions/runs/{RUN_ID}"
WORKFLOW = ".github/workflows/jw-v215-ui-j3-regression.yml"


def canonical(path):
    if path == f"commits/{SOURCE}":
        return {"sha": SOURCE}
    if path == f"commits/{BASE}":
        return {"sha": BASE}
    if path == f"actions/runs/{RUN_ID}":
        return {"id": RUN_ID, "repository": {"full_name": REPO},
                "head_sha": SOURCE, "conclusion": "success",
                "status": "completed", "html_url": RUN,
                "path": WORKFLOW, "event": "push"}
    raise AssertionError("unexpected path: " + path)


def faulty(patch_run):
    def fetch(path):
        v = canonical(path)
        return {**v, **patch_run} if path.startswith("actions/runs/") else v
    return fetch


class OriginTests(unittest.TestCase):
    def verify(self, fetch=canonical, source=SOURCE, base=BASE, run=RUN, path=WORKFLOW):
        return verify_run_provenance(source, base, run, path, fetch)

    def test_realistic_valid_origin(self):
        self.assertEqual(self.verify(), [])

    def test_bogus_source(self):
        self.assertIn("source:", " ".join(self.verify(source="0" * 40)))

    def test_bogus_baseline(self):
        self.assertTrue(self.verify(base="f" * 40))

    def test_sha_type_bool(self):
        self.assertTrue(self.verify(source=True))

    def test_sha_uppercase_or_short(self):
        for sha in (SOURCE.upper(), SOURCE[:7], "../" + SOURCE):
            with self.subTest(sha=sha):
                self.assertTrue(self.verify(source=sha))

    def test_run_url_query_and_other_repo(self):
        for url in (RUN + "?secret=1", RUN.replace(REPO, "other/repo")):
            with self.subTest(url=url):
                self.assertTrue(self.verify(run=url))

    def test_unapproved_workflow_path(self):
        self.assertTrue(self.verify(path="../.github/workflows/x.yml"))

    def test_different_workflow_same_sha(self):
        self.assertIn("path", " ".join(self.verify(fetch=faulty(
            {"path": ".github/workflows/echo-success.yml"}))))

    def test_wrong_repository(self):
        self.assertTrue(self.verify(fetch=faulty({"repository": {"full_name": "foreign/other"}})))

    def test_wrong_id(self):
        self.assertTrue(self.verify(fetch=faulty({"id": 1})))

    def test_boolean_id_rejected(self):
        self.assertTrue(self.verify(fetch=faulty({"id": True})))

    def test_replayed_sha(self):
        self.assertTrue(self.verify(fetch=faulty({"head_sha": BASE})))

    def test_success_conclusion_without_completed_status(self):
        self.assertTrue(self.verify(fetch=faulty({"status": "in_progress"})))

    def test_completed_failure(self):
        self.assertTrue(self.verify(fetch=faulty({"conclusion": "failure"})))

    def test_unauthorized_dispatch(self):
        self.assertTrue(self.verify(fetch=faulty({"event": "workflow_dispatch"})))

    def test_none_response_fails_closed(self):
        self.assertTrue(self.verify(fetch=lambda _: None))

    def test_json_error_fails_closed(self):
        self.assertTrue(self.verify(fetch=lambda _: (_ for _ in ()).throw(ValueError("bad JSON"))))

    def test_timeout_error_fails_closed(self):
        self.assertTrue(self.verify(fetch=lambda _: (_ for _ in ()).throw(TimeoutError("offline"))))

    def test_github_head_sha_from_fork_unrelated(self):
        self.assertTrue(self.verify(fetch=faulty({"head_sha": "1" * 40})))

    def test_cli_verified_run_uses_real_logic_not_hardcoded_assert(self):
        argv = ["gate", "--verify-run", RUN, "--source", SOURCE,
                "--baseline", BASE, "--workflow-path", WORKFLOW]
        with patch("sys.argv", argv), patch("scripts.jw_j3_origin_gate.github_json", canonical), \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(), 0)
            self.assertIn("no business assertions", output.getvalue())

    def test_cli_wrong_workflow_returns_nonzero(self):
        argv = ["gate", "--verify-run", RUN, "--source", SOURCE,
                "--baseline", BASE, "--workflow-path", ".github/workflows/other.yml"]
        with patch("sys.argv", argv), patch("scripts.jw_j3_origin_gate.github_json", canonical), \
             redirect_stdout(io.StringIO()):
            self.assertEqual(main(), 1)

    def test_cli_check_rejects_fabricated_full_pass(self):
        fabricated = {"project": "JARVIS-WORKS", "release": {"status": "REVIEW_CANDIDATE"}}
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "forged.json"
            file.write_text(json.dumps(fabricated))
            with patch("sys.argv", ["gate", "--check", str(file)]), \
                 redirect_stdout(io.StringIO()):
                self.assertEqual(main(), 1)


if __name__ == "__main__":
    unittest.main()
