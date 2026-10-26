"""Opt-in REAL local Gitingest extraction test; no network or private files."""
import tempfile
import unittest
from pathlib import Path
from scripts.jw_jteam_external_sources import local_public_digest

class RealLocalGitingestPilot(unittest.TestCase):
    def test_actual_installed_gitingest_on_two_synthetic_files(self):
        with tempfile.TemporaryDirectory(prefix="jteam-public-fixture-") as folder:
            path = Path(folder)
            (path / "sample.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
            (path / "README.md").write_text("# Synthetic public fixture\n", encoding="utf-8")
            report = local_public_digest(path)
        self.assertEqual(report["file_count"], 2)
        self.assertGreater(report["candidate_characters"], 0)
        self.assertEqual(report["status"], "LOCAL_PUBLIC_PILOT_MEASURED")
        self.assertIs(report["remote_upload"], False)
        self.assertEqual(report["api_calls"], 0)
        self.assertEqual(report["release"], "BLOCKED")

if __name__ == "__main__":
    unittest.main()
