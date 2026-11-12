import importlib.util
import json
import hashlib
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("audit", HERE.parent / "scripts" / "issue142_local_inventory.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def git(repo, *args):
    p = subprocess.run(["git", "-C", str(repo), *args], check=True,
                       capture_output=True, text=True)
    return p.stdout.strip()


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.email", "audit@example.invalid")
        git(self.repo, "config", "user.name", "Audit")
        (self.repo / "README.md").write_text("baseline")
        git(self.repo, "add", "README.md")
        git(self.repo, "commit", "-qm", "baseline")

    def test_inventory_preserves_untracked_and_git_index(self):
        p = self.repo / "docs/review/issue142-evidence.json"
        p.parent.mkdir(parents=True)
        p.write_text('{"SECRET":"do-not-read"}', encoding="utf-8")
        p.chmod(0o600)
        before = git(self.repo, "status", "--porcelain=v1")
        report = audit.collect(self.repo)
        after = git(self.repo, "status", "--porcelain=v1")
        self.assertEqual(before, after)
        self.assertEqual(report["untracked_count"], 1)
        self.assertEqual(report["issue142_untracked_evidence_count"], 1)
        self.assertEqual(report["issue142_evidence_extensions"], {".json": 1})
        self.assertFalse(report["legacy_go_launcher_compatible"])
        self.assertNotIn("SECRET", json.dumps(report))
        self.assertNotIn("do-not-read", json.dumps(report))
        self.assertEqual(p.read_text(), '{"SECRET":"do-not-read"}')

    def test_legacy_branch_allowlist_only(self):
        git(self.repo, "checkout", "-qb", "jwb")
        safe = self.repo / ".github/supabase-root-2021.cer"
        safe.parent.mkdir(parents=True)
        safe.write_text("not-a-real-cert")
        safe.chmod(0o600)
        self.assertTrue(audit.collect(self.repo)["legacy_go_launcher_compatible"])
        x = self.repo / "docs/review/issue142-new.txt"
        x.parent.mkdir(parents=True)
        x.write_text("synthetic")
        self.assertFalse(audit.collect(self.repo)["legacy_go_launcher_compatible"])

    def test_detect_symlink_and_insecure_mode_without_opening(self):
        x = self.repo / "docs/review/issue142-insecure.txt"
        x.parent.mkdir(parents=True)
        x.write_text("synthetic")
        x.chmod(0o644)
        y = self.repo / "docs/review/issue142-link"
        y.symlink_to(x)
        result = audit.collect(self.repo)
        self.assertEqual(result["untracked_symlinks_count"], 1)
        self.assertGreaterEqual(result["untracked_group_or_world_permission_count"], 1)

    def test_porcelain_nul_names_and_rename(self):
        content = b"?? docs/review/issue142-a\nfile.json\0R  new name\0old name\0"
        self.assertEqual(audit.parse_porcelain_z(content),
                         [("??", "docs/review/issue142-a\nfile.json"), ("R ", "new name")])


    def test_exact_index_bytes_not_rewritten(self):
        # The read-only scanner must not refresh or write .git/index.
        index = self.repo / ".git" / "index"
        before = (hashlib.sha256(index.read_bytes()).digest(), index.stat().st_mtime_ns)
        result = audit.collect(self.repo)
        after = (hashlib.sha256(index.read_bytes()).digest(), index.stat().st_mtime_ns)
        self.assertEqual(before, after)
        self.assertEqual(result["tracked_changes_count"], 0)

    def test_tracked_modifications_are_counted_without_content(self):
        (self.repo / "README.md").write_text("VERY PRIVATE SYNTHETIC WORD")
        result = audit.collect(self.repo)
        self.assertEqual(result["tracked_changes_count"], 1)
        self.assertNotIn("VERY PRIVATE", json.dumps(result))

    def test_malformed_porcelain_rejected_without_partial_output(self):
        with self.assertRaisesRegex(RuntimeError, "UNEXPECTED_PORCELAIN_FORMAT"):
            audit.parse_porcelain_z(b"bad input\x00")
        with self.assertRaisesRegex(RuntimeError, "TRUNCATED_RENAME_ENTRY"):
            audit.parse_porcelain_z(b"R  new name\x00")

    def test_branch_and_commits(self):
        obj = audit.collect(self.repo)
        self.assertEqual(len(obj["head"]), 40)
        self.assertFalse(obj["codespaces_archive_offsite_proven"])
        self.assertFalse(obj["independent_recovery_key_proven"])


if __name__ == "__main__":
    unittest.main()
