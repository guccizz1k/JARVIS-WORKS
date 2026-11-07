"""Fail-closed tests for existing evidence inspection, without secret or DB access."""
from __future__ import annotations
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import ci_cinema_pg_z as z
from scripts.pg_backup_v223 import BackupError

class SafeMismatchEvidence(unittest.TestCase):
    def make_case(self, d, label="acl:some_table"):
        directory=Path(d)
        directory.chmod(0o700)
        key="20261107-114904Z-ece668"
        archive=directory/(key+".jwpgbk")
        archive.write_bytes(b"encrypted dummy byte stream")
        data=dict(
            source_real=True,verified_disposable_pg17=True,
            schema_fingerprint=z.w.FINGERPRINT,verdict="FAIL",
            table_count=62,row_count=22,mismatch_count=1,
            mismatch_labels=[label],
            encrypted_archive_sha256=z.w.sha256(archive))
        evidence=directory/(key+".restore-report.json")
        evidence.write_text(json.dumps(data))
        evidence.chmod(0o600)
        return archive,evidence,data

    def test_exact_label_returned_no_db_or_decryption(self):
        with tempfile.TemporaryDirectory() as d:
            self.make_case(d)
            with patch.dict(os.environ,{"CODESPACES":"true"}),\
                 patch.object(z.w,"PRIVATE",Path(d)),\
                 patch.object(z.w,"ROOT",Path.cwd()),\
                 patch.object(z.w,"decrypt_file") as decrypt,\
                 patch.object(z.w,"ensure_local_target") as server:
                self.assertEqual(z.read_report()["mismatch"],"acl:some_table")
                decrypt.assert_not_called()
                server.assert_not_called()

    def test_off_codespaces_denied(self):
        with patch.dict(os.environ,{"CODESPACES":"false"}):
            with self.assertRaises(BackupError):
                z.read_report()

    def test_report_must_match_archive_digest(self):
        with tempfile.TemporaryDirectory() as d:
            archive,_,_=self.make_case(d)
            archive.write_bytes(b"tampered")
            with patch.dict(os.environ,{"CODESPACES":"true"}),\
                 patch.object(z.w,"PRIVATE",Path(d)),\
                 patch.object(z.w,"ROOT",Path.cwd()):
                with self.assertRaisesRegex(BackupError,"DIGEST"):
                    z.read_report()

    def test_unsafe_label_denied(self):
        with tempfile.TemporaryDirectory() as d:
            self.make_case(d,label="acl:secret=somepassword\n")
            with patch.dict(os.environ,{"CODESPACES":"true"}),\
                 patch.object(z.w,"PRIVATE",Path(d)),\
                 patch.object(z.w,"ROOT",Path.cwd()):
                with self.assertRaisesRegex(BackupError,"LABEL"):
                    z.read_report()

    def test_fail_to_pass_tampered_evidence_denied(self):
        with tempfile.TemporaryDirectory() as d:
            _,evidence,data=self.make_case(d)
            data["verdict"]="PASS"
            evidence.write_text(json.dumps(data))
            with patch.dict(os.environ,{"CODESPACES":"true"}),\
                 patch.object(z.w,"PRIVATE",Path(d)),\
                 patch.object(z.w,"ROOT",Path.cwd()):
                with self.assertRaisesRegex(BackupError,"STATE"):
                    z.read_report()

    def test_world_readable_evidence_denied(self):
        with tempfile.TemporaryDirectory() as d:
            _,evidence,_=self.make_case(d)
            evidence.chmod(0o644)
            with patch.dict(os.environ,{"CODESPACES":"true"}),\
                 patch.object(z.w,"PRIVATE",Path(d)),\
                 patch.object(z.w,"ROOT",Path.cwd()):
                with self.assertRaisesRegex(BackupError,"PERMISSIONS"):
                    z.read_report()

    def test_multiple_reports_denied(self):
        with tempfile.TemporaryDirectory() as d:
            _,evidence,_=self.make_case(d)
            (Path(d)/"other.restore-report.json").write_text("{}")
            with patch.dict(os.environ,{"CODESPACES":"true"}),\
                 patch.object(z.w,"PRIVATE",Path(d)),\
                 patch.object(z.w,"ROOT",Path.cwd()):
                with self.assertRaisesRegex(BackupError,"ONE_LOCAL"):
                    z.read_report()

if __name__=="__main__":
    unittest.main()
