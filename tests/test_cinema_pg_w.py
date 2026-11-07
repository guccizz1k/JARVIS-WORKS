"""Independent restore intake/crypto tests; synthetic only, never accesses Supabase."""
from __future__ import annotations
import base64
import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import ci_cinema_pg_w as w
from scripts.pg_backup_v223 import BackupError, encrypt_file

class RestoreOnlySafety(unittest.TestCase):
    def fixture(self, directory):
        root=Path(directory)
        label="20261107-114900Z-abcdef"
        source=root/"source"
        source.write_bytes(b"synthetic test data only" * 800)
        meta=root/"meta"
        meta.write_bytes(b'{"kind":"synthetic"}')
        key=bytes(range(32))
        arc=root/(label+".jwpgbk")
        m=root/(label+".manifest.jwpgbk")
        k=root/(label+".key")
        encrypt_file(source,arc,key)
        encrypt_file(meta,m,key)
        k.write_text(base64.urlsafe_b64encode(key).decode("ascii")+"\n")
        k.chmod(0o600)
        return arc,m,k,key

    def test_matching_triplet(self):
        with tempfile.TemporaryDirectory() as d:
            a,m,k,_=self.fixture(d)
            with patch.object(w,"STAGING",Path(d)):
                self.assertEqual(w.find_input(),(a,m,k))

    def test_missing_key_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            a,m,k,_=self.fixture(d)
            k.unlink()
            with patch.object(w,"STAGING",Path(d)):
                with self.assertRaises(BackupError):
                    w.find_input()

    def test_secret_never_accepted_from_git_trackable_directory(self):
        with tempfile.TemporaryDirectory(dir=str(w.ROOT)) as d:
            path=Path(d)/"test.key"
            path.write_text("fake")
            with patch.object(w.subprocess,"run") as run:
                run.return_value.returncode=1
                with self.assertRaises(BackupError):
                    w.private_transfer([path])

    def test_key_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            _,_,k,key=self.fixture(d)
            self.assertEqual(w.read_key(k),key)
            k.chmod(0o644)
            with self.assertRaises(BackupError):
                w.read_key(k)

    def test_source_identity_mismatch_denied(self):
        with tempfile.TemporaryDirectory() as d:
            a,_,_,_=self.fixture(d)
            with self.assertRaisesRegex(BackupError,"SOURCE_MANIFEST_IDENTITY"):
                w.check_manifest({"real_source":True,"project_ref":"other"},a)

    def test_valid_source_signature_constraints(self):
        with tempfile.TemporaryDirectory() as d:
            a,_,_,_=self.fixture(d)
            sig={"schema":"jw_dev","tables":[["t"+str(i),True,True] for i in range(62)],
                 "rows":{"t0":[22,"x"]}}
            m={"real_source":True,"project_ref":w.PROJECT,"schema":w.SCHEMA,
               "source_fingerprint":w.FINGERPRINT,"snapshot_consistent":True,
               "source_backup_verdict":"EXPORT_ONLY_NOT_DR_PASS",
               "tables":62,"table_row_total":22,"server_major":17,
               "plain_sha256":"a"*64,"cipher_sha256":w.sha256(a),
               "signature":sig,"roles":["jw_backup_ro","jw_cinema_owner"]}
            self.assertEqual(w.check_manifest(m,a),["jw_backup_ro","jw_cinema_owner"])
            m["roles"]=["jw_bad;DROP TABLE x"]
            with self.assertRaisesRegex(BackupError,"ROLE_NAMES"):
                w.check_manifest(m,a)

    def test_real_aes_negative_cases(self):
        with tempfile.TemporaryDirectory() as d:
            a,m,k,key=self.fixture(d)
            result=w.negatives(a,key,Path(d))
            self.assertEqual(result,{"tamper_rejected":True,
                                     "truncation_rejected":True,
                                     "wrong_key_rejected":True})

    def test_main_without_approved_codespace_never_opens_target(self):
        with patch.dict(os.environ,{"CODESPACES":"false"}), \
             patch.object(w,"read_private_target") as target:
            self.assertEqual(w.main(),2)
            target.assert_not_called()

    def test_restorer_password_not_in_command_args(self):
        import subprocess
        dsn="postgresql://postgres:secret_pass@127.0.0.1:55432/postgres"
        with patch.object(w.subprocess,"run",
                          return_value=subprocess.CompletedProcess([],0,stdout="",stderr="")) as run:
            self.assertTrue(w.run_pg(["pg_restore","--version"],dsn))
        args,kwargs=run.call_args
        self.assertNotIn("secret_pass",str(args))
        self.assertEqual(kwargs["env"]["PGPASSWORD"],"secret_pass")
        self.assertEqual(kwargs["env"]["PGHOST"],"127.0.0.1")

if __name__=="__main__":
    unittest.main()
