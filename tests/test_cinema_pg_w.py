"""Independent restore intake/crypto tests; synthetic only, never accesses Supabase."""
from __future__ import annotations
import base64
import hashlib
import io
import json
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

    def test_private_archive_can_resume_without_reupload(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            staging=root/"staged"
            staging.mkdir()
            private=root/"private"
            private.mkdir()
            a,m,k,_=self.fixture(private)
            with patch.object(w,"STAGING",staging), patch.object(w,"PRIVATE",private), \
                 patch.object(w,"private_transfer") as move:
                self.assertEqual(w.find_or_import_archive(),(a,m,k))
                move.assert_not_called()

    def test_partial_staging_never_falls_back_to_private(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            staging=root/"staged"
            staging.mkdir()
            private=root/"private"
            private.mkdir()
            self.fixture(private)
            (staging/"orphan.key").write_text("not an archive")
            with patch.object(w,"STAGING",staging), patch.object(w,"PRIVATE",private):
                with self.assertRaisesRegex(BackupError,"STAGING_PARTIAL_ARCHIVE"):
                    w.find_or_import_archive()

    def test_new_staged_archive_imported_once_only(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            staging=root/"staged"
            staging.mkdir()
            private=root/"private"
            private.mkdir()
            triplet=self.fixture(staging)
            with patch.object(w,"STAGING",staging), patch.object(w,"PRIVATE",private), \
                 patch.object(w,"private_transfer",return_value=triplet[:3]) as move:
                self.assertEqual(w.find_or_import_archive(),triplet[:3])
                move.assert_called_once()

    def test_schema_function_only_grantees_are_source_verified(self):
        self.assertEqual(
            set(w.SOURCE_VERIFIED_SCHEMA_FUNCTION_ONLY_GRANTEES),
            {"jw_auth_stage_v85", "jw_dev_import_review_executor_v201"})
        self.assertTrue(all(name.startswith("jw_") for name in
                            w.SOURCE_VERIFIED_SCHEMA_FUNCTION_ONLY_GRANTEES))

    def test_pg_restore_error_is_redacted_to_stable_category(self):
        import subprocess
        dsn="postgresql://postgres:secret_pass@127.0.0.1:55432/postgres"
        errors=[
            ('pg_restore: ERROR: role "jw_auth_stage_v85" does not exist',
             "MISSING_GRANTEE_ROLE"),
            ('pg_restore: ERROR: permission denied for schema jw_dev',
             "PERMISSION_DENIED"),
            ('pg_restore: ERROR: function extensions.hmac(text,text,text) does not exist',
             "FUNCTION_DEPENDENCY_MISSING"),
            ('pg_restore: ERROR: secret-host result',
             "OTHER_PG_RESTORE_ERROR"),
        ]
        for message,expected in errors:
            proc=subprocess.CompletedProcess([],1,stdout="",stderr=message)
            with patch.object(w.subprocess,"run",return_value=proc):
                outcome=w.run_restore_with_reason(
                    ["pg_restore","--exit-on-error"],dsn,db="postgres",seconds=10)
            self.assertEqual(outcome,expected)
            self.assertNotIn("jw_auth_stage",outcome)
            self.assertNotIn("secret",outcome)

    def test_diagnostic_does_not_allow_arbitrary_command(self):
        from scripts.pg_backup_v223 import BackupError
        with self.assertRaises(BackupError):
            w.run_restore_with_reason(
                ["psql","--exit-on-error"],"bad",db="postgres",seconds=10)

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


    def inspect_fixture(self, **changes):
        c = {
            "Name": "/jw-v223-restore",
            "Config": {"Image": "postgres:17"},
            "HostConfig": {
                "Privileged": False, "NetworkMode": "default",
                "RestartPolicy": {"Name": "no"},
                "PortBindings": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "55432"}]},
            },
            "Mounts": [{"Type": "volume"}],
            "State": {"Running": False},
        }
        for key,value in changes.items():
            c[key]=value
        return json.dumps([c])

    def test_stopped_container_identity_verified_without_start(self):
        import subprocess
        output=subprocess.CompletedProcess([],0,stdout=self.inspect_fixture(),stderr="")
        with patch.object(w.subprocess,"run",return_value=output) as runner:
            self.assertIs(w.inspect_disposable_container(),False)
        runner.assert_called_once_with(
            ["docker","container","inspect","jw-v223-restore"],
            capture_output=True,text=True,check=False,timeout=10)

    def test_wrong_or_public_container_port_never_accepted(self):
        import subprocess
        data=json.loads(self.inspect_fixture())
        data[0]["HostConfig"]["PortBindings"]["5432/tcp"][0]["HostIp"]="0.0.0.0"
        with patch.object(w.subprocess,"run",return_value=subprocess.CompletedProcess([],0,stdout=json.dumps(data),stderr="")):
            with self.assertRaisesRegex(BackupError,"IDENTITY_UNVERIFIED"):
                w.inspect_disposable_container()

    def test_foreign_container_or_bind_mount_refused(self):
        import subprocess
        for bad in ({"Config":{"Image":"postgres:16"}},
                    {"Mounts":[{"Type":"bind","Source":"/sensitive"}]}):
            with patch.object(w.subprocess,"run",return_value=subprocess.CompletedProcess(
                    [],0,stdout=self.inspect_fixture(**bad),stderr="")):
                with self.assertRaisesRegex(BackupError,"IDENTITY_UNVERIFIED"):
                    w.inspect_disposable_container()

    def test_valid_stopped_container_restart_rechecks_marker(self):
        import psycopg
        import subprocess
        class Connected:
            def __enter__(self):
                return self
            def __exit__(self,*args):
                return False
        with patch("psycopg.connect",side_effect=[
                  psycopg.OperationalError("old target paused"),Connected()]), \
             patch.object(w,"inspect_disposable_container",return_value=False), \
             patch.object(w,"verify_ephemeral_target") as marker, \
             patch.object(w.subprocess,"run",return_value=subprocess.CompletedProcess([],0,stdout="",stderr="")) as run:
            self.assertEqual(w.ensure_local_target("local://dummy","private-token"),"RESTARTED_MARKER_VERIFIED")
            run.assert_called_once_with(["docker","start","jw-v223-restore"],
                                        capture_output=True,text=True,timeout=25,check=False)
            marker.assert_called_once()

    def test_unreachable_running_container_refuses_restart(self):
        import psycopg
        with patch("psycopg.connect",side_effect=psycopg.OperationalError("unreachable")), \
             patch.object(w,"inspect_disposable_container",return_value=True), \
             patch.object(w.subprocess,"run") as subprocess_run:
            with self.assertRaisesRegex(BackupError,"RUNNING_LOCAL_DB_UNREACHABLE"):
                w.ensure_local_target("local://dummy","token")
            subprocess_run.assert_not_called()

    def test_invalid_target_marker_stops_before_docker(self):
        class Connected:
            def __enter__(self):
                return self
            def __exit__(self,*args):
                return False
        with patch("psycopg.connect",return_value=Connected()), \
             patch.object(w,"verify_ephemeral_target",
                          side_effect=BackupError("BLOCKED_TARGET_NOT_PROVEN")), \
             patch.object(w,"inspect_disposable_container") as inspect:
            with self.assertRaises(BackupError):
                w.ensure_local_target("local://dummy","token")
            inspect.assert_not_called()

    def test_target_failure_never_moves_uploaded_archive(self):
        with patch.dict(os.environ,{"CODESPACES":"true"}), \
             patch.object(w,"read_private_target",return_value={
                "JW_PG_TARGET_ADMIN_DSN":"local://dummy",
                "JW_PG_TARGET_EPHEMERAL_TOKEN":"fake"}), \
             patch.object(w,"ensure_local_target",
                          side_effect=BackupError("BLOCKED_LOCAL_DB_UNREACHABLE_AFTER_RESTART")), \
             patch.object(w,"private_transfer") as moved:
            with self.assertRaises(BackupError):
                w.verify_restore()
            moved.assert_not_called()

if __name__=="__main__":
    unittest.main()
