"""Post-A/B 65-table encrypted archive intake is strict and separate from pre-A/B."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import ci_cinema_pg_w as w
from scripts.pg_backup_v223 import BackupError

SIDE_TABLES=("cinema_pg_order_terms","cinema_pg_invoice_terms",
             "cinema_pg_payment_notes")
REQUIRED_FUNCS=(
    "jw_dev.cinema_pg_order_terms_set(text,text,date)",
    "jw_dev.cinema_pg_invoice_terms_set(text,text,date)",
    "jw_dev.cinema_pg_payment_note_set(text,text,text)",
)

class PostABRestoreTests(unittest.TestCase):
    def fixture(self):
        td=tempfile.TemporaryDirectory()
        archive=Path(td.name)/"20261108-000000Z-abcdef.jwpgbk"
        archive.write_bytes(b"encrypted-test-fixture-not-real-backup")
        tables=["cinema_pg_quotes",*SIDE_TABLES]+[
            f"synthetic_{i:02d}" for i in range(61)]
        self.assertEqual(len(tables),65)
        sig={
            "schema":"jw_dev",
            "tables":[[name,True,True] for name in tables],
            "functions":[[name,"0"*32] for name in REQUIRED_FUNCS],
            "rows":{tables[0]:[22,"0"*32]}
        }
        m={
            "real_source":True,"project_ref":w.PROJECT,"schema":"jw_dev",
            "source_fingerprint":w.POSTAB_FINGERPRINT,"snapshot_consistent":True,
            "source_backup_verdict":"EXPORT_ONLY_NOT_DR_PASS",
            "tables":65,"table_row_total":22,"server_major":17,
            "plain_sha256":"a"*64,"cipher_sha256":w.sha256(archive),
            "signature":sig,"roles":["jw_backup_ro","jw_cinema_writer"],
            "post_ab_validated":True,"backup_profile":"JW_V223_POST_AB_65",
        }
        return td,archive,m

    def test_65_profile_valid(self):
        td,archive,m=self.fixture()
        try:
            roles=w.check_manifest(m,archive,expected_fingerprint=w.POSTAB_FINGERPRINT,
                                   expected_tables=65,postab=True)
            self.assertEqual(roles,m["roles"])
        finally: td.cleanup()

    def test_old_62_profile_never_accepts_postab(self):
        td,archive,m=self.fixture()
        try:
            with self.assertRaises(BackupError):
                w.check_manifest(m,archive)
        finally: td.cleanup()

    def test_new_profile_rejects_old_table_count(self):
        td,archive,m=self.fixture()
        try:
            m["tables"]=62
            with self.assertRaisesRegex(BackupError,"IDENTITY"):
                w.check_manifest(m,archive,expected_fingerprint=w.POSTAB_FINGERPRINT,
                                 expected_tables=65,postab=True)
        finally: td.cleanup()

    def test_new_profile_rejects_preab_fingerprint(self):
        td,archive,m=self.fixture()
        try:
            m["source_fingerprint"]=w.FINGERPRINT
            with self.assertRaisesRegex(BackupError,"IDENTITY"):
                w.check_manifest(m,archive,expected_fingerprint=w.POSTAB_FINGERPRINT,
                                 expected_tables=65,postab=True)
        finally: td.cleanup()

    def test_new_profile_rejects_missing_postab_attestation(self):
        td,archive,m=self.fixture()
        try:
            for field in ("post_ab_validated","backup_profile"):
                with self.subTest(field=field):
                    current=m.pop(field)
                    with self.assertRaisesRegex(BackupError,"PROFILE"):
                        w.check_manifest(m,archive,expected_fingerprint=w.POSTAB_FINGERPRINT,
                                         expected_tables=65,postab=True)
                    m[field]=current
        finally: td.cleanup()

    def test_new_profile_rejects_missing_required_tables(self):
        td,archive,m=self.fixture()
        try:
            m["signature"]["tables"][1][0]="altered_table"
            with self.assertRaisesRegex(BackupError,"TABLES_MISSING"):
                w.check_manifest(m,archive,expected_fingerprint=w.POSTAB_FINGERPRINT,
                                 expected_tables=65,postab=True)
        finally: td.cleanup()

    def test_new_profile_rejects_missing_required_functions(self):
        td,archive,m=self.fixture()
        try:
            m["signature"]["functions"].pop()
            with self.assertRaisesRegex(BackupError,"FUNCTIONS_MISSING"):
                w.check_manifest(m,archive,expected_fingerprint=w.POSTAB_FINGERPRINT,
                                 expected_tables=65,postab=True)
        finally: td.cleanup()

    def test_cipher_digest_tampering_rejected(self):
        td,archive,m=self.fixture()
        try:
            archive.write_bytes(b"tampered")
            with self.assertRaisesRegex(BackupError,"ARCHIVE_DIGEST"):
                w.check_manifest(m,archive,expected_fingerprint=w.POSTAB_FINGERPRINT,
                                 expected_tables=65,postab=True)
        finally: td.cleanup()

    def test_restoration_profiles_have_separate_private_storage(self):
        self.assertNotEqual(w.PRIVATE,w.POSTAB_PRIVATE)
        self.assertEqual(w.STAGING,w.POSTAB_STAGING)
        self.assertNotEqual(w.FINGERPRINT,w.POSTAB_FINGERPRINT)

    def test_postab_main_forwards_explicit_profile(self):
        with patch.object(w,"verify_restore",return_value=0) as verify:
            self.assertEqual(w.main(profile="postab"),0)
            verify.assert_called_once_with(profile="postab")

    def test_unknown_profile_denied_without_db_access(self):
        with patch.dict(os.environ,{"CODESPACES":"true"}),\
             patch.object(w,"read_private_target") as read:
            with self.assertRaisesRegex(BackupError,"UNKNOWN_RESTORE_PROFILE"):
                w.verify_restore(profile="unknown")
            read.assert_not_called()

    def test_real_db_off_codespaces_refused(self):
        with patch.dict(os.environ,{"CODESPACES":"false"}),\
             patch.object(w,"read_private_target") as read:
            with self.assertRaises(BackupError):
                w.verify_restore(profile="postab")
            read.assert_not_called()

if __name__=="__main__":
    unittest.main()
