import base64
import unittest
from app.naruv_hr_profile_envelope import seal_profile,open_profile,ProfileBlocked

class HRProfileEnvelope(unittest.TestCase):
    def setUp(self):
        self.scope=dict(tenant="ci-a",worker="pilot-worker",revision="r1",key_id="test-key",key=b"x"*32)
        self.profile=dict(display_name="Synthetic Worker",work_email="worker@example.invalid",employment_start="2026-01-01")
    def test_roundtrip_random_nonce_and_no_plaintext(self):
        a=seal_profile(**self.scope,profile=self.profile)
        b=seal_profile(**self.scope,profile=self.profile)
        self.assertNotEqual(a["nonce"],b["nonce"])
        self.assertNotEqual(a["ciphertext"],b["ciphertext"])
        self.assertEqual(open_profile(**self.scope,envelope=a),self.profile)
        self.assertNotIn(self.profile["work_email"].encode(),base64.b64decode(a["ciphertext"]))
    def test_tenant_worker_revision_key_and_tamper(self):
        a=seal_profile(**self.scope,profile=self.profile)
        for change in ({"tenant":"ci-b"},{"worker":"other"},{"revision":"r2"},{"key_id":"other"},{"key":b"y"*32}):
            with self.subTest(change=change),self.assertRaisesRegex(ProfileBlocked,"HR_PROFILE_INVALID"):
                open_profile(**dict(self.scope,**change),envelope=a)
        c=bytearray(base64.b64decode(a["ciphertext"]));c[-1]^=1
        for bad in (dict(a,ciphertext=base64.b64encode(c).decode()),dict(a,nonce="!"*16),dict(a,v=True),dict(a,extra="unknown")):
            with self.assertRaises(ProfileBlocked):open_profile(**self.scope,envelope=bad)
    def test_minimum_fields_and_strict_validation(self):
        for bad in (dict(self.profile,rrn="synthetic-not-accepted"),
                    dict(self.profile,bank_account="synthetic-not-accepted"),
                    dict(self.profile,display_name="123456"),
                    dict(self.profile,display_name="Name\nInjected"),
                    dict(self.profile,work_email="invalid"),
                    dict(self.profile,employment_start="2026-02-30")):
            with self.assertRaises(ProfileBlocked):seal_profile(**self.scope,profile=bad)
    def test_explicit_key_rotation_reencryption(self):
        a=seal_profile(**self.scope,profile=self.profile)
        new=dict(self.scope,key_id="test-key-2",key=b"z"*32,revision="r2")
        b=seal_profile(**new,profile=open_profile(**self.scope,envelope=a))
        self.assertEqual(open_profile(**new,envelope=b),self.profile)
        with self.assertRaises(ProfileBlocked):open_profile(**self.scope,envelope=b)

    def test_revision_sql_source_integrity(self):
        # Early detection of accidental source duplication; PostgreSQL execution
        # remains the authoritative syntax and behavior acceptance.
        from pathlib import Path
        sql=(Path(__file__).resolve().parents[1]/"db/review/naruv_hr_profile_ci.sql").read_text()
        self.assertEqual(sql.count("CREATE FUNCTION naruv_draft.profile_envelope("),1)
        self.assertEqual(sql.count("RETURN jsonb_build_object('status','SEALED'"),1)
        self.assertEqual(sql.count("RESET ROLE;"),1)
        self.assertEqual(sql.count("END $$;"),2)
        self.assertIn("IF p_expected !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR p_expected=p_revision THEN",sql)
        self.assertTrue(sql.rstrip().endswith("RESET ROLE;"))


    def test_rotation_helper_key_reuse_tamper_and_recovery(self):
        from app.naruv_hr_profile_envelope import rotate_profile
        a=seal_profile(**self.scope,profile=self.profile)
        args=dict(tenant="ci-a",worker="pilot-worker",old_revision="r1",new_revision="r2",
                  old_key_id="test-key",new_key_id="new-key",old_key=b"x"*32,new_key=b"z"*32,envelope=a)
        b=rotate_profile(**args)
        self.assertEqual(open_profile(**dict(self.scope,revision="r2",key_id="new-key",key=b"z"*32),envelope=b),self.profile)
        self.assertEqual(open_profile(**self.scope,envelope=a),self.profile)
        for change in ({"new_key":b"x"*32},{"new_key_id":"test-key"},{"new_revision":"r1"},
                       {"old_key":b"y"*32},{"tenant":"ci-b"},{"envelope":dict(a,nonce="!"*16)}):
            with self.subTest(change=change),self.assertRaises(ProfileBlocked):rotate_profile(**dict(args,**change))

    def test_retention_decision_boundary_and_hold(self):
        from app.naruv_hr_profile_envelope import retention_decision
        from datetime import datetime,timezone,timedelta
        now=datetime(2026,11,26,tzinfo=timezone.utc)
        args=dict(tenant="ci-a",worker="pilot-worker",revision="r1",as_of=now,purpose_closed=True,
                  legal_review_complete=True,legal_hold=False,retain_until=now,approval_sha256="a"*64)
        for change,expected in (({},"PURGE_CANDIDATE_ONLY"),({"purpose_closed":False},"ACTIVE_PURPOSE"),
                ({"legal_review_complete":False},"REVIEW_REQUIRED"),({"approval_sha256":None},"REVIEW_REQUIRED"),
                ({"legal_hold":True},"LEGAL_HOLD_SEPARATE_STORAGE_REQUIRED"),
                ({"retain_until":now+timedelta(microseconds=1)},"RETAIN_SEPARATELY")):
            r=retention_decision(**dict(args,**change))
            self.assertEqual(r["status"],expected)
            self.assertFalse(r["deletion_authorized"]);self.assertFalse(r["production_authorized"])
        for change in ({"as_of":now.replace(tzinfo=None)},{"legal_hold":1},{"approval_sha256":"bad"}):
            with self.assertRaises(ProfileBlocked):retention_decision(**dict(args,**change))
