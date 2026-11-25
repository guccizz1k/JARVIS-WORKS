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
