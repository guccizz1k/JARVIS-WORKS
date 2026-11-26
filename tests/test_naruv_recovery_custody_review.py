import copy,hashlib,unittest
from datetime import datetime,timedelta,timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.naruv_recovery_custody_review import custody_evidence_message,review_custody_evidence

class RecoveryCustodyTests(unittest.TestCase):
    def setUp(self):
        self.keys=[Ed25519PrivateKey.generate() for _ in range(2)]
        self.pub=[k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw) for k in self.keys]
        now=datetime(2026,11,26,tzinfo=timezone.utc)
        expected={"old":{"state":"RECOVERY_ONLY","expected_assets":["old-a","old-b"]},"new":{"state":"STAGED","expected_assets":["new-a"]}}
        observations=[]
        for k,v in expected.items():
            observations.append(dict(key_id=k,state=v["state"],site_id="site-b",custody_receipt_sha256="b"*64,
                restores=[dict(asset_id=a,ciphertext_sha256=hashlib.sha256(a.encode()).hexdigest(),restore_evidence_sha256="c"*64,
                    full_authentication=True,restore_ok=True,network_isolated=True) for a in v["expected_assets"]]))
        trust=dict(primary_site="site-a",independent_site="site-b",inventory_fingerprint=hashlib.sha256(self.pub[0]).hexdigest(),
            custodian_fingerprint=hashlib.sha256(self.pub[1]).hexdigest())
        self.a=dict(tenant="ci-a",expected_keys=expected,observations=observations,trust=trust,challenge="d"*64,issued_at=now)
    def signed(self,a=None):
        a=copy.deepcopy(self.a if a is None else a);msg=custody_evidence_message(**a)
        return dict(a,as_of=a["issued_at"]+timedelta(seconds=1),inventory_public_key=self.pub[0],custodian_public_key=self.pub[1],
            inventory_signature=self.keys[0].sign(b"inventory:"+msg),custodian_signature=self.keys[1].sign(b"custodian:"+msg))
    def test_review_only(self):
        r=review_custody_evidence(**self.signed())
        self.assertEqual(r["restore_assertion_count"],3)
        for k in ("physical_custody_verified","independent_site_verified","key_activation_authorized","key_retirement_authorized","deletion_authorized","production_authorized"):
            self.assertIs(r[k],False)
    def test_missing_or_partial_restore(self):
        for field in ("full_authentication","restore_ok","network_isolated"):
            a=copy.deepcopy(self.a);a["observations"][0]["restores"][0][field]=False
            with self.subTest(field=field),self.assertRaises(ValueError):self.signed(a)
        a=copy.deepcopy(self.a);a["observations"][0]["restores"].pop()
        with self.assertRaises(ValueError):self.signed(a)
    def test_scope_and_key_state(self):
        for change in (dict(site_id="site-a"),dict(state="ACTIVE"),dict(key_id="unknown")):
            a=copy.deepcopy(self.a);a["observations"][0].update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):self.signed(a)
    def test_replay_and_signature_tamper(self):
        a=self.signed()
        for change in (dict(challenge="e"*64),dict(tenant="ci-b"),dict(as_of=a["issued_at"]+timedelta(minutes=11)),
                       dict(inventory_signature=a["custodian_signature"]),dict(custodian_public_key=self.pub[0])):
            with self.subTest(change=change),self.assertRaises(ValueError):review_custody_evidence(**dict(a,**change))
    def test_signer_site_collision(self):
        for change in (dict(independent_site="site-a"),dict(custodian_fingerprint=self.a["trust"]["inventory_fingerprint"])):
            a=copy.deepcopy(self.a);a["trust"].update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):self.signed(a)
    def test_digest_mutation(self):
        a=self.signed();a["observations"][0]["restores"][0]["ciphertext_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"CUSTODY_SIGNATURE"):review_custody_evidence(**a)

if __name__=="__main__":unittest.main()
