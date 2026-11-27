import tempfile,unittest
from pathlib import Path
from datetime import datetime,timedelta,timezone
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.naruv_recovery_custody_review import custody_evidence_message,sha
from app.naruv_operational_readiness import custody_trust_pin,review_and_consume_local_challenge
from app import naruv_hr_profile_envelope as paths

class ClockTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.journal=Path(self.tmp.name)
    def args(self,offset):
        keys=[Ed25519PrivateKey.generate() for _ in range(2)];pub=[k.public_key().public_bytes_raw() for k in keys]
        expected={k:dict(state=s,expected_assets={k:sha(k.encode())}) for k,s in [('old','RECOVERY_ONLY'),('new','STAGED')]}
        obs=[dict(key_id=k,state=v['state'],site_id='site-b',custody_receipt_sha256='b'*64,restores=[dict(asset_id=k,ciphertext_sha256=sha(k.encode()),restore_evidence_sha256='c'*64,full_authentication=True,restore_ok=True,network_isolated=True)]) for k,v in expected.items()]
        trust=dict(primary_site='site-a',independent_site='site-b',inventory_fingerprint=sha(pub[0]),custodian_fingerprint=sha(pub[1]))
        issued=datetime.now(timezone.utc)+timedelta(seconds=offset)
        a=dict(tenant='ci-a',expected_keys=expected,observations=obs,trust=trust,challenge='d'*64,issued_at=issued)
        msg=custody_evidence_message(**a)
        return dict(a,as_of=issued+timedelta(seconds=1),inventory_public_key=pub[0],custodian_public_key=pub[1],inventory_signature=keys[0].sign(b'inventory:'+msg),custodian_signature=keys[1].sign(b'custodian:'+msg),expected_trust_pin=custody_trust_pin(tenant='ci-a',expected_keys=expected,trust=trust),expected_challenge='d'*64)
    def consume(self,a):return review_and_consume_local_challenge(journal_dir=str(self.journal),**a)
    def denied(self,a):
        with self.assertRaisesRegex(ValueError,'CUSTODY_FRESHNESS'):self.consume(a)
        self.assertEqual(list(self.journal.iterdir()),[])
    def test_stale_with_backdated_caller(self):self.denied(self.args(-601))
    def test_future_with_future_caller(self):self.denied(self.args(60))
    def test_fresh_caller_time_ignored(self):
        a=self.args(-5);a['as_of']=a['issued_at']-timedelta(days=1)
        self.assertTrue(self.consume(a)['local_challenge_consumed'])
    def test_near_expiry(self):self.assertTrue(self.consume(self.args(-590))['local_challenge_consumed'])
    def test_replay(self):
        a=self.args(-5);self.consume(a)
        with self.assertRaisesRegex(ValueError,'CUSTODY_LOCAL_REPLAY'):self.consume(a)
    def test_concurrent(self):
        a=self.args(-5)
        def run(_):
            try:return self.consume(a)['local_challenge_consumed']
            except ValueError as e:return str(e)
        with ThreadPoolExecutor(8) as pool:r=list(pool.map(run,range(8)))
        self.assertEqual(r.count(True),1);self.assertEqual(r.count('CUSTODY_LOCAL_REPLAY'),7)
    def test_expiry_during_open(self):
        original=paths._open_trusted_key_directory
        import time
        a=self.args(-599.5)
        def open_slow(p):
            fd=original(p);time.sleep(0.8);return fd
        with patch.object(paths,'_open_trusted_key_directory',open_slow):self.denied(a)
if __name__=='__main__':unittest.main(verbosity=2)
