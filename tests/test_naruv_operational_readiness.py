import tempfile,unittest,os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.naruv_operational_readiness import prepare_upload_scope,custody_trust_pin,review_and_consume_local_challenge
from app.naruv_b2_retention_journal import DAY
from tests.test_naruv_b2_native_upload import encrypted
from tests.test_naruv_recovery_custody_review import RecoveryCustodyTests

class OperationalReadinessTests(unittest.TestCase):
    def test_unsigned_upload_proposal(self):
        k=AESGCM.generate_key(256);raw=encrypted(k,[b"PGDMP synthetic"])
        ts=1795500000000
        a=dict(account_id="account",bucket_id="bucket",bucket_name="private",operation_id="a"*32,
            raw=raw,archive_key=k,planned_at_ms=ts,approval_expires_ms=ts+3600000,
            approved_until_ms=ts+30*DAY+180000,max_upload_ms=120000,max_clock_skew_ms=60000)
        r=prepare_upload_scope(**a)
        self.assertFalse(r["upload_authorized"]);self.assertFalse(r["remote_write"])
        self.assertEqual(r["authenticated_chunks"],1)
        for change in (dict(approval_expires_ms=ts+6*3600000),dict(approved_until_ms=ts+30*DAY),
            dict(operation_id="old"),dict(archive_key=AESGCM.generate_key(256))):
            with self.subTest(change=list(change)),self.assertRaises(ValueError):prepare_upload_scope(**dict(a,**change))
    def custody(self):
        fixture=RecoveryCustodyTests();fixture.setUp();a=fixture.signed()
        return dict(expected_trust_pin=custody_trust_pin(tenant=a["tenant"],expected_keys=a["expected_keys"],trust=a["trust"]),
            expected_challenge=a["challenge"],**a)
    def test_concurrent_replay_and_no_authority(self):
        a=self.custody()
        with tempfile.TemporaryDirectory() as d:
            def run(_):
                try:return review_and_consume_local_challenge(journal_dir=d,**a)
                except ValueError as e:return str(e)
            with ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(run,range(8)))
            good=[r for r in results if type(r) is dict]
            self.assertEqual(len(good),1);self.assertEqual(results.count("CUSTODY_LOCAL_REPLAY"),7)
            self.assertFalse(good[0]["physical_custody_verified"]);self.assertFalse(good[0]["production_authorized"])
            self.assertFalse(good[0]["distributed_challenge_consumption_verified"])
            self.assertEqual(len(list(Path(d).iterdir())),1)
    def test_invalid_trust_or_signature_does_not_consume(self):
        a=self.custody()
        with tempfile.TemporaryDirectory() as d:
            for change in (dict(expected_trust_pin="0"*64),dict(expected_challenge="0"*64),dict(inventory_signature=b"x"*64)):
                with self.subTest(change=list(change)),self.assertRaises(ValueError):review_and_consume_local_challenge(journal_dir=d,**dict(a,**change))
            self.assertEqual(list(Path(d).iterdir()),[])
            os.chmod(d,0o755)
            with self.assertRaisesRegex(ValueError,"CUSTODY_LOCAL_DIRECTORY"):review_and_consume_local_challenge(journal_dir=d,**a)
            self.assertEqual(list(Path(d).iterdir()),[])
