import hashlib,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from app.naruv_b2_upload_execution import DisposableB2,execute_fixture_upload
from app.naruv_b2_retention_journal import DAY

class UploadExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/"journal"
        self.ts=1795500000000;self.times=iter([self.ts,self.ts+647,self.ts+648])
        self.clock=lambda:next(self.times)
        self.p=DisposableB2("fixture",self.clock);self.raw=b"synthetic ciphertext only"
        self.args=dict(provider=self.p,clock=self.clock,journal=self.path,
            scope={"bucket_id":"fixture","name":"synthetic/a.jwpgbk"},raw=self.raw,
            expected_sha256=hashlib.sha256(self.raw).hexdigest(),max_upload_ms=120000,
            max_clock_skew_ms=60000,approved_until_ms=self.ts+30*DAY+180000)
    def run_upload(self,**change):return execute_fixture_upload(**dict(self.args,**change))
    def stages(self):return [json.loads(l)["stage"] for l in self.path.read_text().splitlines()]
    def test_end_to_end(self):
        r=self.run_upload();self.assertTrue(r["fixture_ciphertext_verified"]);self.assertFalse(r["remote_write"])
        self.assertEqual(self.stages(),["attempt","ack","verified","complete"]);self.assertEqual(self.p.calls,1)
        with self.assertRaises(ValueError):self.run_upload()
        self.assertEqual(self.p.calls,1)
    def test_no_retry_after_uncertain_ack(self):
        original=self.p.upload
        def lost(*a):original(*a);raise TimeoutError()
        with patch.object(self.p,"upload",side_effect=lost),self.assertRaises(TimeoutError):self.run_upload()
        self.assertEqual(self.stages(),["attempt"])
        with self.assertRaises(ValueError):self.run_upload()
        self.assertEqual(self.p.calls,1)
    def test_prior_journal_no_write(self):
        self.path.write_text("attempt")
        with self.assertRaises(FileExistsError):self.run_upload()
        self.assertEqual(self.p.calls,0)
    def test_shortfall_never_complete(self):
        self.times=iter([self.ts,self.ts+180001,self.ts+180002])
        with self.assertRaisesRegex(ValueError,"UPLOAD_RETENTION_SHORTFALL"):self.run_upload()
        self.assertEqual(self.stages(),["attempt","ack"])
    def test_readback_mismatch(self):
        with patch.object(self.p,"read_bytes",return_value=b"wrong"),self.assertRaisesRegex(ValueError,"READBACK_MISMATCH"):self.run_upload()
        self.assertEqual(self.stages(),["attempt","ack"])
    def test_scope_rejected_before_attempt(self):
        for change in (dict(provider=object()),dict(scope={"bucket_id":"wrong","name":"synthetic/a.jwpgbk"}),
                       dict(expected_sha256="0"*64),dict(approved_until_ms=self.ts+30*DAY)):
            with self.subTest(change=change),self.assertRaises(ValueError):self.run_upload(**change)
        self.assertFalse(self.path.exists());self.assertEqual(self.p.calls,0)
