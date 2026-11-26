import copy,unittest
from app.naruv_b2_upload_policy import upload_policy_plan,verify_uploaded_metadata
from app.naruv_b2_retention_journal import DAY

class UploadPolicyTests(unittest.TestCase):
    def setUp(self):
        self.ts=1795500000000
        self.plan=upload_policy_plan(planned_at_ms=self.ts,max_upload_ms=120000,max_clock_skew_ms=60000,
            approved_until_ms=self.ts+30*DAY+180000)
        self.expected=dict(bucketId="b",fileName="synthetic/a",fileId="v1",contentLength=123,contentSha1="a"*40)
        self.info=dict(self.expected,action="upload",uploadTimestamp=self.ts+647,
            serverSideEncryption={"mode":"SSE-B2","algorithm":"AES256"},
            fileRetention={"isClientAuthorizedToRead":True,"value":{"mode":"compliance","retainUntilTimestamp":self.plan["retain_until_ms"]}})
    def verify(self,info=None,plan=None,now=None,expected=None):
        return verify_uploaded_metadata(plan=self.plan if plan is None else plan,
            expected=self.expected if expected is None else expected,info=self.info if info is None else info,
            now_ms=self.ts+180001 if now is None else now)
    def test_previous_subsecond_failure(self):
        out=self.verify()
        self.assertTrue(out["retention_at_least_30days"])
        self.assertFalse(out["ciphertext_verified"]);self.assertFalse(out["retry_authorized"])
    def test_exact_limit(self):
        self.info["uploadTimestamp"]=self.ts+180000
        self.assertTrue(self.verify()["retention_at_least_30days"])
        self.info["uploadTimestamp"]+=1
        with self.assertRaisesRegex(ValueError,"UPLOAD_RETENTION_SHORTFALL"):self.verify()
    def test_approval_ceiling(self):
        with self.assertRaisesRegex(ValueError,"UPLOAD_RETENTION_APPROVAL"):
            upload_policy_plan(planned_at_ms=self.ts,max_upload_ms=120000,max_clock_skew_ms=60000,approved_until_ms=self.ts+30*DAY)
    def test_tampered_plan(self):
        for change in (dict(retain_until_ms=self.plan["retain_until_ms"]+1),dict(upload_authorized=True),dict(mode="governance")):
            with self.subTest(change=change),self.assertRaises(ValueError):self.verify(plan=dict(self.plan,**change))
    def test_id_and_metadata(self):
        for change in (dict(fileId="v2"),dict(bucketId="other"),dict(action="hide"),dict(contentLength=True),dict(contentSha1="b"*40),
                       dict(serverSideEncryption={"mode":"none"}),dict(uploadTimestamp=self.ts-60001)):
            with self.subTest(change=change),self.assertRaises(ValueError):self.verify(info=dict(self.info,**change))
    def test_retention_access_and_exact_target(self):
        for change in (dict(isClientAuthorizedToRead=False),dict(value={"mode":"governance","retainUntilTimestamp":self.plan["retain_until_ms"]}),
                       dict(value={"mode":"compliance","retainUntilTimestamp":self.plan["retain_until_ms"]+1})):
            row=copy.deepcopy(self.info);row["fileRetention"].update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):self.verify(info=row)
    def test_expired_and_future_upload(self):
        for now in (self.ts,self.plan["retain_until_ms"]):
            with self.subTest(now=now),self.assertRaises(ValueError):self.verify(now=now)

if __name__=="__main__":unittest.main()
