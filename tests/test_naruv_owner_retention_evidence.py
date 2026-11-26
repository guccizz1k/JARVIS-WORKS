import hashlib,json,os,tempfile,unittest
from pathlib import Path
from scripts.naruv_owner_retention_evidence import check,secure_read,JOURNAL_NAME
from app.naruv_b2_retention_journal import reconcile,DAY

class OwnerRetentionEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name)
        self.groups=(("a/","one","scope1"),("b/","two","scope2"))
        self.plan=[]
        for group,filename,scope in self.groups:
            records={}
            for i in range(11):
                n=group+str(i).zfill(2);fid="id-"+n;digest=hashlib.sha256(n.encode()).hexdigest()
                ts=1795500000000;target=ts+30*DAY;old=target-600
                records[n]={"file_id":fid,"sha256":digest,"retain_until_ms":old}
                self.plan.append(dict(name=n,id=fid,old=old,target=target,upload_ms=ts,sha256=digest))
            self.put(filename,json.dumps(records).encode())
        self.lines=[{"stage":"plan","items":self.plan}]+[dict(stage=s,**p) for p in self.plan for s in ("attempt","verified")]+[{"stage":"complete","verified":22,"shortfall_count":0}]
        self.raw=("\n".join(json.dumps(x) for x in self.lines)+"\n").encode();self.put(JOURNAL_NAME,self.raw)
        self.pin=hashlib.sha256(self.raw).hexdigest()
    def put(self,n,raw):
        p=self.home/n;p.write_bytes(raw);p.chmod(0o600)
    def call(self,pin=None,reader=secure_read):
        return check(self.home,pin or self.pin,lambda raw,prefix,scope:json.loads(raw),reconcile,self.groups,reader)
    def test_complete_without_provider(self):
        out=self.call();self.assertEqual(out["corrected_receipts"],22);self.assertFalse(out["remote_read"]);self.assertFalse(out["remote_write"])
    def test_wrong_pin(self):
        with self.assertRaises(ValueError):self.call("0"*64)
    def test_receipt_changed(self):
        r=json.loads((self.home/"one").read_bytes());r["a/00"]["sha256"]="0"*64;self.put("one",json.dumps(r).encode())
        with self.assertRaises(ValueError):self.call()
    def test_journal_permissions(self):
        (self.home/JOURNAL_NAME).chmod(0o644)
        with self.assertRaises(ValueError):self.call()
    def test_symlink(self):
        (self.home/"one").rename(self.home/"target");(self.home/"one").symlink_to(self.home/"target")
        with self.assertRaises(OSError):self.call()
    def test_hardlink(self):
        os.link(self.home/"one",self.home/"alias")
        with self.assertRaises(ValueError):self.call()
    def test_drift(self):
        n=0
        def reader(p,limit):
            nonlocal n
            raw=secure_read(p,limit);n+=1
            return raw+b" " if n==4 else raw
        with self.assertRaisesRegex(ValueError,"ORIGINAL_EVIDENCE_DRIFT"):self.call(reader=reader)

if __name__=="__main__":unittest.main()
