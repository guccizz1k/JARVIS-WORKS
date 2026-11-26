import hashlib,json,tempfile,unittest,struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path
from unittest.mock import patch
from app import naruv_b2_native_upload as m
from app.naruv_b2_retention_journal import DAY

REAL_UPLOAD=m._upload

def encrypted(key,chunks):
    prefix=b"fixture!"
    return b"JWPGBK2\n"+prefix+b"".join(struct.pack(">I",len(c)+16)+AESGCM(key).encrypt(prefix+struct.pack(">I",i),c,b"JWPGBK2\n"+struct.pack(">QB",i,int(i==len(chunks)-1))) for i,c in enumerate(chunks))

class NativeUploadTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.ts=1795500000000;self.key=AESGCM.generate_key(256);self.raw=encrypted(self.key,[b"PGDMP synthetic-only"])
        h=hashlib.sha256(self.raw).hexdigest()
        self.s=dict(account_id="account",bucket_id="bucket",bucket_name_sha256=m.sha(b"private"),
            name="naruv-one/new-backup/"+"a"*32+"/"+h+".jwpgbk",sha256=h,size=len(self.raw),
            approval_expires_ms=self.ts+3600000,approved_until_ms=self.ts+30*DAY+180000,
            max_upload_ms=120000,max_clock_skew_ms=60000)
        self.args=dict(scope=self.s,approved_scope_sha256=m.scope_digest(self.s),raw=self.raw,archive_key=self.key,
            writer_credentials=("writer","fake"),audit_credentials=("audit","fake"),journal_dir=self.tmp.name)
        self.until=self.s["approved_until_ms"];self.rows=[];self.upload_count=0
        self.info=dict(bucketId="bucket",fileName=self.s["name"],fileId="version",contentLength=len(self.raw),
            contentSha1=hashlib.sha1(self.raw).hexdigest(),action="upload",uploadTimestamp=self.ts,
            fileRetention={"isClientAuthorizedToRead":True,"value":{"mode":"compliance","retainUntilTimestamp":self.until}},
            serverSideEncryption={"mode":"SSE-B2","algorithm":"AES256"},legalHold={"isClientAuthorizedToRead":True,"value":None})
        def fake_auth(cred):
            w=cred[0]=="writer"
            a=dict(accountId="account",authorizationToken="fake",applicationKeyExpirationTimestamp=self.ts+1800000)
            s=dict(apiUrl="https://api001.backblazeb2.com",downloadUrl="https://f001.backblazeb2.com",
                allowed=dict(buckets=[dict(id="bucket",name="private")],capabilities=sorted(m.WRITER_CAPS if w else m.AUDIT_CAPS),namePrefix=self.s["name"] if w else None))
            return a,s
        def fake_api(a,s,method,params):
            if method=="b2_list_buckets":return {"buckets":[dict(bucketId="bucket",bucketName="private",bucketType="allPrivate",
                fileLockConfiguration={"value":{"isFileLockEnabled":True}},defaultServerSideEncryption={"value":{"mode":"SSE-B2","algorithm":"AES256"}})]}
            if method=="b2_list_file_versions":return dict(files=list(self.rows),nextFileName=None,nextFileId=None)
            if method=="b2_get_upload_url":return dict(bucketId="bucket",uploadUrl="https://pod-1.backblaze.com/b2api/v4/b2_upload_file/bucket/token",authorizationToken="fake")
            if method=="b2_get_file_info":return self.info
            raise AssertionError(method)
        def fake_upload(*args):
            self.upload_count+=1;self.rows=[self.info];return dict(self.info)
        def fake_download(*args):
            return self.raw,{"X-Bz-File-Id":"version","X-Bz-Content-Sha1":self.info["contentSha1"],
                "X-Bz-File-Retention-Mode":"compliance","X-Bz-File-Retention-Retain-Until-Timestamp":str(self.until)}
        for name,fn in (("now_ms",lambda:self.ts),("_auth",fake_auth),("_api",fake_api),("_upload",fake_upload),("_download",fake_download)):
            p=patch.object(m,name,side_effect=fn);p.start();self.addCleanup(p.stop)
    def run_upload(self,**kwargs):return m.execute_approved_upload(**dict(self.args,**kwargs))
    def stages(self):
        paths=list(Path(self.tmp.name).glob("*.jsonl"));self.assertEqual(len(paths),1)
        return [json.loads(x)["stage"] for x in paths[0].read_text().splitlines()]
    def test_success_and_no_retry(self):
        self.assertTrue(self.run_upload()["ciphertext_verified"]);self.assertEqual(self.stages(),["attempt","ack","verified","complete"])
        with self.assertRaisesRegex(ValueError,"NATIVE_EXISTING_VERSION"):self.run_upload()
        self.assertEqual(self.upload_count,1)
    def test_bad_approval_and_ciphertext(self):
        for changes in (dict(approved_scope_sha256="0"*64),dict(raw=b"plaintext")):
            with self.assertRaises(ValueError):self.run_upload(**changes)
        self.assertEqual(m._auth.call_count,0)
    def test_authenticated_archive_boundary(self):
        self.assertEqual(m.authenticate_new_archive(self.raw,self.key)["authenticated_chunks"],1)
        full=encrypted(self.key,[b"PGDMP"+b"a"*(1048576-5),b"last"])
        self.assertEqual(m.authenticate_new_archive(full,self.key)["authenticated_chunks"],2)
        for bad in (self.raw[:-1],self.raw+b"x",self.raw[:-1]+bytes([self.raw[-1]^1]),b"JWPGBK1\n"+self.raw[8:],full[:-20],encrypted(self.key,[b"not PG custom"])):
            with self.subTest(size=len(bad)),self.assertRaises(ValueError):m.authenticate_new_archive(bad,self.key)
        with self.assertRaisesRegex(ValueError,"NATIVE_ARCHIVE_AUTH"):m.authenticate_new_archive(self.raw,AESGCM.generate_key(256))
        with self.assertRaisesRegex(ValueError,"NATIVE_ARCHIVE_KEY"):m.authenticate_new_archive(self.raw,b"bad")
    def test_forged_header_rejected_before_network(self):
        fake=b"JWPGBK2\n"+b"x"*60;h=m.sha(fake)
        scope=dict(self.s,sha256=h,size=len(fake),name="naruv-one/new-backup/"+"a"*32+"/"+h+".jwpgbk")
        with self.assertRaises(ValueError):self.run_upload(scope=scope,approved_scope_sha256=m.scope_digest(scope),raw=fake)
        self.assertEqual(m._auth.call_count,0)
        with self.assertRaisesRegex(ValueError,"NATIVE_ARCHIVE_AUTH"):self.run_upload(archive_key=AESGCM.generate_key(256))
        self.assertEqual(m._auth.call_count,0)
    def test_protected_prefix(self):
        s=dict(self.s,name="jw-v223/old.jwpgbk")
        with self.assertRaisesRegex(ValueError,"NATIVE_NEW_PREFIX"):self.run_upload(scope=s,approved_scope_sha256=m.scope_digest(s))
    def test_uncertain_upload_no_retry(self):
        m._upload.side_effect=TimeoutError()
        with self.assertRaises(TimeoutError):self.run_upload()
        self.assertEqual(self.stages(),["attempt"])
        with self.assertRaises(FileExistsError):self.run_upload()
        self.assertEqual(m._upload.call_count,1)
    def test_readback_mismatch(self):
        m._download.side_effect=None;m._download.return_value=(b"wrong",{})
        with self.assertRaisesRegex(ValueError,"NATIVE_READBACK"):self.run_upload()
        self.assertEqual(self.stages(),["attempt","ack"])
    def test_retention_shortfall(self):
        self.info["uploadTimestamp"]=self.ts+180001
        original=m._upload.side_effect
        def late(*args):
            out=original(*args);self.ts+=180002;return out
        m._upload.side_effect=late
        with self.assertRaisesRegex(ValueError,"UPLOAD_RETENTION_SHORTFALL"):self.run_upload()
        self.assertEqual(self.stages(),["attempt","ack"])
    def test_upload_header_contract(self):
        with patch.object(m,"_request",return_value=(b'{"fileId":"v"}',{})) as req:
            # Exercise the actual HTTP header builder without opening a socket.
            result=REAL_UPLOAD("https://pod-1.backblaze.com/b2api/v4/b2_upload_file/bucket/token",
                "fake",self.s["name"],self.raw,self.until)
            self.assertEqual(result,{"fileId":"v"})
            args=req.call_args.args
            self.assertEqual(args[2],self.raw)
            self.assertEqual(args[3]["X-Bz-File-Retention-Mode"],"compliance")
            self.assertEqual(args[3]["X-Bz-File-Retention-Retain-Until-Timestamp"],str(self.until))
            self.assertEqual(args[3]["X-Bz-Content-Sha1"],hashlib.sha1(self.raw).hexdigest())
            self.assertEqual(args[3]["X-Bz-Server-Side-Encryption"],"AES256")
    def test_prefix_and_pagination(self):
        a,s=m._auth(("writer","fake"));s["allowed"]["namePrefix"]="naruv-one/"
        with self.assertRaisesRegex(ValueError,"NATIVE_SESSION_PREFIX"):m._scope_session(a,s,self.s,True)
        original=m._api.side_effect
        def paged(a,s,method,params):
            if method=="b2_list_file_versions":return {"files":[],"nextFileName":"other","nextFileId":"v"}
            return original(a,s,method,params)
        m._api.side_effect=paged
        with self.assertRaisesRegex(ValueError,"NATIVE_VERSION_PAGINATION"):self.run_upload()
        self.assertEqual(self.upload_count,0)
    def test_api_and_download_hosts_are_separate(self):
        self.assertEqual(m._base("https://api001.backblazeb2.com"),"https://api001.backblazeb2.com")
        self.assertEqual(m._base("https://f001.backblazeb2.com",download=True),"https://f001.backblazeb2.com")
        for url,download in (("https://f001.backblazeb2.com",False),("https://api001.backblazeb2.com",True),
                             ("https://f001.backblazeb2.com.evil.example",True),("https://f001.backblazeb2.com:443",True)):
            with self.subTest(url=url,download=download),self.assertRaisesRegex(ValueError,"NATIVE_BASE_URL"):
                m._base(url,download=download)
    def test_urls(self):
        for url in ("http://pod-1.backblaze.com/b2api/v4/b2_upload_file/bucket/token",
            "https://pod-1.backblaze.com.evil.example/b2api/v4/b2_upload_file/bucket/token",
            "https://pod-1.backblaze.com/b2api/v4/b2_upload_file/other/token",
            "https://pod-1.backblaze.com/b2api/v4/b2_upload_file?bucket=other"):
            with self.subTest(url=url),self.assertRaises(ValueError):m._upload_url(url,"bucket")
        self.assertEqual(m._upload_url("https://pod-1.backblaze.com/b2api/v4/b2_upload_file?bucket=bucket","bucket"),"https://pod-1.backblaze.com/b2api/v4/b2_upload_file?bucket=bucket")
    def test_excess_key_scope(self):
        a,s=m._auth(("writer","fake"));s["allowed"]["capabilities"].append("deleteFiles")
        with self.assertRaisesRegex(ValueError,"NATIVE_SESSION_CAPS"):m._scope_session(a,s,self.s,True)
