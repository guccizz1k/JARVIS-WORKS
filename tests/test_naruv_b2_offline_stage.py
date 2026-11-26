import json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch,MagicMock
from scripts.naruv_b2_offline_stage import *

class B2StageTests(unittest.TestCase):
    def setUp(self):
        self.data={str(i):bytes([i])*64 for i in range(22)}
        self.rows=[dict(scope="legacy" if i<11 else "staged",file_id=str(i),size=64,
            sha256=hash256(self.data[str(i)]),git_blob_sha1=git_blob(self.data[str(i)])) for i in range(22)]
    def manifest(self):
        raw=json.dumps(dict(version=1,archives=self.rows)).encode()
        return raw,hash256(raw)
    def test_stage_and_offline_read_both_scopes(self):
        raw,pin=self.manifest()
        with tempfile.TemporaryDirectory() as d:
            p=stage(raw,pin,d,lambda r:self.data[r["file_id"]])
            for scope in ("legacy","staged"):
                expected={r["git_blob_sha1"]:self.data[r["file_id"]] for r in self.rows if r["scope"]==scope}
                self.assertEqual(read_staged(raw,pin,p,scope),expected)
            (p/"extra").write_bytes(b"x")
            with self.assertRaises(ValueError):read_staged(raw,pin,p,"legacy")
    def test_pin_scope_duplicate_size_fail_closed(self):
        raw,pin=self.manifest()
        with self.assertRaises(ValueError):parse_manifest(raw,"0"*64)
        for key,value in (("file_id","1"),("scope","staged"),("size",True),("git_blob_sha1",self.rows[1]["git_blob_sha1"])):
            orig=self.rows[0][key];self.rows[0][key]=value
            with self.assertRaises(ValueError):parse_manifest(*self.manifest())
            self.rows[0][key]=orig
    def test_stage_rolls_back_and_rejects_drift(self):
        raw,pin=self.manifest()
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                stage(raw,pin,d,lambda r: b"x"*64 if r["file_id"]=="15" else self.data[r["file_id"]])
            self.assertEqual(list(Path(d).iterdir()),[])
            p=stage(raw,pin,d,lambda r:self.data[r["file_id"]])
            (p/(self.rows[0]["git_blob_sha1"]+".cipher")).write_bytes(b"x"*64)
            with self.assertRaises(ValueError):read_staged(raw,pin,p,"staged")
    def test_https_exact_version_and_no_redirect(self):
        row=self.rows[0];data=self.data["0"]
        with patch("scripts.naruv_b2_offline_stage.http.client.HTTPSConnection") as factory:
            conn=factory.return_value;r=conn.getresponse.return_value
            r.status=200;r.read.return_value=data
            headers={"X-Bz-File-Id":"0","Content-Length":"64","X-Bz-Content-Sha1":hashlib.sha1(data).hexdigest()}
            r.getheader.side_effect=headers.get
            self.assertEqual(native_download("f001.backblazeb2.com","test-token",row),data)
            self.assertEqual(conn.request.call_args.args[:2],("GET","/b2api/v4/b2_download_file_by_id?fileId=0"))
            for status in (302,206,403):
                r.status=status
                with self.assertRaises(ValueError):native_download("f001.backblazeb2.com","test-token",row)
            r.status=200;headers["X-Bz-File-Id"]="wrong"
            with self.assertRaises(ValueError):native_download("f001.backblazeb2.com","test-token",row)
            with self.assertRaises(ValueError):native_download("f001.backblazeb2.com.evil.test","test-token",row)
