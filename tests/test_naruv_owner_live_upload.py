import hashlib,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.naruv_b2_native_upload import authenticate_new_archive
from scripts import naruv_owner_live_upload as m

class OwnerProbeTests(unittest.TestCase):
    def test_encrypt_and_exclusive_evidence(self):
        key=AESGCM.generate_key(256);raw=m.encrypt_dump(b"PGDMP synthetic",key)
        self.assertEqual(authenticate_new_archive(raw,key)["authenticated_chunks"],1)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"scope"
            m.store(p,raw)
            self.assertEqual(p.stat().st_mode&0o777,0o600)
            with self.assertRaises(FileExistsError):m.store(p,b"new")
            self.assertEqual(p.read_bytes(),raw)
        for bad in (b"not a dump",b"PGDMP"+b"a"*m.MAX):
            with self.assertRaises(ValueError):m.encrypt_dump(bad,key)
    def test_create_key_strict_scope(self):
        from app import naruv_b2_native_upload as n
        ts=1795500000000
        scope=dict(account_id="acc",bucket_id="bid",name="naruv-one/new-backup/"+"a"*32+"/x.jwpgbk",approval_expires_ms=ts+5*3600000)
        a={"authorizationToken":"fake"};s={"apiUrl":"https://api001.backblazeb2.com"}
        response=dict(accountId="acc",bucketIds=["bid"],capabilities=sorted(n.WRITER_CAPS),namePrefix=scope["name"],
            expirationTimestamp=ts+3600000,applicationKeyId="fake",applicationKey="fake")
        with patch.object(n,"now_ms",return_value=ts),patch.object(n,"_json",return_value=response) as call:
            self.assertEqual(m.create_temp(n,a,s,scope,n.WRITER_CAPS,scope["name"],"write"),("fake","fake"))
            p=call.call_args.args[2];self.assertEqual(p["validDurationInSeconds"],3600);self.assertEqual(p["namePrefix"],scope["name"])
            for change in (dict(bucketIds=["other"]),dict(capabilities=["deleteFiles"]),dict(namePrefix="naruv-one/"),dict(expirationTimestamp=ts+5*3600000)):
                call.return_value=dict(response,**change)
                with self.assertRaisesRegex(ValueError,"OWNER_TEMP_KEY_SCOPE"):m.create_temp(n,a,s,scope,n.WRITER_CAPS,scope["name"],"write")
    def test_pinned_module_blobs(self):
        # Verify original exact source without executing a live runner or network.
        for name,pin in m.PINS.items():
            raw=m.run(["git","--no-replace-objects","show",m.SOURCE+":app/"+name+".py"]).stdout
            self.assertEqual(hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest(),pin)
