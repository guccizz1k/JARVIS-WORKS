import json, os, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import jw_rekey_candidate_v223 as r

OLD=b'O'*32; NEW=b'N'*32

def source():
    return {r.git_id(c):c for i in range(11) for c in [r.encrypt(b'PGDMP'+bytes([i])*128,OLD,i.to_bytes(8,'big'))]}

class TestRekey(unittest.TestCase):
    def test_full_batch(self):
        s=source(); out=r.prepare(s,OLD,NEW)
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/'out'; result=r.publish_local(target,out,NEW)
            self.assertEqual(result['verified'],11); self.assertFalse(result['activated']); self.assertEqual(len(list(target.glob('*.jwpgbk'))),11)
            for i,(c,_) in out.items():
                self.assertEqual(r.decrypt(c,NEW),r.decrypt(s[i],OLD))
                with self.assertRaises(InvalidTag): r.decrypt(c,OLD)
    def test_wrong_old(self):
        with self.assertRaises(InvalidTag): r.prepare(source(),b'W'*32,NEW)
    def test_same_key(self):
        with self.assertRaisesRegex(ValueError,'KEY_NOT_DISTINCT'): r.prepare(source(),OLD,OLD)
    def test_missing(self):
        s=source(); s.pop(next(iter(s)))
        with self.assertRaisesRegex(ValueError,'SOURCE_COUNT'): r.prepare(s,OLD,NEW)
    def test_tamper(self):
        s=source(); i=next(iter(s)); s[i]=s[i][:-1]+bytes([s[i][-1]^1])
        with self.assertRaises(InvalidTag): r.prepare(s,OLD,NEW)
    def test_nonce_collision(self):
        with patch.object(r.secrets,'token_bytes',return_value=b'x'*8):
            with self.assertRaisesRegex(ValueError,'NONCE_COLLISION'): r.prepare(source(),OLD,NEW)
    def test_scope_substitution(self):
        s=source(); rows=[{'blob_sha1':i,'cipher_sha256':r.sha(c)} for i,c in s.items()]; doc={'vault_commit_sha1':r.VAULT,'archives':rows}; pin=r.scope(s)
        self.assertEqual(set(r.manifest(doc,pin)),set(s)); rows[0]['blob_sha1']='f'*40
        with self.assertRaisesRegex(ValueError,'SCOPE_PIN'): r.manifest(doc,pin)
    def test_source_scan(self):
        s=source(); expected={i:r.sha(c) for i,c in s.items()}
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); [r.write_new(p/(i+'.jwpgbk'),c) for i,c in s.items()]; self.assertEqual(r.scan(p,expected),s)
            i=next(iter(s)); os.chmod(p/(i+'.jwpgbk'),0o644)
            with self.assertRaisesRegex(ValueError,'PRIVATE_FILE'): r.scan(p,expected)
    def test_existing_output(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); f=p/'sentinel'; f.write_bytes(b'keep')
            with self.assertRaises(FileExistsError): r.publish_local(p,r.prepare(source(),OLD,NEW),NEW)
            self.assertEqual(f.read_bytes(),b'keep')
    def test_legacy(self):
        m=r.LEGACY; prefix=b'ABCD'; plain=b'PGDMP'+b'x'*100; c=AESGCM(OLD).encrypt(r.nonce(prefix,0),plain,r.aad(m,0,True)); raw=m+prefix+len(c).to_bytes(4,'big')+c
        self.assertEqual(r.decrypt(raw,OLD),plain)
    def test_chunk_truncation(self):
        c=r.encrypt(b'PGDMP'+b'x'*r.CHUNK,OLD,b'12345678'); length=int.from_bytes(c[16:20],'big')
        with self.assertRaises(InvalidTag): r.decrypt(c[:20+length],OLD)
    def test_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); (p/'f').write_bytes(b'x'); (p/'link').symlink_to(p/'f')
            with self.assertRaises(OSError): r.private_read(p/'link')

if __name__=='__main__': unittest.main()
