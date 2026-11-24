import tempfile,unittest
from pathlib import Path
from scripts import jw_backup_authz_checkpoint_v223 as m
from scripts import jw_role_proof_v223 as role
from scripts import jw_current_authz_proof_v223 as a

def fixture():
    names=[*a.SCOPE,"owner"]
    return {"schema":"jw-current-authz-v1","scope":"jw_dev",
        "role_graph":role.graph([[n,False,True,False,False,False,False,False,-1] for n in names],[],names),
        "objects":a.object_rows([["schema","jw_dev","","owner",True,[]]]),"default_acl":[]}

class CheckpointTest(unittest.TestCase):
    def setUp(self):
        self.doc=fixture();self.key=b"k"*32;self.bind=dict(cipher_sha="a"*64,plain_sha="b"*64)
        self.blob=m.seal(self.doc,self.key,**self.bind)
    def test_roundtrip(self):
        self.assertEqual(m.unseal(self.blob,self.key,**self.bind),self.doc)
    def test_tamper(self):
        with self.assertRaisesRegex(role.Blocked,"CHECKPOINT_AUTH_FAILED"):
            m.unseal(self.blob[:-1]+bytes([self.blob[-1]^1]),self.key,**self.bind)
    def test_wrong_key(self):
        with self.assertRaises(role.Blocked):m.unseal(self.blob,b"x"*32,**self.bind)
    def test_cipher_substitution(self):
        with self.assertRaisesRegex(role.Blocked,"CHECKPOINT_BINDING"):
            m.unseal(self.blob,self.key,cipher_sha="c"*64,plain_sha=self.bind["plain_sha"])
    def test_plain_substitution(self):
        with self.assertRaises(role.Blocked):
            m.unseal(self.blob,self.key,cipher_sha=self.bind["cipher_sha"],plain_sha="c"*64)
    def test_nonce_randomized(self):
        self.assertNotEqual(self.blob,m.seal(self.doc,self.key,**self.bind))
    def test_private_write_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"backup.jwauthz"
            self.assertEqual(m.write_new(p,self.blob),__import__("hashlib").sha256(self.blob).hexdigest())
            self.assertEqual(p.stat().st_mode&0o777,0o600)
            with self.assertRaises(FileExistsError):m.write_new(p,b"x")
            self.assertEqual(p.read_bytes(),self.blob)
    def test_bad_key_size(self):
        with self.assertRaises(role.Blocked):m.seal(self.doc,b"bad",**self.bind)
