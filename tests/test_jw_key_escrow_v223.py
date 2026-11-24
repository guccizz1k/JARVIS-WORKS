import os, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from cryptography.exceptions import InvalidTag
from scripts import jw_key_escrow_v223 as e
P=b'synthetic-test-only-password-12345'
K=bytes(range(32))
class Tests(unittest.TestCase):
 def test_roundtrip(self): self.assertEqual(e.unseal(e.seal(K,P),P),K)
 def test_wrong_password(self):
  with self.assertRaises(InvalidTag): e.unseal(e.seal(K,P),P+b'x')
 def test_tamper(self):
  x=bytearray(e.seal(K,P)); x[-1]^=1
  with self.assertRaises(InvalidTag): e.unseal(bytes(x),P)
 def test_bad_length(self):
  with self.assertRaises(ValueError): e.unseal(b'x',P)
 def test_weak_length(self):
  with self.assertRaises(ValueError): e.seal(K,b'short')
 def test_randomized_envelope(self): self.assertNotEqual(e.seal(K,P),e.seal(K,P))
 def test_mismatch_no_write(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'key'
   with self.assertRaises(ValueError): e.create(p,P,P+b'x')
   self.assertFalse(p.exists())
 def test_no_overwrite_and_permissions(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'key'; e.create(p,P,P); before=p.read_bytes()
   self.assertEqual(p.stat().st_mode&0o777,0o600)
   with self.assertRaises(ValueError): e.create(p,P,P)
   self.assertEqual(p.read_bytes(),before)
 def test_symlink_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'key'; p.symlink_to(Path(d)/'missing')
   with self.assertRaises(ValueError): e.create(p,P,P)
   self.assertTrue(p.is_symlink())
 def test_nonprivate_dir_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   os.chmod(d,0o755)
   with self.assertRaises(ValueError): e.create(Path(d)/'key',P,P)
 def test_bad_read_mode(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'key'; p.write_bytes(b'x'*e.SIZE); p.chmod(0o644)
   with self.assertRaises(ValueError): e.read_private(p)
if __name__=='__main__': unittest.main(verbosity=2)
