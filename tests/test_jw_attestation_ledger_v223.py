import concurrent.futures
import hashlib
import multiprocessing
import os
import sqlite3
import tempfile
import time
import unittest
from datetime import datetime,timezone
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import jw_role_proof_v223 as proof
from scripts import jw_attestation_ledger_v223 as m

def try_consume(args):
    path,sid,p,sig,pub=args
    try:
        return m.Ledger(path,sid).consume(p,sig,pub)["local_one_time_consumption"]
    except proof.Blocked as exc:
        return str(exc)

class LedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/"ledger.sqlite"
        self.sid=m.initialize(self.path)
        self.ledger=m.Ledger(self.path,self.sid)
        self.key=Ed25519PrivateKey.generate()
        self.pub=self.key.public_key().public_bytes_raw()
        self.binding=dict(commit="a"*40,snapshot="b"*64,scope="c"*64,signer_pin=hashlib.sha256(self.pub).hexdigest())
    def tearDown(self): self.tmp.cleanup()
    def signed(self,ttl=300):
        x=self.ledger.issue(**self.binding,ttl=ttl)
        p=dict(schema="jw-role-evidence-v1",purpose="current-scoped-role-graph",
               commit=self.binding["commit"],snapshot_sha256=self.binding["snapshot"],
               archive_scope_sha256=self.binding["scope"],challenge=x["challenge"],
               observed_at=datetime.fromtimestamp(x["issued"],timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        return p,self.key.sign(proof.evidence_message(p)),self.pub
    def test_valid_and_replay_after_reopen(self):
        p,s,k=self.signed()
        x=self.ledger.consume(p,s,k)
        self.assertEqual(x["local_one_time_consumption"],"PASS")
        self.assertEqual(x["rollback_resistance"],"NOT_ATTESTED")
        self.assertEqual(x["overall"],"BLOCKED")
        self.assertFalse(x["activation_allowed"])
        self.assertRegex(x["receipt_sha256"],r"^[0-9a-f]{64}$")
        with self.assertRaisesRegex(proof.Blocked,"CHALLENGE_ALREADY_CONSUMED"):
            m.Ledger(self.path,self.sid).consume(p,s,k)
    def test_bad_signature_does_not_burn_challenge(self):
        p,s,k=self.signed()
        with self.assertRaisesRegex(proof.Blocked,"SIGNATURE_INVALID"):
            self.ledger.consume(p,bytes([s[0]^1])+s[1:],k)
        self.assertEqual(self.ledger.consume(p,s,k)["pinned_signature"],"PASS")
    def test_wrong_key(self):
        p,s,k=self.signed()
        other=Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(proof.Blocked,"SIGNER_PIN_MISMATCH"):
            self.ledger.consume(p,other.sign(proof.evidence_message(p)),other.public_key().public_bytes_raw())
    def test_substituted_commit(self):
        p,s,k=self.signed();p["commit"]="e"*40
        with self.assertRaisesRegex(proof.Blocked,"EVIDENCE_BINDING_MISMATCH"):
            self.ledger.consume(p,self.key.sign(proof.evidence_message(p)),k)
    def test_substituted_scope(self):
        p,s,k=self.signed();p["archive_scope_sha256"]="e"*64
        with self.assertRaisesRegex(proof.Blocked,"EVIDENCE_BINDING_MISMATCH"):
            self.ledger.consume(p,self.key.sign(proof.evidence_message(p)),k)
    def test_substituted_snapshot(self):
        p,s,k=self.signed();p["snapshot_sha256"]="e"*64
        with self.assertRaisesRegex(proof.Blocked,"EVIDENCE_BINDING_MISMATCH"):
            self.ledger.consume(p,self.key.sign(proof.evidence_message(p)),k)
    def test_unknown(self):
        p,s,k=self.signed();p["challenge"]="f"*64
        with self.assertRaisesRegex(proof.Blocked,"UNKNOWN_CHALLENGE"):
            self.ledger.consume(p,self.key.sign(proof.evidence_message(p)),k)
    def test_expiry(self):
        p,s,k=self.signed(ttl=1)
        with patch.object(m.time,"time",return_value=time.time()+10):
            with self.assertRaisesRegex(proof.Blocked,"CHALLENGE_EXPIRED"): self.ledger.consume(p,s,k)
    def test_clock_rollback(self):
        with patch.object(m.time,"time",return_value=time.time()-60):
            with self.assertRaisesRegex(proof.Blocked,"CLOCK_ROLLBACK"): self.ledger.issue(**self.binding)
    def test_ttl_and_pin_bounds(self):
        for v in (0,901,True):
            with self.assertRaisesRegex(proof.Blocked,"TTL_INVALID"): self.ledger.issue(**self.binding,ttl=v)
        with self.assertRaisesRegex(proof.Blocked,"PIN_FORMAT"): self.ledger.issue(**dict(self.binding,commit="wrong"))
    def test_no_reinitialize(self):
        with self.assertRaises(FileExistsError): m.initialize(self.path)
    def test_wrong_store(self):
        with self.assertRaisesRegex(proof.Blocked,"LEDGER_ID_MISMATCH"):
            m.Ledger(self.path,"d"*64).issue(**self.binding)
    def test_missing_store_no_recreation(self):
        self.path.unlink()
        with self.assertRaises(FileNotFoundError): self.ledger.issue(**self.binding)
        self.assertFalse(self.path.exists())
    def test_symlink(self):
        p=self.path.with_name("alias");p.symlink_to(self.path)
        with self.assertRaisesRegex(proof.Blocked,"PRIVATE_LEDGER_REQUIRED"):
            m.Ledger(p,self.sid).issue(**self.binding)
    def test_public_mode(self):
        os.chmod(self.path,0o644)
        with self.assertRaisesRegex(proof.Blocked,"PRIVATE_LEDGER_REQUIRED"): self.ledger.issue(**self.binding)
    def test_unsafe_sidecar(self):
        p=Path(str(self.path)+"-journal");p.symlink_to(self.path)
        with self.assertRaisesRegex(proof.Blocked,"UNSAFE_SIDECAR"): self.ledger.issue(**self.binding)
    def test_capacity(self):
        self.signed()
        with patch.object(m,"MAX_RECORDS",1):
            with self.assertRaisesRegex(proof.Blocked,"LEDGER_CAPACITY"): self.ledger.issue(**self.binding)
    def test_thread_contention(self):
        p,s,k=self.signed()
        args=(self.path,self.sid,p,s,k)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            out=list(pool.map(try_consume,[args]*16))
        self.assertEqual(out.count("PASS"),1)
        self.assertEqual(out.count("CHALLENGE_ALREADY_CONSUMED"),15)
    def test_process_contention(self):
        p,s,k=self.signed()
        args=(self.path,self.sid,p,s,k)
        with concurrent.futures.ProcessPoolExecutor(max_workers=4,mp_context=multiprocessing.get_context("spawn")) as pool:
            out=list(pool.map(try_consume,[args]*8))
        self.assertEqual(out.count("PASS"),1)
        self.assertEqual(out.count("CHALLENGE_ALREADY_CONSUMED"),7)
    def test_uncommitted_consumption_rolled_back(self):
        p,s,k=self.signed()
        c=sqlite3.connect(self.path,isolation_level=None)
        try:
            c.execute("BEGIN IMMEDIATE")
            c.execute("UPDATE challenges SET consumed=1, receipt_sha='temporary' WHERE nonce=?",(p["challenge"],))
        finally: c.close()
        self.assertEqual(self.ledger.consume(p,s,k)["local_one_time_consumption"],"PASS")
    def test_receipt_matches_persisted(self):
        p,s,k=self.signed();r=self.ledger.consume(p,s,k)
        c=sqlite3.connect(self.path)
        try:
            row=c.execute("SELECT receipt_sha,consumed FROM challenges WHERE nonce=?",(p["challenge"],)).fetchone()
            self.assertEqual(row[0],r["receipt_sha256"]);self.assertIsInstance(row[1],int)
        finally: c.close()
