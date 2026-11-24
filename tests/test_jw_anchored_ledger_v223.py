"""Witness protocol contract and real SQLite snapshot rollback tests.
The fixture witness is deliberately in-process and not an independent custodian.
"""
import hashlib
import os
import shutil
import tempfile
import unittest
from datetime import datetime,timezone
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import jw_role_proof_v223 as proof
from scripts import jw_attestation_ledger_v223 as base
from scripts import jw_anchored_ledger_v223 as m

class Witness:
    def __init__(self,key,store,state):
        self.key=key;self.store=store;self.state=state;self.seq=0
        self.read_response=None;self.fail_before=False;self.fail_after=False
        self.bad_advance=False
    def signed(self,request,action):
        p=dict(version=1,store=self.store,request=request,action=action,sequence=self.seq,state=self.state)
        return p,self.key.sign(m.message(p))
    def read(self,store,request):
        proof.need(store==self.store,"STORE_MISMATCH")
        if self.read_response is not None:return self.read_response
        return self.signed(request,"read")
    def advance(self,store,request,seq,previous,next_state):
        proof.need((store,seq,previous)==(self.store,self.seq,self.state),"STALE_CAS")
        if self.fail_before:raise RuntimeError("synthetic unavailable")
        self.seq+=1;self.state=next_state
        if self.fail_after:raise RuntimeError("synthetic lost response after CAS")
        if self.bad_advance:return self.signed(request,"read")
        return self.signed(request,"advance")

class AnchoredTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/"ledger.sqlite"
        self.sid=base.initialize(self.path)
        self.signer=Ed25519PrivateKey.generate();self.pub=self.signer.public_key().public_bytes_raw()
        self.wkey=Ed25519PrivateKey.generate();self.wpub=self.wkey.public_key().public_bytes_raw()
        self.wpin=hashlib.sha256(self.wpub).hexdigest()
        self.witness=Witness(self.wkey,self.sid,m.enrollment_state(self.path,self.sid))
        self.ledger=m.AnchoredLedger(self.path,self.sid,witness=self.witness,public_key=self.wpub,public_key_pin=self.wpin)
        self.binding=dict(commit="a"*40,snapshot="b"*64,scope="c"*64,signer_pin=hashlib.sha256(self.pub).hexdigest())
    def tearDown(self):self.tmp.cleanup()
    def signed(self):
        x=self.ledger.issue(**self.binding)
        p=dict(schema="jw-role-evidence-v1",purpose="current-scoped-role-graph",
            commit=self.binding["commit"],snapshot_sha256=self.binding["snapshot"],archive_scope_sha256=self.binding["scope"],
            challenge=x["challenge"],observed_at=datetime.fromtimestamp(x["issued"],timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        return p,self.signer.sign(proof.evidence_message(p)),self.pub
    def test_valid_and_no_self_attestation(self):
        p,s,k=self.signed();r=self.ledger.consume(p,s,k)
        self.assertEqual(self.witness.seq,2)
        self.assertEqual(self.witness.state,m.enrollment_state(self.path,self.sid))
        self.assertEqual(r["witness_checkpoint"],"PASS_SIGNED_CAS")
        self.assertEqual(r["overall"],"BLOCKED")
        self.assertFalse(r["activation_allowed"])
    def test_actual_sqlite_snapshot_rollback(self):
        p,s,k=self.signed();old=self.path.with_name("old.sqlite")
        shutil.copy2(self.path,old)
        self.ledger.consume(p,s,k)
        os.replace(old,self.path)
        with self.assertRaisesRegex(proof.Blocked,"ANCHOR_DIVERGED"):self.ledger.consume(p,s,k)
    def test_unanchored_writer_detected(self):
        base.Ledger(self.path,self.sid).issue(**self.binding)
        with self.assertRaisesRegex(proof.Blocked,"ANCHOR_DIVERGED"):self.ledger.issue(**self.binding)
    def test_witness_failure_before_cas_rolls_back(self):
        original=m.enrollment_state(self.path,self.sid);self.witness.fail_before=True
        with self.assertRaises(RuntimeError):self.ledger.issue(**self.binding)
        self.assertEqual(m.enrollment_state(self.path,self.sid),original)
        self.assertEqual(self.witness.seq,0)
        self.witness.fail_before=False
        self.ledger.issue(**self.binding)
    def test_lost_response_after_cas_fails_closed(self):
        original=m.enrollment_state(self.path,self.sid);self.witness.fail_after=True
        with self.assertRaises(RuntimeError):self.ledger.issue(**self.binding)
        self.assertEqual(m.enrollment_state(self.path,self.sid),original)
        self.assertEqual(self.witness.seq,1)
        self.witness.fail_after=False
        with self.assertRaisesRegex(proof.Blocked,"ANCHOR_DIVERGED"):self.ledger.issue(**self.binding)
    def test_bad_advance_action_fails_closed(self):
        self.witness.bad_advance=True
        with self.assertRaisesRegex(proof.Blocked,"WITNESS_BINDING"):self.ledger.issue(**self.binding)
        self.assertEqual(self.witness.seq,1)
        with self.assertRaisesRegex(proof.Blocked,"ANCHOR_DIVERGED"):self.ledger.issue(**self.binding)
    def test_stale_read_response(self):
        self.witness.read_response=self.witness.signed("f"*64,"read")
        with self.assertRaisesRegex(proof.Blocked,"WITNESS_BINDING"):self.ledger.issue(**self.binding)
    def test_wrong_key_pin(self):
        with self.assertRaisesRegex(proof.Blocked,"WITNESS_KEY_PIN"):
            m.AnchoredLedger(self.path,self.sid,witness=self.witness,public_key=self.wpub,public_key_pin="0"*64)
    def test_signature_tampering(self):
        p,s=self.witness.signed("f"*64,"read")
        with self.assertRaisesRegex(proof.Blocked,"WITNESS_SIGNATURE"):
            m.verify((p,bytes([s[0]^1])+s[1:]),self.wpub,self.wpin,store=self.sid,request="f"*64,action="read")
    def test_wrong_enrollment_id(self):
        with self.assertRaisesRegex(proof.Blocked,"LEDGER_ID_MISMATCH"):
            m.enrollment_state(self.path,"0"*64)
    def test_invalid_user_signature_preserves_anchor(self):
        p,s,k=self.signed();seq=self.witness.seq
        with self.assertRaisesRegex(proof.Blocked,"SIGNATURE_INVALID"):
            self.ledger.consume(p,bytes([s[0]^1])+s[1:],k)
        self.assertEqual(self.witness.seq,seq)
        self.assertEqual(self.witness.state,m.enrollment_state(self.path,self.sid))
        self.ledger.consume(p,s,k)
    def test_replay_rejected_without_advance(self):
        p,s,k=self.signed();self.ledger.consume(p,s,k);seq=self.witness.seq
        with self.assertRaisesRegex(proof.Blocked,"CHALLENGE_ALREADY_CONSUMED"):self.ledger.consume(p,s,k)
        self.assertEqual(self.witness.seq,seq)
