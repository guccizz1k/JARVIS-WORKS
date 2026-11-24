"""Opt-in independently anchored ledger adapter (no network transport).
An external witness must provide durable, linearizable compare-and-swap and
fresh signed readbacks. A local or co-administered mock cannot establish
independence. Advance witness BEFORE committing locally: any interruption
between the two commits blocks further use, never silently resets the anchor.
No recovery/reset API is provided. Existing ledger V1 remains unchanged.
"""
import hashlib
import secrets
import time
from contextlib import contextmanager
from scripts import jw_attestation_ledger_v223 as base
from scripts import jw_role_proof_v223 as proof
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

DOMAIN=b"JW-LEDGER-WITNESS-V1\x00"
MAX_SEQUENCE=2**63-1

def state(c):
    """Commit to the entire ordered ledger, including consumed challenges."""
    meta=c.execute("SELECT id,store_id,last_time FROM meta").fetchall()
    proof.need(len(meta)==1,"ANCHOR_META_INVALID")
    count=c.execute("SELECT count(*) FROM challenges").fetchone()[0]
    proof.need(0<=count<=base.MAX_RECORDS,"ANCHOR_COUNT_INVALID")
    h=hashlib.sha256(b"JW-LEDGER-STATE-V1\x00")
    h.update(proof.canonical(meta)+b"\n")
    n=0
    for row in c.execute("SELECT nonce,commit_sha,snapshot_sha,scope_sha,signer_pin,issued,expires,consumed,receipt_sha FROM challenges ORDER BY nonce COLLATE BINARY"):
        h.update(proof.canonical(row)+b"\n")
        n+=1
    proof.need(n==count,"ANCHOR_COUNT_INVALID")
    return h.hexdigest()

def message(p):
    proof.need(type(p) is dict and set(p)=={"version","store","request","action","sequence","state"},"WITNESS_FORMAT")
    proof.need(type(p["version"]) is int and p["version"]==1 and p["action"] in ("read","advance"),"WITNESS_FORMAT")
    for k in ("store","request","state"): base.pin(p[k])
    proof.need(type(p["sequence"]) is int and 0<=p["sequence"]<=MAX_SEQUENCE,"WITNESS_SEQUENCE")
    return DOMAIN+proof.canonical(p)

def verify(response,key,key_pin,*,store,request,action):
    proof.need(type(response) is tuple and len(response)==2,"WITNESS_RESPONSE")
    p,s=response
    proof.need(type(p) is dict,"WITNESS_RESPONSE")
    p=dict(p)
    msg=message(p)
    proof.need(type(key) is bytes and len(key)==32 and hashlib.sha256(key).hexdigest()==key_pin,"WITNESS_KEY_PIN")
    proof.need(type(s) is bytes and len(s)==64,"WITNESS_SIGNATURE")
    proof.need((p["store"],p["request"],p["action"])==(store,request,action),"WITNESS_BINDING")
    try: Ed25519PublicKey.from_public_bytes(key).verify(s,msg)
    except (InvalidSignature,ValueError): raise proof.Blocked("WITNESS_SIGNATURE") from None
    return p["sequence"],p["state"]

def enrollment_state(path,store_id):
    """Read-only enrollment candidate. Never enroll automatically."""
    p=base.private_path(path,exists=True)
    c=base.connect(p)
    try:
        c.execute("BEGIN IMMEDIATE")
        proof.need(c.execute("PRAGMA user_version").fetchone()[0]==base.VERSION,"LEDGER_VERSION")
        meta=c.execute("SELECT id,store_id FROM meta").fetchall()
        proof.need(meta==[(1,base.pin(store_id))],"LEDGER_ID_MISMATCH")
        return state(c)
    finally:
        if c.in_transaction:c.execute("ROLLBACK")
        c.close()

class AnchoredLedger(base.Ledger):
    """Witness protocol: read(store, request) and
    advance(store, request, expected_sequence, expected_state, next_state).
    Both return (signed_payload, signature). Stale CAS must raise.
    Witness must never reset or reuse a store identity.
    """
    def __init__(self,path,store_id,*,witness,public_key,public_key_pin):
        super().__init__(path,store_id)
        self.witness=witness
        self.key=public_key
        self.key_pin=base.pin(public_key_pin)
        proof.need(type(public_key) is bytes and len(public_key)==32 and hashlib.sha256(public_key).hexdigest()==self.key_pin,"WITNESS_KEY_PIN")

    @contextmanager
    def transaction(self):
        with super().transaction() as (c,now):
            before=state(c)
            request=secrets.token_hex(32)
            seq,remote=verify(self.witness.read(self.store_id,request),self.key,self.key_pin,
                store=self.store_id,request=request,action="read")
            proof.need(remote==before,"ANCHOR_DIVERGED")
            proof.need(seq<MAX_SEQUENCE,"WITNESS_SEQUENCE_EXHAUSTED")
            yield c,now
            # Match the parent transaction's final timestamp update exactly.
            c.execute("UPDATE meta SET last_time=? WHERE id=1",(now,))
            after=state(c)
            # Reads that did not change state do not manufacture an event.
            if after!=before:
                request=secrets.token_hex(32)
                actual=verify(self.witness.advance(self.store_id,request,seq,before,after),
                    self.key,self.key_pin,store=self.store_id,request=request,action="advance")
                proof.need(actual==(seq+1,after),"WITNESS_ADVANCE_MISMATCH")
            # Parent commits locally only after signed CAS. If commit fails,
            # witness remains ahead and next use fails closed.

    def consume(self,payload,signature,public_key):
        result=super().consume(payload,signature,public_key)
        result["witness_checkpoint"]="PASS_SIGNED_CAS"
        # Trust of the witness is external; never self-attest.
        result["rollback_resistance"]="NOT_ATTESTED_WITNESS_INDEPENDENCE_REQUIRED"
        return result
