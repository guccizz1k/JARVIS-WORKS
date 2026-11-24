"""Local durable one-time challenge ledger for current role evidence.

Trusted local directory and clock required. Not a WORM ledger, trusted
timestamp, independent custody proof, or authorization to activate keys.
No application/backup/production database access. No private keys stored.
"""
import hashlib
import os
import secrets
import sqlite3
import stat
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from scripts import jw_role_proof_v223 as proof

MAX_RECORDS = 100000
MAX_TTL = 900
VERSION = 1

def need(ok, code):
    proof.need(ok, code)

def pin(value, regex=proof.SHA):
    need(type(value) is str and regex.fullmatch(value), "PIN_FORMAT")
    return value

def private_path(path, *, exists):
    p=Path(path)
    need(p.is_absolute() and p.parent.resolve()==p.parent,"PRIVATE_DIRECTORY_REQUIRED")
    st=p.parent.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o700,"PRIVATE_DIRECTORY_REQUIRED")
    if exists:
        st=p.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,"PRIVATE_LEDGER_REQUIRED")
    for suffix in ("-wal","-shm","-journal"):
        side=Path(str(p)+suffix)
        if os.path.lexists(side):
            st=side.lstat()
            need(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and not (st.st_mode & 0o077) and st.st_nlink==1,"UNSAFE_SIDECAR")
    return p

def connect(path):
    c=sqlite3.connect(path.as_uri()+"?mode=rw",uri=True,timeout=10,isolation_level=None)
    try:
        c.execute("PRAGMA trusted_schema=OFF")
        c.execute("PRAGMA synchronous=FULL")
        need(c.execute("PRAGMA journal_mode").fetchone()[0]=="delete","JOURNAL_MODE_DENIED")
        return c
    except BaseException:
        c.close()
        raise

def initialize(path):
    """Explicit create only; never overwrite or silently replace lost state.
    Save returned store_id independently of the ledger.
    """
    p=private_path(path,exists=False)
    fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    os.close(fd)
    sid=secrets.token_hex(32)
    c=connect(p)
    try:
        c.execute("BEGIN IMMEDIATE")
        c.execute("CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1),store_id TEXT NOT NULL,last_time INTEGER NOT NULL)")
        c.execute("CREATE TABLE challenges (nonce TEXT PRIMARY KEY,commit_sha TEXT NOT NULL,snapshot_sha TEXT NOT NULL,scope_sha TEXT NOT NULL,signer_pin TEXT NOT NULL,issued INTEGER NOT NULL,expires INTEGER NOT NULL,consumed INTEGER,receipt_sha TEXT)")
        c.execute("INSERT INTO meta VALUES(1,?,?)",(sid,int(time.time())))
        c.execute("PRAGMA user_version=1")
        c.execute("COMMIT")
    finally:
        c.close()
    fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    return sid

class Ledger:
    def __init__(self,path,store_id):
        self.path=Path(path)
        self.store_id=pin(store_id)

    @contextmanager
    def transaction(self):
        p=private_path(self.path,exists=True)
        c=connect(p)
        try:
            c.execute("BEGIN IMMEDIATE")
            need(c.execute("PRAGMA user_version").fetchone()[0]==VERSION,"LEDGER_VERSION")
            meta=c.execute("SELECT id,store_id,last_time FROM meta").fetchall()
            need(len(meta)==1 and meta[0][:2]==(1,self.store_id) and type(meta[0][2]) is int,"LEDGER_ID_MISMATCH")
            now=int(time.time())
            need(now>=meta[0][2],"CLOCK_ROLLBACK")
            yield c,now
            c.execute("UPDATE meta SET last_time=? WHERE id=1",(now,))
            c.execute("COMMIT")
        except BaseException:
            if c.in_transaction: c.execute("ROLLBACK")
            raise
        finally:
            c.close()

    def issue(self,*,commit,snapshot,scope,signer_pin,ttl=300):
        pin(commit,proof.COMMIT)
        for v in (snapshot,scope,signer_pin): pin(v)
        need(type(ttl) is int and 1<=ttl<=MAX_TTL,"TTL_INVALID")
        with self.transaction() as (c,now):
            need(c.execute("SELECT count(*) FROM challenges").fetchone()[0]<MAX_RECORDS,"LEDGER_CAPACITY")
            nonce=secrets.token_hex(32)
            c.execute("INSERT INTO challenges VALUES(?,?,?,?,?,?,?,NULL,NULL)",(nonce,commit,snapshot,scope,signer_pin,now,now+ttl))
        return {"challenge":nonce,"issued":now,"expires":now+ttl}

    def consume(self,payload,signature,public_key):
        # Snapshot the caller's input; no trust in caller-supplied clock or pins.
        need(type(payload) is dict,"EVIDENCE_FORMAT")
        payload=dict(payload)
        msg=proof.evidence_message(payload)
        nonce=payload["challenge"]
        with self.transaction() as (c,now):
            row=c.execute("SELECT commit_sha,snapshot_sha,scope_sha,signer_pin,issued,expires,consumed,receipt_sha FROM challenges WHERE nonce=?",(nonce,)).fetchone()
            need(row is not None,"UNKNOWN_CHALLENGE")
            commit,snapshot,scope,signer,issued,expires,used,receipt=row
            need(used is None and receipt is None,"CHALLENGE_ALREADY_CONSUMED")
            need(issued<=now<=expires and 1<=expires-issued<=MAX_TTL,"CHALLENGE_EXPIRED")
            proof.verify_attestation(payload,signature,public_key,public_key_pin=signer,
                expected_commit=commit,expected_snapshot=snapshot,expected_scope=scope,
                expected_challenge=nonce,not_before=datetime.fromtimestamp(issued,timezone.utc),
                now=datetime.fromtimestamp(now,timezone.utc))
            # Domain-separated receipt; only public evidence is hashed/stored.
            receipt=hashlib.sha256(b"JW-LOCAL-CONSUME-V1\x00"+bytes.fromhex(self.store_id)+msg+public_key+signature).hexdigest()
            n=c.execute("UPDATE challenges SET consumed=?,receipt_sha=? WHERE nonce=? AND consumed IS NULL AND receipt_sha IS NULL",(now,receipt,nonce)).rowcount
            need(n==1,"CONSUME_RACE")
        # Return only after durable COMMIT. A lost response cannot be replayed.
        return {"pinned_signature":"PASS","local_one_time_consumption":"PASS",
                "receipt_sha256":receipt,"store_id":self.store_id,
                "independent_custody":"NOT_ATTESTED","trusted_timestamp":"NOT_ATTESTED",
                "rollback_resistance":"NOT_ATTESTED","historic_source_signature":"NOT_ATTESTED",
                "overall":"BLOCKED","activation_allowed":False}
