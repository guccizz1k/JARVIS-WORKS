"""Encrypted, archive-bound authorization sidecar for NEW backups only.
No role grants, ownership changes, credential export, or signing claims.
A distinct 32-byte metadata key is supplied by an authorized caller. The
result is recoverable metadata, not independent source attestation.
"""
import hashlib
import json
import os
import secrets
import stat
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from scripts import jw_current_authz_proof_v223 as authz
from scripts import jw_role_proof_v223 as proof

MAGIC=b"JW-AUTHZ-CHECKPOINT-V1\x00"
MAX_BYTES=16*1024*1024

def need(ok,code): proof.need(ok,code)

def key_check(key):
    need(type(key) is bytes and len(key)==32,"CHECKPOINT_KEY_REQUIRED")

def binding(cipher_sha,plain_sha):
    for v in (cipher_sha,plain_sha):
        need(type(v) is str and proof.SHA.fullmatch(v),"ARCHIVE_BINDING_INVALID")
    return MAGIC+bytes.fromhex(cipher_sha)+bytes.fromhex(plain_sha)

def seal(doc,key,*,cipher_sha,plain_sha):
    key_check(key)
    authz.summary(doc)
    raw=proof.canonical(doc)
    need(0<len(raw)<=MAX_BYTES,"CHECKPOINT_SIZE")
    header=binding(cipher_sha,plain_sha)
    nonce=secrets.token_bytes(12)
    return header+nonce+AESGCM(key).encrypt(nonce,raw,header)

def unseal(blob,key,*,cipher_sha,plain_sha):
    key_check(key)
    header=binding(cipher_sha,plain_sha)
    need(type(blob) is bytes and len(header)+28<len(blob)<=len(header)+28+MAX_BYTES and blob.startswith(header),"CHECKPOINT_BINDING")
    try:
        raw=AESGCM(key).decrypt(blob[len(header):len(header)+12],blob[len(header)+12:],header)
    except InvalidTag: raise proof.Blocked("CHECKPOINT_AUTH_FAILED") from None
    doc=json.loads(raw)
    need(proof.canonical(doc)==raw,"CHECKPOINT_NOT_CANONICAL")
    authz.summary(doc)
    return doc

def write_new(path,blob):
    p=Path(path)
    st=p.parent.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o700 and p.parent.resolve()==p.parent.absolute(),"CHECKPOINT_PRIVATE_DIRECTORY")
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(blob);f.flush();os.fsync(f.fileno())
        rd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(rd,"rb") as f:
            st=os.fstat(f.fileno())
            need(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o600,"CHECKPOINT_PRIVATE_FILE")
            need(f.read(len(blob)+1)==blob,"CHECKPOINT_READBACK")
        fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    except BaseException:
        p.unlink(missing_ok=True)
        raise
    return hashlib.sha256(blob).hexdigest()

def capture(conn,identity_check):
    """Called inside the existing pg_dump export transaction, never after it."""
    with conn.cursor() as cur:
        cur.execute("SELECT current_setting('search_path'),current_setting('statement_timeout')")
        path,timeout=cur.fetchone()
        cur.execute("SET LOCAL search_path=pg_catalog")
        cur.execute("SET LOCAL statement_timeout='15s'")
        try:return authz.collect_in_snapshot(cur,conn,identity_check=identity_check)
        finally:
            # An aborted transaction must be rolled back by the existing caller.
            if conn.info.transaction_status==2:
                cur.execute("SELECT set_config('search_path',%s,true),set_config('statement_timeout',%s,true)",(path,timeout))
