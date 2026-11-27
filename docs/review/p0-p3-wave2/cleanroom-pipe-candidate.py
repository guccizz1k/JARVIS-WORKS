"""Clean-room key recovery proof; NO source Codespaces key, archive or database.

Proves that a separately supplied 32-byte AES-GCM key can authenticate
eleven EXACT ciphertexts from one pinned private Git vault commit.
The key must arrive via a pre-opened OS pipe, not argv, environment,
GitHub or a disk file. No decrypted bytes are written or displayed.
Independent custody is NOT attested merely by supplying an equivalent key:
external custodian signature/site evidence is required separately.
"""
from __future__ import annotations
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

REPO = "repos/guccizz1k/jw-backup-vault-261111"
ACK = "OWNER_APPROVES_INDEPENDENT_CLEANROOM_KEY_PROOF"
SHA1 = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
MAX_OBJECT = 32 * 1024 * 1024
MAX_MANIFEST = 4096
MAX_TREE = 80


class Blocked(RuntimeError):
    pass


def _env():
    env=os.environ.copy()
    # The clean-room process must not inherit any Codespaces source token.
    env.pop("GITHUB_TOKEN",None)
    env.pop("JW_PG_BACKUP_KEY",None)
    env.pop("JW_PG_VAULT_READ_TOKEN",None)
    env.pop("JW_PG_CLEANROOM_KEY_FD",None)
    env.update(GH_PROMPT_DISABLED="1", GH_NO_UPDATE_NOTIFIER="1",
               GIT_TERMINAL_PROMPT="0")
    return env


def _api(endpoint, budget=65536):
    if (not endpoint.startswith(REPO+"/") or
            len(endpoint)>190 or any(c in endpoint for c in "\r\n ")):
        raise Blocked("INVALID_PRIVATE_VAULT_ENDPOINT")
    try:
        p=subprocess.run(["gh","api",endpoint,"--method","GET",
            "--header","Accept: application/vnd.github+json"],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,env=_env(),timeout=90,check=False)
        if p.returncode or len(p.stdout)>budget:
            raise Blocked("CLEANROOM_GH_PRIVATE_READ_UNAVAILABLE")
        val=json.loads(p.stdout)
        if not isinstance(val,dict):
            raise Blocked("CLEANROOM_PROVIDER_RESPONSE_INVALID")
        return val
    except (ValueError,UnicodeError,OSError,subprocess.TimeoutExpired):
        raise Blocked("CLEANROOM_PROVIDER_READ_FAILED") from None


PIPE_READ_TIMEOUT_SECONDS = 5

def _read_pipe(fd_text, limit, label):
    """Bounded complete pipe frame, EOF required; single local reader only."""
    import select
    import time
    data=bytearray()
    try:
        fd=int(fd_text)
        if fd<3 or fd>1048576 or not stat.S_ISFIFO(os.fstat(fd).st_mode):
            raise Blocked(label)
        poll=select.poll()
        poll.register(fd,select.POLLIN|select.POLLHUP|select.POLLERR)
        deadline=time.monotonic()+PIPE_READ_TIMEOUT_SECONDS
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not poll.poll(max(1,int(remaining*1000))):
                raise Blocked(label)
            chunk=os.read(fd,min(4096,limit+1-len(data)))
            if time.monotonic()>deadline:
                raise Blocked(label)
            if not chunk:
                break
            data.extend(chunk)
            if len(data)>limit:
                raise Blocked(label)
        if not data:
            raise Blocked(label)
        return bytes(data)
    except (OSError,ValueError,TypeError,OverflowError):
        raise Blocked(label) from None
    finally:
        data[:]=b"\x00"*len(data)


def _inputs():
    if os.environ.get("CODESPACES","").lower()=="true":
        raise Blocked("NOT_INDEPENDENT_OWNER_CODESPACE")
    if os.environ.get("JW_PG_BACKUP_KEY"):
        raise Blocked("SOURCE_BACKUP_KEY_STILL_PRESENT")
    if os.environ.get("JW_PG_CLEANROOM_ACK")!=ACK:
        raise Blocked("EXPLICIT_CLEANROOM_CONSENT_REQUIRED")
    pin=os.environ.get("JW_PG_CLEANROOM_VAULT_SHA","")
    if not SHA1.fullmatch(pin):
        raise Blocked("PINNED_VAULT_COMMIT_REQUIRED")
    key_raw=bytearray(_read_pipe(
        os.environ.get("JW_PG_CLEANROOM_KEY_FD"),128,
        "EXTERNAL_KEY_PIPE_REQUIRED"))
    try:
        try:
            key=base64.urlsafe_b64decode(bytes(key_raw).strip())
        except (ValueError,binascii.Error):
            raise Blocked("EXTERNAL_KEY_ENCODING_INVALID") from None
        if len(key)!=32:
            raise Blocked("EXTERNAL_KEY_LENGTH_INVALID")
    finally:
        key_raw[:]=b"\x00"*len(key_raw)
    manifest_raw=_read_pipe(os.environ.get("JW_PG_CLEANROOM_MANIFEST_FD"),
                             MAX_MANIFEST,"PINNED_MANIFEST_PIPE_REQUIRED")
    try:
        doc=json.loads(manifest_raw)
    except (ValueError,UnicodeError):
        raise Blocked("EXTERNAL_MANIFEST_INVALID") from None
    if (not isinstance(doc,dict) or doc.get("vault_commit_sha1")!=pin
            or not isinstance(doc.get("archives"),list)
            or len(doc["archives"])!=11):
        raise Blocked("EXTERNAL_MANIFEST_ELEVEN_REQUIRED")
    pairs=[]
    for obj in doc["archives"]:
        if (not isinstance(obj,dict) or
                not SHA1.fullmatch(obj.get("blob_sha1","")) or
                not SHA256.fullmatch(obj.get("cipher_sha256",""))):
            raise Blocked("EXTERNAL_MANIFEST_DIGEST_INVALID")
        pairs.append((obj["blob_sha1"],obj["cipher_sha256"]))
    if len(set(x[0] for x in pairs))!=11:
        raise Blocked("EXTERNAL_MANIFEST_DUPLICATE_ARCHIVE")
    return pin,key,pairs


def _head_tree(pin):
    ref=_api(REPO+"/git/ref/heads/main")
    item=ref.get("object")
    if not isinstance(item,dict) or item.get("sha")!=pin:
        raise Blocked("VAULT_MAIN_CHANGED")
    commit=_api(REPO+"/git/commits/"+pin)
    tree=commit.get("tree")
    if (commit.get("sha")!=pin or not isinstance(tree,dict)
            or not SHA1.fullmatch(tree.get("sha",""))):
        raise Blocked("VAULT_COMMIT_TREE_INVALID")
    data=_api(REPO+"/git/trees/"+tree["sha"]+"?recursive=1")
    if (data.get("truncated") is not False
            or not isinstance(data.get("tree"),list)
            or not 11<=len(data["tree"])<=MAX_TREE):
        raise Blocked("VAULT_TREE_INVALID")
    digests=set()
    for o in data["tree"]:
        if not isinstance(o,dict):
            raise Blocked("VAULT_TREE_INVALID_ENTRY")
        if o.get("type")=="tree" and o.get("mode")=="040000":
            continue
        if (o.get("type")!="blob" or o.get("mode")!="100644" or
                not isinstance(o.get("path"),str) or
                not o["path"].endswith(".jwpgbk") or
                not SHA1.fullmatch(o.get("sha",""))):
            raise Blocked("VAULT_TREE_UNSAFE_ENTRY")
        digests.add(o["sha"])
    if len(digests)<11:
        raise Blocked("VAULT_TREE_TOO_FEW_UNIQUE_CIPHERS")
    return digests


def _download(blob_id, expected):
    data=_api(REPO+"/git/blobs/"+blob_id,budget=2*MAX_OBJECT+8192)
    content,size=data.get("content"),data.get("size")
    if (data.get("sha")!=blob_id or data.get("encoding")!="base64"
            or not isinstance(content,str) or not isinstance(size,int)
            or isinstance(size,bool) or not 24<size<=MAX_OBJECT
            or len(content)>2*MAX_OBJECT):
        raise Blocked("REMOTE_CIPHER_METADATA_INVALID")
    try:
        c=base64.b64decode("".join(content.split()),validate=True)
    except (ValueError,binascii.Error):
        raise Blocked("REMOTE_CIPHER_ENCODING_INVALID") from None
    if (len(c)!=size or
            hashlib.sha1(b"blob "+str(size).encode()+b"\0"+c).hexdigest()!=blob_id
            or hashlib.sha256(c).hexdigest()!=expected):
        raise Blocked("REMOTE_CIPHER_HASH_MISMATCH")
    return c


def _auth_all_chunks(cipher, key):
    """Authenticate every AES-GCM record in memory, including the final flag.

    This proves ciphertext decryptability with the supplied key but does NOT
    establish independent key custody or a successful PostgreSQL restoration.
    """
    magic = cipher[:8]
    if magic not in (b"JWPGBK1\n", b"JWPGBK2\n"):
        raise Blocked("ENCRYPTED_MAGIC_UNSUPPORTED")
    prefix_len = 8 if magic == b"JWPGBK2\n" else 4
    pos = 8 + prefix_len
    prefix = cipher[8:pos]
    aes = AESGCM(key)
    counter = 0
    while pos < len(cipher):
        if counter >= (2**32 if prefix_len == 8 else 2**64):
            raise Blocked("ENCRYPTED_CHUNK_COUNTER_EXHAUSTED")
        if len(cipher) - pos < 4:
            raise Blocked("ENCRYPTED_RECORD_TRUNCATED")
        size = struct.unpack(">I", cipher[pos:pos+4])[0]
        if not 16 <= size <= (1 << 20) + 16:
            raise Blocked("ENCRYPTED_RECORD_LENGTH_INVALID")
        start = pos + 4
        end = start + size
        if end > len(cipher):
            raise Blocked("ENCRYPTED_RECORD_TRUNCATED")
        nonce = (prefix + struct.pack(">I", counter)
                 if prefix_len == 8 else prefix + struct.pack(">Q", counter))
        final = end == len(cipher)
        aad = magic + struct.pack(">QB", counter, int(final))
        try:
            plain = aes.decrypt(nonce, cipher[start:end], aad)
        except (InvalidTag, ValueError):
            raise Blocked("ESCROW_RECOVERY_KEY_AUTHENTICATION_FAILED") from None
        if counter == 0 and not plain.startswith(b"PGDMP"):
            raise Blocked("DECRYPTED_ARCHIVE_NOT_PG_CUSTOM")
        pos = end
        counter += 1
    if counter == 0:
        raise Blocked("ENCRYPTED_RECORD_TRUNCATED")
    return True


def verify():
    result={
        "cleanroom_cryptographic_key_proof":"BLOCKED",
        "remote_cipher_authentication_count":0,
        "source_codespace_key_used":False,
        "plaintext_written_to_disk":False,
        "key_or_plaintext_exported":False,
        "independent_external_key_custody":"NOT_VERIFIED",
        "external_custodian_attestation":"NOT_VERIFIED",
        "immutable_retention":"NOT_VERIFIED",
        "historical_source_provenance":"NOT_VERIFIED",
        "overall":"BLOCKED",
    }
    try:
        pin,key,pairs=_inputs()
        if not set(k for k,_ in pairs)<=_head_tree(pin):
            raise Blocked("MANIFEST_BLOB_NOT_IN_PINNED_PRIVATE_VAULT")
        for blob,sha256 in pairs:
            c=_download(blob,sha256)
            _auth_all_chunks(c,key)
            result["remote_cipher_authentication_count"]+=1
        if result["remote_cipher_authentication_count"]==11:
            result["cleanroom_cryptographic_key_proof"]="PASS_11_REMOTE_CIPHERS_AUTHENTICATED"
    except Blocked as e:
        result["blocker"]=str(e)
    except Exception:
        result["blocker"]="CLEANROOM_RECOVERY_FAIL_CLOSED"
    return result


def main(argv=None):
    argv=sys.argv[1:] if argv is None else argv
    if argv!=["verify-external"]:
        print("USAGE: python -m scripts.p1_cleanroom_key_recovery_v223 verify-external",
              file=sys.stderr)
        return 2
    data=verify()
    print(json.dumps(data,sort_keys=True,separators=(",",":")))
    return 0 if data["cleanroom_cryptographic_key_proof"]=="PASS_11_REMOTE_CIPHERS_AUTHENTICATED" else 1


if __name__=="__main__":
    raise SystemExit(main())
