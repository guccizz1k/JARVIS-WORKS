"""Synthetic two-site recovery proof. Never sees a user's backup key."""
import base64
import hashlib
import json
import os
import struct
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scripts import p1_cleanroom_key_recovery_v223 as c

def fixture(monkeypatch):
    key=b"Q"*32
    pin="b"*40
    content={}
    manifest=[]
    for i in range(11):
        prefix=(i+1).to_bytes(8,"big")
        chunk=b"PGDMP"+bytes([i])*256
        nonce=prefix+struct.pack(">I",0)
        tag=AESGCM(key).encrypt(nonce,chunk,b"JWPGBK2\n"+struct.pack(">QB",0,1))
        raw=b"JWPGBK2\n"+prefix+struct.pack(">I",len(tag))+tag
        blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
        strong=hashlib.sha256(raw).hexdigest()
        content[blob]=raw
        manifest.append({"blob_sha1":blob,"cipher_sha256":strong})
    def api(path,budget=65536):
        if path.endswith("git/ref/heads/main"):
            return {"object":{"sha":pin}}
        if "git/commits/" in path:
            return {"sha":pin,"tree":{"sha":"c"*40}}
        if "git/trees/" in path:
            return {"truncated":False,"tree":[{"type":"blob","mode":"100644",
                "path":f"owner/{i}.jwpgbk","sha":item["blob_sha1"]}
                for i,item in enumerate(manifest)]}
        if "git/blobs/" in path:
            blob=path.rsplit("/",1)[-1]
            data=content[blob]
            return {"sha":blob,"encoding":"base64",
                    "size":len(data),"content":base64.b64encode(data).decode()}
        raise AssertionError("unexpected external API")
    monkeypatch.setattr(c,"_api",api)
    monkeypatch.setenv("JW_PG_CLEANROOM_ACK",c.ACK)
    monkeypatch.setenv("JW_PG_CLEANROOM_VAULT_SHA",pin)
    monkeypatch.delenv("CODESPACES",raising=False)
    monkeypatch.delenv("JW_PG_BACKUP_KEY",raising=False)
    return key,{"vault_commit_sha1":pin,"archives":manifest},content

def fake_pipe(data):
    r,w=os.pipe()
    os.write(w,data)
    os.close(w)
    return r

def run_with_pipes(monkeypatch,key,manifest):
    keyfd=fake_pipe(base64.urlsafe_b64encode(key))
    manifestfd=fake_pipe(json.dumps(manifest).encode())
    try:
        monkeypatch.setenv("JW_PG_CLEANROOM_KEY_FD",str(keyfd))
        monkeypatch.setenv("JW_PG_CLEANROOM_MANIFEST_FD",str(manifestfd))
        return c.verify()
    finally:
        os.close(keyfd)
        os.close(manifestfd)

def test_eleven_authenticated_from_private_provider_with_independent_pipe_key(monkeypatch,capsys):
    key,manifest,_=fixture(monkeypatch)
    result=run_with_pipes(monkeypatch,key,manifest)
    assert result["cleanroom_cryptographic_key_proof"]=="PASS_11_REMOTE_CIPHERS_AUTHENTICATED"
    assert result["remote_cipher_authentication_count"]==11
    assert result["plaintext_written_to_disk"] is False
    assert result["key_or_plaintext_exported"] is False
    assert result["independent_external_key_custody"]=="NOT_VERIFIED"
    assert result["overall"]=="BLOCKED"
    assert base64.urlsafe_b64encode(key).decode() not in str(result)

def test_wrong_external_key_must_fail_cryptographic_auth(monkeypatch):
    _,manifest,_=fixture(monkeypatch)
    result=run_with_pipes(monkeypatch,b"B"*32,manifest)
    assert result["blocker"]=="ESCROW_RECOVERY_KEY_AUTHENTICATION_FAILED"
    assert result["remote_cipher_authentication_count"]==0
    assert result["overall"]=="BLOCKED"

def test_codespace_or_source_key_env_never_qualifies_as_cleanroom(monkeypatch):
    key,manifest,_=fixture(monkeypatch)
    monkeypatch.setenv("CODESPACES","true")
    result=run_with_pipes(monkeypatch,key,manifest)
    assert result["blocker"]=="NOT_INDEPENDENT_OWNER_CODESPACE"
    monkeypatch.setenv("CODESPACES","false")
    monkeypatch.setenv("JW_PG_BACKUP_KEY","SOURCE_SECRETS_MUST_NEVER_BE_USED")
    result=run_with_pipes(monkeypatch,key,manifest)
    assert result["blocker"]=="SOURCE_BACKUP_KEY_STILL_PRESENT"

def test_untrusted_manifest_pin_mismatch_or_duplicate_rejected(monkeypatch):
    key,manifest,_=fixture(monkeypatch)
    manifest["vault_commit_sha1"]="a"*40
    assert run_with_pipes(monkeypatch,key,manifest)["blocker"]=="EXTERNAL_MANIFEST_ELEVEN_REQUIRED"
    manifest["vault_commit_sha1"]="b"*40
    manifest["archives"][1]=manifest["archives"][0].copy()
    assert run_with_pipes(monkeypatch,key,manifest)["blocker"]=="EXTERNAL_MANIFEST_DUPLICATE_ARCHIVE"

def test_key_fd_must_be_a_pipe_no_regular_file(monkeypatch,tmp_path):
    key,manifest,_=fixture(monkeypatch)
    path=tmp_path/"synthetic_key"
    path.write_bytes(base64.urlsafe_b64encode(key))
    with open(path,"rb") as f:
        monkeypatch.setenv("JW_PG_CLEANROOM_KEY_FD",str(f.fileno()))
        mfd=fake_pipe(json.dumps(manifest).encode())
        try:
            monkeypatch.setenv("JW_PG_CLEANROOM_MANIFEST_FD",str(mfd))
            assert c.verify()["blocker"]=="EXTERNAL_KEY_PIPE_REQUIRED"
        finally:
            os.close(mfd)

def test_remote_ciphertext_bitflip_fails_before_key_auth(monkeypatch):
    key,manifest,store=fixture(monkeypatch)
    blob=manifest["archives"][0]["blob_sha1"]
    damaged=bytearray(store[blob])
    damaged[-1]^=1
    store[blob]=bytes(damaged)
    result=run_with_pipes(monkeypatch,key,manifest)
    assert result["blocker"]=="REMOTE_CIPHER_HASH_MISMATCH"
    assert result["remote_cipher_authentication_count"]==0

def test_ref_changed_is_blocked_even_if_blob_unchanged(monkeypatch):
    key,manifest,store=fixture(monkeypatch)
    old=c._api
    def changed(path,budget=65536):
        if path.endswith("git/ref/heads/main"):
            return {"object":{"sha":"d"*40}}
        return old(path,budget=budget)
    monkeypatch.setattr(c,"_api",changed)
    assert run_with_pipes(monkeypatch,key,manifest)["blocker"]=="VAULT_MAIN_CHANGED"

def test_missing_consent_or_malformed_fd_never_opens_provider(monkeypatch):
    _,manifest,_=fixture(monkeypatch)
    monkeypatch.delenv("JW_PG_CLEANROOM_ACK",raising=False)
    monkeypatch.setattr(c,"_api",lambda *args,**kwargs:(_ for _ in ()).throw(
        AssertionError("provider contacted without owner approval")))
    assert c.verify()["blocker"]=="EXPLICIT_CLEANROOM_CONSENT_REQUIRED"
    monkeypatch.setenv("JW_PG_CLEANROOM_ACK",c.ACK)
    monkeypatch.setenv("JW_PG_CLEANROOM_KEY_FD","bad-fd")
    assert c.verify()["blocker"]=="EXTERNAL_KEY_PIPE_REQUIRED"

def test_cli_rejects_other_actions_no_network(monkeypatch):
    monkeypatch.setattr(c,"verify",lambda:(_ for _ in ()).throw(
        AssertionError("must not invoke verify")))
    assert c.main(["upload"])==2

# New, scope-specific gate: the existing proof authenticated only record 0.
# A replaced provider blob plus a correspondingly updated manifest could pass
# even though a later record was not decryptable with the independent key.
def _multichunk_candidate(key, index=4, bad_tag=False, bad_length=False, legacy=False):
    magic=b"JWPGBK1\n" if legacy else b"JWPGBK2\n"
    prefix=index.to_bytes(4 if legacy else 8,"big")
    raw=bytearray(magic+prefix)
    for counter,plain in enumerate((b"PGDMP"+b"header"*24,b"second PG backup chunk")):
        nonce=prefix+struct.pack(">Q" if legacy else ">I",counter)
        aad=magic+struct.pack(">QB",counter,int(counter==1))
        encrypted=bytearray(AESGCM(key).encrypt(nonce,plain,aad))
        if counter==1 and bad_tag:
            encrypted[-1]^=1
        if counter==1 and bad_length:
            encrypted=encrypted[:8]
        raw.extend(struct.pack(">I",len(encrypted)))
        raw.extend(encrypted)
    return bytes(raw)


def _replace_manifest_archive(manifest,store,raw,index=4):
    digest=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
    store[digest]=raw
    manifest["archives"][index]={"blob_sha1":digest,
        "cipher_sha256":hashlib.sha256(raw).hexdigest()}


def test_new_second_record_aead_corruption_fails_closed_even_with_matching_manifest(monkeypatch):
    key,manifest,store=fixture(monkeypatch)
    _replace_manifest_archive(manifest,store,_multichunk_candidate(key,bad_tag=True))
    result=run_with_pipes(monkeypatch,key,manifest)
    assert result["cleanroom_cryptographic_key_proof"]=="BLOCKED"
    assert result["remote_cipher_authentication_count"]==4
    assert result["blocker"]=="ESCROW_RECOVERY_KEY_AUTHENTICATION_FAILED"


def test_new_second_record_too_short_fails_closed_even_with_matching_manifest(monkeypatch):
    key,manifest,store=fixture(monkeypatch)
    _replace_manifest_archive(manifest,store,_multichunk_candidate(key,bad_length=True))
    result=run_with_pipes(monkeypatch,key,manifest)
    assert result["cleanroom_cryptographic_key_proof"]=="BLOCKED"
    assert result["remote_cipher_authentication_count"]==4
    assert result["blocker"]=="ENCRYPTED_RECORD_LENGTH_INVALID"


def test_new_valid_two_record_v2_accepted_without_claiming_external_custody(monkeypatch):
    key,manifest,store=fixture(monkeypatch)
    _replace_manifest_archive(manifest,store,_multichunk_candidate(key))
    result=run_with_pipes(monkeypatch,key,manifest)
    assert result["cleanroom_cryptographic_key_proof"]=="PASS_11_REMOTE_CIPHERS_AUTHENTICATED"
    assert result["remote_cipher_authentication_count"]==11
    assert result["independent_external_key_custody"]=="NOT_VERIFIED"
    assert result["overall"]=="BLOCKED"


def test_new_valid_legacy_v1_two_record_archive_preserved(monkeypatch):
    key,manifest,store=fixture(monkeypatch)
    _replace_manifest_archive(manifest,store,_multichunk_candidate(key,legacy=True))
    result=run_with_pipes(monkeypatch,key,manifest)
    assert result["cleanroom_cryptographic_key_proof"]=="PASS_11_REMOTE_CIPHERS_AUTHENTICATED"
    assert result["remote_cipher_authentication_count"]==11
