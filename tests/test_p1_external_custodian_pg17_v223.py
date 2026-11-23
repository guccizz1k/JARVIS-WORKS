"""Synthetic only; never handle owner backups or owner key."""
import base64
import io
import json
import os
import struct

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scripts import p1_external_custodian_pg17_v223 as e
from scripts import p1_cleanroom_key_recovery_v223 as clean
from scripts import pg_backup_v223 as backup


def cipher(key,plain=b"PGDMP-synthetic-custom-archive",*,legacy=False,corrupt=False,nonce_seed=None):
    magic=backup.MAGIC_LEGACY if legacy else backup.MAGIC
    prefix=b"1234" if legacy else b"12345678"
    if nonce_seed is not None:
        prefix=nonce_seed.to_bytes(len(prefix), "big")
    payload=bytearray(magic+prefix)
    parts=(plain[:8],plain[8:])
    for counter,part in enumerate(parts):
        nonce=backup._nonce(prefix,counter)
        tag=bytearray(AESGCM(key).encrypt(
            nonce,part,backup._aad(counter,counter==len(parts)-1,magic)))
        if corrupt and counter==1:
            tag[-1]^=0x40
        payload.extend(struct.pack(">I",len(tag)))
        payload.extend(tag)
    return bytes(payload)


@pytest.mark.parametrize("legacy",[False,True])
def test_all_aead_records_recover_in_memory_only(legacy):
    key=b"K"*32
    raw=cipher(key,legacy=legacy)
    clear=e.decrypt_verified(raw,key)
    try:
        assert clear==b"PGDMP-synthetic-custom-archive"
    finally:
        clear.clear()
    assert len(clear)==0


@pytest.mark.parametrize("legacy",[False,True])
def test_second_record_corruption_is_denied(legacy):
    key=b"K"*32
    with pytest.raises(e.Blocked,match="AUTH_FAILED"):
        e.decrypt_verified(cipher(key,legacy=legacy,corrupt=True),key)


def test_wrong_key_or_truncated_ciphertext_is_denied():
    raw=cipher(b"K"*32)
    with pytest.raises(e.Blocked):
        e.decrypt_verified(raw,b"L"*32)
    with pytest.raises(e.Blocked):
        e.decrypt_verified(raw[:-3],b"K"*32)


@pytest.mark.parametrize("name,value,expected",[
    ("JW_PG_SECOND_SITE_ACK","","EXPLICIT_SECOND_SITE_APPROVAL_REQUIRED"),
    ("CODESPACES","true","SOURCE_CODESPACE_IS_NOT_AN_INDEPENDENT_SITE"),
    ("JW_PG_BACKUP_KEY","fake-secret","SOURCE_OR_PRODUCTION_CREDENTIAL_PRESENT"),
    ("DATABASE_URL","postgresql://internal","SOURCE_OR_PRODUCTION_CREDENTIAL_PRESENT"),
    ("JW_PG_CLEANROOM_ACK","","EXTERNAL_KEY_PIPE_APPROVAL_REQUIRED"),
    ("JW_PG_CLEANROOM_VAULT_SHA","not-sha","EXACT_PRIVATE_VAULT_COMMIT_REQUIRED"),
    ("DOCKER_HOST","tcp://untrusted.invalid:2375","REMOTE_DOCKER_DAEMON_BLOCKED"),
])
def test_second_site_preflight_fails_before_provider_or_docker(name,value,expected):
    environment={"JW_PG_SECOND_SITE_ACK":e.ACK,
                 "JW_PG_CLEANROOM_ACK":clean.ACK,
                 "JW_PG_CLEANROOM_VAULT_SHA":"b"*40,
                 "JW_WORM_OWNER_SCOPE_SHA256":"c"*64}
    environment[name]=value
    assert e.preflight(environment)==expected


def test_no_approval_never_contacts_provider_or_exposes_a_key(monkeypatch):
    monkeypatch.delenv("JW_PG_SECOND_SITE_ACK",raising=False)
    monkeypatch.setattr(clean,"_inputs",lambda:(_ for _ in ()).throw(
        AssertionError("A private pipe must not be read before consent")))
    assert e.run()["external_pg17_restore"]=="BLOCKED"
    assert e.run()["verified_provider_cipher_count"]==0


def test_external_site_status_cannot_forge_custody_or_worm(monkeypatch):
    """No test-fixture success may upgrade final custody/retention claims."""
    monkeypatch.setattr(e,"preflight",lambda:"PASS")
    monkeypatch.setattr(clean,"_inputs",lambda:("b"*40,b"K"*32,
        [("a"*39+str(i%10), "b"*64) for i in range(11)]))
    monkeypatch.setattr(clean,"_head_tree",lambda pin: {
        "a"*39+str(i%10) for i in range(11)})
    # Deliberately duplicate a provider blob to force strict fail closed.
    receipt=e.run()
    assert receipt["overall"]=="BLOCKED"
    assert receipt["independent_key_custody"]=="NOT_ATTESTED"
    assert receipt["independent_legal_retention"]=="NOT_ATTESTED"
    assert receipt["external_pg17_restore"]!="PASS_ELEVEN_PROVIDER_CIPHERS_NETWORKLESS_PG17"


def test_scope_pin_rejects_substitution_and_duplicate_before_provider(monkeypatch):
    import hashlib
    ids = [f"{i:040x}" for i in range(12)]
    pairs = [(x, "b"*64) for x in ids[:11]]
    pin = hashlib.sha256(("JW-WORM-OWNER-SCOPE-V1\n" + "\n".join(ids[:11]) + "\n").encode()).hexdigest()
    e._require_owner_scope(list(reversed(pairs)), pin)
    with pytest.raises(e.Blocked, match="PIN_MISMATCH"):
        e._require_owner_scope(pairs[:-1]+[(ids[11], "b"*64)], pin)
    with pytest.raises(e.Blocked, match="DUPLICATE_ARCHIVE"):
        e._require_owner_scope(pairs[:-1]+[pairs[0]], pin)
    with pytest.raises(e.Blocked, match="PIN_REQUIRED"):
        e._require_owner_scope(pairs, "")
    monkeypatch.setenv("JW_WORM_OWNER_SCOPE_SHA256", pin)
    monkeypatch.setattr(e, "preflight", lambda: "PASS")
    monkeypatch.setattr(clean, "_inputs", lambda: ("c"*40, b"K"*32, pairs[:-1]+[(ids[11], "b"*64)]))
    monkeypatch.setattr(clean, "_head_tree", lambda _: pytest.fail("provider reached before owner pin"))
    monkeypatch.setattr(e.offline, "_docker", lambda *a, **kw: pytest.fail("Docker reached before owner pin"))
    report=e.run()
    assert report["blocker"]=="OWNER_SCOPE_PIN_MISMATCH"
    assert report["owner_scope_pin_checked"] is False
    assert report["verified_provider_cipher_count"]==0


def test_no_unknown_cli_commands_cause_restore(monkeypatch):
    monkeypatch.setattr(e,"run",lambda:(_ for _ in ()).throw(
        AssertionError("unexpected restore")))
    assert e.main(["upload-key"])==2
