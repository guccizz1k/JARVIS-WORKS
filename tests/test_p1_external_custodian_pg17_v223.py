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


def test_b2_offline_requires_reference_and_approval_before_key(monkeypatch):
    monkeypatch.setattr(e,"preflight",lambda:"PASS")
    monkeypatch.setattr(clean,"_inputs",lambda:pytest.fail("key read before staged gate"))
    monkeypatch.delenv("JW_PG_B2_OFFLINE_ACK",raising=False)
    staged=(b"{}", "0"*64, "/missing", "legacy")
    assert e.run(staged=staged)["blocker"]=="B2_OFFLINE_CATALOG_REFERENCE_REQUIRED"
    assert e.run(b"{}", "0"*64,catalog_required=True,staged=staged)["blocker"]=="B2_OFFLINE_APPROVAL_REQUIRED"
    monkeypatch.setenv("JW_PG_B2_OFFLINE_ACK",e.B2_ACK)
    monkeypatch.setenv("GH_TOKEN","synthetic")
    assert e.run(b"{}", "0"*64,catalog_required=True,staged=staged)["blocker"]=="B2_OFFLINE_PROVIDER_CREDENTIAL_PRESENT"
    monkeypatch.delenv("GH_TOKEN")
    for k in ("GITHUB_TOKEN","B2_APPLICATION_KEY","B2_APPLICATION_KEY_ID","AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY"):
        monkeypatch.delenv(k,raising=False)
    assert e.run(b"{}", "0"*64,catalog_required=True,staged=staged)["blocker"]=="B2_OFFLINE_CIPHERTEXT_SET_INVALID"

def test_b2_scope_mismatch_never_calls_provider_or_starts_container(monkeypatch):
    import hashlib
    monkeypatch.setattr(e,"preflight",lambda:"PASS")
    ids=[f"{i:040x}" for i in range(11)]
    pairs=[(i,"b"*64) for i in ids]
    monkeypatch.setenv("JW_WORM_OWNER_SCOPE_SHA256",e.equivalence.owner_scope(ids))
    monkeypatch.setattr(e,"_staged_inputs",lambda _:dict.fromkeys(ids,b"wrong"))
    monkeypatch.setattr(clean,"_inputs",lambda:("c"*40,b"K"*32,pairs))
    monkeypatch.setattr(e.catalog,"load_reference",lambda *a,**k:(None,None))
    class FakeComparison:
        def __init__(self,*args):pass
        def receipt(self,**kwargs):return {"normalized_archive_comparison":"BLOCKED"}
    monkeypatch.setattr(e.catalog,"CatalogComparison",FakeComparison)
    monkeypatch.setattr(clean,"_head_tree",lambda *_:pytest.fail("GitHub called"))
    monkeypatch.setattr(clean,"_download",lambda *_:pytest.fail("GitHub called"))
    monkeypatch.setattr(e.offline,"_docker",lambda *a,**kw:pytest.fail("Docker reached before binding"))
    receipt=e.run(b"{}", "0"*64,catalog_required=True,staged=(None,)*4)
    assert receipt["blocker"]=="B2_OFFLINE_OWNER_MANIFEST_MISMATCH"
    assert receipt["b2_staged_scope_bound"] is False
    assert receipt["overall"]=="BLOCKED"

def test_owner_site_requires_separate_approval_and_no_external_ack():
    env={"JW_PG_OWNER_SITE_ACK":e.OWNER_ACK}
    assert e.preflight({},owner_controlled=True)=="OWNER_SITE_APPROVAL_REQUIRED"
    assert e.preflight(dict(env,JW_PG_SECOND_SITE_ACK=e.ACK),owner_controlled=True)=="OWNER_SITE_EXTERNAL_ACK_CONFLICT"
    assert e.preflight(env,owner_controlled=True)=="OWNER_SITE_ISOLATION_ACK_REQUIRED"

def test_owner_key_pipe_strict_and_bounded(monkeypatch):
    r,w=os.pipe()
    try:
        os.write(w,base64.urlsafe_b64encode(b"K"*32))
        os.close(w);w=None
        monkeypatch.setenv("JW_PG_OWNER_KEY_FD",str(r))
        assert e._owner_key()==b"K"*32
    finally:
        os.close(r)
        if w is not None:os.close(w)
    monkeypatch.setenv("JW_PG_OWNER_KEY_FD","1")
    with pytest.raises(e.Blocked,match="OWNER_KEY_PIPE_INVALID"):e._owner_key()

def test_owner_scope_requires_staged_before_key(monkeypatch):
    monkeypatch.setattr(e,"preflight",lambda **kw:"PASS")
    monkeypatch.setattr(e,"_owner_key",lambda:pytest.fail("key read before gate"))
    monkeypatch.setattr(clean,"_inputs",lambda:pytest.fail("external inputs forbidden"))
    r=e.run(owner_controlled=True)
    assert r["blocker"]=="OWNER_SITE_STAGED_INPUT_REQUIRED"
    assert r["owner_site_restore"]=="BLOCKED"
    assert r["external_pg17_restore"]=="NOT_APPLICABLE_OWNER_SITE"

def test_owner_reference_pipe_no_external_fds_and_alias_denied(monkeypatch):
    for k in ("JW_PG_CLEANROOM_KEY_FD","JW_PG_CLEANROOM_MANIFEST_FD"):
        monkeypatch.delenv(k,raising=False)
    r,w=os.pipe()
    kr,kw=os.pipe()
    try:
        os.write(w,b'{"synthetic":true}')
        os.close(w);w=None
        monkeypatch.setenv("JW_PG_RESTORE_REFERENCE_FD",str(r))
        monkeypatch.setenv("JW_PG_OWNER_KEY_FD",str(kr))
        assert e._owner_reference_pipe()==b'{"synthetic":true}'
        monkeypatch.setenv("JW_PG_OWNER_KEY_FD",str(r))
        with pytest.raises(e.Blocked,match="OWNER_REFERENCE_PIPE_INVALID"):
            e._owner_reference_pipe()
        dup=os.dup(r)
        try:
            monkeypatch.setenv("JW_PG_OWNER_KEY_FD",str(dup))
            with pytest.raises(e.Blocked,match="OWNER_REFERENCE_PIPE_INVALID"):
                e._owner_reference_pipe()
        finally:os.close(dup)
    finally:
        for fd in (r,w,kr,kw):
            if fd is not None:os.close(fd)

def test_owner_cli_uses_owner_reference_pipe(monkeypatch,tmp_path,capsys):
    manifest=tmp_path/"manifest.json"
    manifest.write_bytes(b"{}")
    monkeypatch.setenv("JW_PG_B2_OFFLINE_ACK",e.B2_ACK)
    monkeypatch.setenv("JW_PG_B2_MANIFEST_PATH",str(manifest))
    monkeypatch.setenv("JW_PG_B2_STAGE_DIRECTORY",str(tmp_path))
    monkeypatch.setenv("JW_PG_B2_SCOPE","legacy")
    monkeypatch.setattr(e,"preflight",lambda **kw:"PASS")
    monkeypatch.setattr(e,"_owner_reference_pipe",lambda:b"synthetic")
    monkeypatch.setattr(e.equivalence,"read_reference_pipe",lambda *_:pytest.fail("external pipe used"))
    def run(raw,pin,**kw):
        assert raw==b"synthetic" and kw["owner_controlled"] is True
        return dict(owner_site_restore="PASS_ELEVEN_OWNER_SITE_CIPHERS",
            b2_staged_scope_bound=True,normalized_catalog_comparison="PASS_11_SCOPED_CATALOG_CHECKPOINTS",
            disposable_pg17_removed="PASS",overall="BLOCKED")
    monkeypatch.setattr(e,"run",run)
    assert e.main(["restore-owner-b2-offline-catalog"])==0
    assert "PASS_ELEVEN_OWNER_SITE_CIPHERS" in capsys.readouterr().out
