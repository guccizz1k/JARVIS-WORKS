"""Synthetic provider-only disaster recovery; no external data or key in CI."""
import base64
import hashlib
from pathlib import Path
import pytest
from scripts import p1_owner_remote_recovery_v223 as recover
from scripts import p1_owner_vault_readback_v223 as vault


def test_remote_provider_payload_checks_git_identity_and_cipher_sha(monkeypatch):
    b=b"JWPGBK2\n"+bytes(range(120))
    git=hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
    strong=hashlib.sha256(b).hexdigest()
    monkeypatch.setattr(vault,"_vault_api_json",lambda *a,**kw:{
        "sha":git,"size":len(b),"encoding":"base64",
        "content":base64.b64encode(b).decode()})
    obj=recover._cipher_from_provider(git,strong)
    assert bytes(obj)==b
    obj.clear()
    with pytest.raises(recover.Blocked,match="HASH_OR_MAGIC_MISMATCH"):
        recover._cipher_from_provider(git,"0"*64)


def test_remote_provider_base64_corruption_fails(monkeypatch):
    sha="a"*40
    monkeypatch.setattr(vault,"_vault_api_json",lambda *a,**kw:{
        "sha":sha,"size":30,"encoding":"base64","content":"%%%invalid"})
    with pytest.raises(recover.Blocked,match="ENCODING_INVALID"):
        recover._cipher_from_provider(sha,"b"*64)


@pytest.mark.parametrize("v",[
    (False,False,False), (True,False,False), (True,True,False)
])
def test_owner_approval_required_before_any_download(monkeypatch,v):
    owner,read,rest=v
    monkeypatch.setenv("CODESPACES","true" if owner else "false")
    if read:monkeypatch.setenv("JW_PG_VAULT_READBACK_ACK",vault.ACK)
    else:monkeypatch.delenv("JW_PG_VAULT_READBACK_ACK",raising=False)
    if rest:monkeypatch.setenv("JW_PG_REMOTE_RECOVERY_ACK",recover.ACK)
    else:monkeypatch.delenv("JW_PG_REMOTE_RECOVERY_ACK",raising=False)
    assert recover._preflight()!="PASS"


def test_zero_remote_download_when_docker_is_unavailable(monkeypatch):
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.setenv("JW_PG_VAULT_READBACK_ACK",vault.ACK)
    monkeypatch.setenv("JW_PG_REMOTE_RECOVERY_ACK",recover.ACK)
    monkeypatch.setenv("JW_PG_OFFLINE_RESTORE_ACK",recover.offline.ACK)
    monkeypatch.setenv(recover.PIN_ENV,"c"*40)
    monkeypatch.setattr(recover.offline,"_preflight",lambda:"DOCKER_UNAVAILABLE")
    assert recover.recover()["blocker"]=="NETWORKLESS_PG17_PRECONDITIONS_NOT_MET"


def test_provider_only_eleven_from_temporary_0600_cipher_never_owner_original(monkeypatch,tmp_path):
    local={}
    provider={}
    for i in range(11):
        payload=b"JWPGBK1\n"+bytes([i])*500
        git=hashlib.sha1(b"blob "+str(len(payload)).encode()+b"\0"+payload).hexdigest()
        sha=hashlib.sha256(payload).hexdigest()
        private_original=tmp_path/f"source_{i:02d}.jwpgbk"
        private_original.write_bytes(payload)
        private_original.chmod(0o600)
        local[git]=(private_original,sha,len(payload),(0,0,0,0))
        provider[git]=payload
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.setenv("JW_PG_VAULT_READBACK_ACK",vault.ACK)
    monkeypatch.setenv("JW_PG_REMOTE_RECOVERY_ACK",recover.ACK)
    monkeypatch.setenv("JW_PG_OFFLINE_RESTORE_ACK",recover.offline.ACK)
    monkeypatch.setenv(recover.PIN_ENV,"c"*40)
    monkeypatch.setattr(recover.offline,"_preflight",lambda:"PASS")
    monkeypatch.setattr(recover.backup,"load_key",lambda:b"K"*32)
    monkeypatch.setattr(recover.upload,"local_files",lambda:local)
    monkeypatch.setattr(vault,"_vault_api_readback",lambda hashes,pin:{
        "remote_commit_pinned":True,
        "readback_transport":"GH_REST_BLOB_BASE64_VERIFIED",
        "all_11_archives_offsite":True,
        "remote_unique_full_sha256_matches":11,
        "local_archives_not_offsite":0})
    def api(path,max_bytes=65536,timeout=45):
        sha=path.rsplit("/",1)[-1]
        b=provider[sha]
        return {"sha":sha,"size":len(b),"encoding":"base64",
                "content":base64.b64encode(b).decode()}
    monkeypatch.setattr(vault,"_vault_api_json",api)
    received=[]
    old_discover=recover.offline.owner.discover_owner_archive
    def synthetic_restore():
        archives,reason=recover.offline.owner.discover_owner_archive()
        assert reason=="REMOTE_ONLY_VERIFIED"
        assert len(archives)==11
        assert all(x not in {z[0] for z in local.values()} for x in archives)
        for p in archives:
            assert p.exists() and p.stat().st_mode & 0o777==0o600
            assert b"JWPGBK1\n"==p.read_bytes()[:8]
        received.extend(archives)
        return {"offline_restore_execution":"PASS_LOCAL_ONLY",
                "offline_restored_archive_count":11,
                "offline_65_table_archive_count":11,
                "offline_restore_failure_count":0,
                "offline_restore_skipped_budget_count":0,
                "container_removed":"PASS"}
    monkeypatch.setattr(recover.offline,"run_offline",synthetic_restore)
    report=recover.recover()
    assert report["remote_disaster_recovery"]=="PASS_ELEVEN_PROVIDER_CIPHERS_NETWORKLESS_PG17_RESTORED"
    assert report["provider_sha256_authenticated_download_count"]==11
    assert report["remote_only_disposable_pg17_restore_count"]==11
    assert report["remote_only_pg17_65_table_count"]==11
    assert report["source_database_contacted"] is False
    assert report["original_owner_ciphertexts_used_as_restore_input"] is False
    assert report["downloaded_temporary_ciphertexts_removed"]=="PASS"
    assert all(not x.exists() for x in received)
    assert recover.offline.owner.discover_owner_archive is old_discover
    assert report["overall"]=="BLOCKED"


def test_fail_closed_if_provider_11_not_attested(monkeypatch):
    monkeypatch.setattr(recover,"_preflight",lambda:"PASS")
    monkeypatch.setattr(recover.upload,"local_files",lambda:{
        str(i).zfill(40):(None,"a"*64,123,(0,0,0,0)) for i in range(11)})
    monkeypatch.setenv(recover.PIN_ENV,"d"*40)
    monkeypatch.setattr(vault,"_vault_api_readback",lambda *a:{
        "remote_commit_pinned":True,
        "all_11_archives_offsite":False,
        "remote_unique_full_sha256_matches":10})
    assert recover.recover()["blocker"]=="REMOTE_ELEVEN_OWNER_BACKUPS_NOT_INDEPENDENTLY_VERIFIED"


def test_remote_download_tampering_never_triggers_restore(monkeypatch):
    monkeypatch.setattr(recover,"_preflight",lambda:"PASS")
    local={}
    for i in range(11):
        local[str(i).zfill(40)]=(None,"a"*64,100,(0,0,0,0))
    monkeypatch.setattr(recover.upload,"local_files",lambda:local)
    monkeypatch.setenv(recover.PIN_ENV,"e"*40)
    monkeypatch.setattr(vault,"_vault_api_readback",lambda *a:{
        "remote_commit_pinned":True,
        "readback_transport":"GH_REST_BLOB_BASE64_VERIFIED",
        "all_11_archives_offsite":True,"remote_unique_full_sha256_matches":11,
        "local_archives_not_offsite":0})
    monkeypatch.setattr(recover,"_cipher_from_provider",
        lambda *a:(_ for _ in ()).throw(recover.Blocked("REMOTE_CIPHERTEXT_HASH_OR_MAGIC_MISMATCH")))
    monkeypatch.setattr(recover.offline,"run_offline",
        lambda:(_ for _ in ()).throw(AssertionError("restore on tamper forbidden")))
    assert recover.recover()["blocker"]=="REMOTE_CIPHERTEXT_HASH_OR_MAGIC_MISMATCH"
