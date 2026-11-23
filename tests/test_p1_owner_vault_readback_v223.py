"""Owner private ciphertext readback synthetic Git objects only, no network."""
import hashlib
import subprocess
from pathlib import Path
import pytest
from scripts import p1_owner_vault_readback_v223 as vault

def repo_fixture(tmp_path):
    repo=tmp_path/"vault"
    subprocess.run(["git","init","-q",str(repo)],check=True)
    blob=b"JWPGBK1\nsynthetic-no-real-customer-data"
    f=repo/"synthetic.jwpgbk";f.write_bytes(blob);f.chmod(0o600)
    subprocess.run(["git","add","synthetic.jwpgbk"],cwd=repo,check=True)
    subprocess.run(["git","-c","user.email=synthetic@example.invalid",
        "-c","user.name=synthetic","commit","-q","-m","test ciphertext"],
        cwd=repo,check=True)
    sha=subprocess.run(["git","rev-parse","HEAD:synthetic.jwpgbk"],cwd=repo,
        check=True,capture_output=True,text=True).stdout.strip()
    return repo,f,sha,blob

def test_real_git_object_matches_ciphertest_sha256_without_plaintext(tmp_path,monkeypatch):
    repo,f,sha,blob=repo_fixture(tmp_path)
    monkeypatch.setattr(vault.owner,"_private_cipher_file",lambda p:Path(p)==f)
    localsha,local256=vault.local_hash(f)
    assert localsha==sha
    assert local256==hashlib.sha256(blob).hexdigest()
    assert vault.remote_sha256(repo,sha)==(local256,len(blob))
    result=vault.compare([sha],{sha:local256},repo)
    assert result["remote_full_sha256_readback_matches"]==1
    assert result["remote_readback"]=="PASS_MATCHED_REMOTE_CIPHERTEXT"
    assert result["all_11_archives_offsite"] is False
    assert sha not in str(result) and str(tmp_path) not in str(result)

def test_git_object_without_matching_local_archive_fails_only_offsite_equality(tmp_path):
    repo,f,sha,blob=repo_fixture(tmp_path)
    r=vault.compare([sha],{"0"*40:"a"*64},repo)
    assert r["remote_full_sha256_readback_matches"]==0
    assert r["remote_readback"]=="BLOCKED_REMOTE_NOT_LOCAL"

def test_tree_rejects_unsafe_git_entries_and_non_ciphertext():
    sha=b"a"*40
    assert vault.remote_blobs(b"100644 blob "+sha+b"\tbackup/test.jwpgbk\0")==["a"*40]
    for raw in (
        b"100644 blob "+sha+b"\tbackup/test.jwpgbk",
        b"120000 blob "+sha+b"\tbackup/test.jwpgbk\0",
        b"100644 blob "+sha+b"\t../../e.jwpgbk\0",
        b"100644 blob "+sha+b"\tbackup/key.txt\0",
        b"100644 blob "+sha+b"\tbackup/test.jwpgbk\0"*2,
        b"",
    ):
        with pytest.raises(vault.Blocked):vault.remote_blobs(raw)

@pytest.mark.parametrize("unsafe",["","abc","Z"*40,"../../../../evil"])
def test_invalid_git_sha_never_invokes_cat_file(tmp_path,unsafe):
    with pytest.raises(vault.Blocked):vault.remote_sha256(tmp_path,unsafe)

def test_owner_only_guard_and_pinned_vault_head(monkeypatch):
    monkeypatch.delenv("CODESPACES",raising=False)
    assert vault.audit()["blocker"]=="OWNER_CODESPACE_REQUIRED"
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.delenv("JW_PG_VAULT_READBACK_ACK",raising=False)
    assert vault.audit()["blocker"]=="EXPLICIT_READBACK_APPROVAL_REQUIRED"
    monkeypatch.setenv("JW_PG_VAULT_READBACK_ACK",vault.ACK)
    monkeypatch.delenv("JW_PG_VAULT_EXPECTED_SHA",raising=False)
    assert vault.audit()["blocker"]=="EXPECTED_REMOTE_COMMIT_REQUIRED"

def test_local_file_permission_checks(tmp_path,monkeypatch):
    f=tmp_path/"synthetic.jwpgbk";f.write_bytes(b"cipher")
    f.chmod(0o644)
    monkeypatch.setattr(vault.owner,"_private_cipher_file",lambda p: True)
    with pytest.raises(vault.Blocked,match="LOCAL_CIPHERTEXT_UNSAFE"):
        vault.local_hash(f)
    f.chmod(0o600)
    link=tmp_path/"link.jwpgbk";link.symlink_to(f)
    monkeypatch.setattr(vault.owner,"_private_cipher_file",lambda p: False)
    with pytest.raises(vault.Blocked,match="PERMISSIONS_INVALID"):
        vault.local_hash(link)

def test_cli_can_pass_readback_without_misrepresenting_release(monkeypatch,capsys):
    monkeypatch.setattr(vault,"audit",lambda:{
        "remote_readback":"PASS_MATCHED_REMOTE_CIPHERTEXT",
        "temporary_clone_removed":"PASS","all_11_archives_offsite":False,
        "historical_source_signer_verified":False,
        "independent_key_escrow_verified":False,"overall":"BLOCKED"})
    assert vault.main(["readback"])==0
    out=capsys.readouterr().out
    assert '"overall":"BLOCKED"' in out
    assert '"independent_key_escrow_verified":false' in out
    assert vault.main(["other"])==2



def test_duplicate_remote_ciphertext_paths_are_valid_but_duplicate_paths_fail():
    # 2026-11-23 real private vault metadata: four encrypted paths,
    # three unique blobs. The original parser mistakenly rejected this.
    a=b"a"*40
    b=b"b"*40
    entry=lambda sha,name:b"100644 blob "+sha+b"\t"+name+b"\0"
    valid=entry(a,b"archives/one.jwpgbk")+entry(a,b"backups/two.jwpgbk")+entry(b,b"backups/three.jwpgbk")
    assert vault.remote_blobs(valid)==["a"*40,"a"*40,"b"*40]
    with pytest.raises(vault.Blocked):
        vault.remote_blobs(entry(a,b"archives/one.jwpgbk")*2)


def test_private_vault_manifest_mode_compares_local_git_hashes_without_auth(tmp_path,monkeypatch):
    repo,local_file,sha,_=repo_fixture(tmp_path)
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.setenv("JW_PG_VAULT_READBACK_ACK",vault.ACK)
    monkeypatch.setenv(vault.PINNED_ENV,"a"*40)
    monkeypatch.setenv(vault.MANIFEST_ENV,",".join([sha,sha,"b"*40]))
    monkeypatch.setattr(vault.owner,"discover_owner_archive",lambda:([local_file],"FOUND_ONE"))
    monkeypatch.setattr(vault.owner,"_private_cipher_file",lambda p:Path(p)==local_file)
    out=vault.manifest_diagnostic()
    assert out["manifest_diagnostic"]=="PASS_LOCAL_HASH_COMPARISON_EXECUTED"
    assert out["provider_file_entry_count"]==3
    assert out["provider_unique_git_blob_count"]==2
    assert out["provider_duplicate_content_entries"]==1
    assert out["provider_git_blob_id_matched_local_count"]==1
    assert out["provider_ciphertext_sha256_readback"]=="NOT_RUN"
    assert out["overall"]=="BLOCKED"
    assert vault.main(["diagnose-manifest"])==0


def test_manifest_mode_rejects_untrusted_metadata_or_missing_consent(monkeypatch):
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.delenv("JW_PG_VAULT_READBACK_ACK",raising=False)
    assert vault.manifest_diagnostic()["blocker"]=="EXPLICIT_READBACK_APPROVAL_REQUIRED"
    monkeypatch.setenv("JW_PG_VAULT_READBACK_ACK",vault.ACK)
    monkeypatch.setenv(vault.PINNED_ENV,"c"*40)
    for metadata in ("", "not-a-blob", "a"*39, "z"*40):
        monkeypatch.setenv(vault.MANIFEST_ENV,metadata)
        assert vault.manifest_diagnostic()["blocker"]=="TRUSTED_REMOTE_BLOB_LIST_REQUIRED"


def test_git_auth_probe_distinguishes_helper_vs_gh_cli_without_exposing_tokens(monkeypatch):
    import subprocess
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.setenv("JW_PG_VAULT_READBACK_ACK",vault.ACK)
    monkeypatch.setattr(vault.shutil,"which",lambda x:"/usr/bin/"+x)
    monkeypatch.setattr(vault,"git",lambda *a,**kw:subprocess.CompletedProcess([],128,b"",b"authentication failed token=secret"))
    def fake_run(cmd,**kw):
        assert "gh"==cmd[0] and kw["stdout"]==subprocess.PIPE
        return subprocess.CompletedProcess(cmd,0,b"true\n",b"")
    monkeypatch.setattr(subprocess,"run",fake_run)
    result=vault.auth_probe()
    assert result["auth_diagnostic"]=="GIT_HELPER_USING_DIFFERENT_CREDENTIALS"
    assert "secret" not in str(result)
    assert vault.main(["diagnose-auth"])==0


def test_approved_gh_token_retrieval_missing_permissions_fails_closed(monkeypatch,tmp_path):
    import subprocess
    monkeypatch.setenv("GH_TOKEN","synthetic-token-not-real")
    monkeypatch.setattr(vault.shutil,"which",lambda x:"/usr/bin/"+x)
    monkeypatch.setattr(vault,"git",lambda *a,**kw:subprocess.CompletedProcess([],128,b"",b"no access"))
    monkeypatch.setattr(subprocess,"run",lambda cmd,**kw:subprocess.CompletedProcess(cmd,1,b"",b"not found"))
    with pytest.raises(vault.Blocked,match="GH_TOKEN_MISSING_PRIVATE_VAULT_CONTENTS_READ"):
        vault._clone_with_approved_credentials(tmp_path,tmp_path/"temporary_checkout")
