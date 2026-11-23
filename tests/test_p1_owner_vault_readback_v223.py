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
