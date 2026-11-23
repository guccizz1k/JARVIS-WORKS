"""Owner private ciphertext readback synthetic Git objects only, no network."""
import hashlib
import os
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



def test_duplicate_remote_blob_paths_cannot_falsely_make_11_complete(monkeypatch,tmp_path):
    sha="a"*40
    monkeypatch.setattr(vault,"remote_sha256",lambda repo,x:("b"*64,10))
    out=vault.compare([sha,sha],{sha:"b"*64,"c"*40:"d"*64},tmp_path)
    assert out["remote_ciphertext_count"]==2
    assert out["remote_unique_ciphertext_count"]==1
    assert out["remote_duplicate_content_entries"]==1
    assert out["remote_full_sha256_readback_matches"]==2
    assert out["remote_unique_full_sha256_matches"]==1
    assert out["local_archives_not_offsite"]==1
    assert out["all_11_archives_offsite"] is False


def test_gh_cli_can_be_authorized_without_extra_token_env(monkeypatch,tmp_path):
    import subprocess
    monkeypatch.delenv("GH_TOKEN",raising=False)
    monkeypatch.setattr(vault.shutil,"which",lambda x:"/usr/bin/"+x)
    monkeypatch.setattr(vault,"git",lambda *a,**kw:subprocess.CompletedProcess([],128,b"",b""))
    called=[]
    def fake_run(cmd,**kw):
        called.append(cmd[:2])
        if cmd[:2]==["gh","api"]:
            return subprocess.CompletedProcess(cmd,0,b"true\n",b"")
        if cmd[:2]==["gh","repo"]:
            return subprocess.CompletedProcess(cmd,0,b"",b"")
        raise AssertionError("unknown command")
    monkeypatch.setattr(subprocess,"run",fake_run)
    vault._clone_with_approved_credentials(tmp_path,tmp_path/"testclone")
    assert called==[["gh","api"],["gh","repo"]]



def test_real_one_shot_codespaces_cli_offline_manifest_synthetic_11_archives(tmp_path):
    """End-to-end invoke the EXACT mobile owner's diagnostic module command.

    No Codespaces authentication, no network, no secret, no owner backups.
    Fixture recreates original owner archive discovery layout and permissions.
    """
    import json
    import os
    import sys
    root=tmp_path/"isolated-owner"
    backup_root=root/".local"/"share"/"jw-v223-restore"/"backups"
    folder=backup_root/"jw_v223_synthetic-only"
    folder.mkdir(parents=True,mode=0o700)
    backup_root.chmod(0o700)
    folder.chmod(0o700)
    shas=[]
    for i in range(11):
        file=folder/f"synthetic-{i:02d}.jwpgbk"
        data=b"JWPGBK1\n"+f"NON_CUSTOMER_TEST_{i:02d}".encode()*2
        file.write_bytes(data)
        file.chmod(0o600)
        blob=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
        shas.append(blob)
    env=os.environ.copy()
    env.update({
        "HOME":str(root),
        "CODESPACES":"true",
        "JW_PG_VAULT_READBACK_ACK":vault.ACK,
        vault.PINNED_ENV:"c"*40,
        vault.MANIFEST_ENV:",".join([shas[0],shas[1],shas[2],shas[0]]),
        "PYTHONDONTWRITEBYTECODE":"1",
    })
    result=subprocess.run(
        [sys.executable,"-m","scripts.p1_owner_vault_readback_v223",
         "diagnose-manifest"],
        env=env,check=False,capture_output=True,text=True,timeout=30)
    assert result.returncode==0, (result.returncode,result.stdout[:200])
    report=json.loads(result.stdout)
    assert report["local_archive_count"]==11
    assert report["manifest_diagnostic"]=="PASS_LOCAL_HASH_COMPARISON_EXECUTED"
    assert report["provider_file_entry_count"]==4
    assert report["provider_unique_git_blob_count"]==3
    assert report["provider_duplicate_content_entries"]==1
    assert report["provider_git_blob_id_matched_local_count"]==3
    assert report["owner_archives_not_in_provider_manifest"]==8
    assert report["provider_ciphertext_sha256_readback"]=="NOT_RUN"
    assert report["overall"]=="BLOCKED"
    assert all(sha not in result.stdout for sha in shas)
    assert str(root) not in result.stdout



def test_diagnose_all_auth_blocked_still_finishes_local_manifest_without_false_pass(monkeypatch,capsys):
    local={"manifest_diagnostic":"PASS_LOCAL_HASH_COMPARISON_EXECUTED",
           "provider_file_entry_count":4, "provider_unique_git_blob_count":3,
           "provider_git_blob_id_matched_local_count":2,"overall":"BLOCKED"}
    monkeypatch.setattr(vault,"manifest_diagnostic",lambda:local.copy())
    monkeypatch.setattr(vault,"auth_probe",lambda:{
       "auth_diagnostic":"CODESPACE_CREDENTIAL_CANNOT_READ_PRIVATE_VAULT",
       "git_read_only_private_access":"BLOCKED",
       "gh_cli_private_api_access":"BLOCKED"})
    def no_remote():raise AssertionError("unauthorized archive download attempted")
    monkeypatch.setattr(vault,"audit",no_remote)
    assert vault.main(["diagnose-all"])==0
    import json
    report=json.loads(capsys.readouterr().out)
    assert report["remote_readback"]=="NOT_RUN_AUTHORIZATION_REQUIRED"
    assert report["overall"]=="BLOCKED"
    assert report["provider_unique_git_blob_count"]==3


def test_diagnose_all_authorized_attempts_exact_remote_readback_but_never_releases(monkeypatch,capsys):
    monkeypatch.setattr(vault,"manifest_diagnostic",lambda:{
       "manifest_diagnostic":"PASS_LOCAL_HASH_COMPARISON_EXECUTED","overall":"BLOCKED"})
    monkeypatch.setattr(vault,"auth_probe",lambda:{
       "auth_diagnostic":"GIT_HELPER_USING_DIFFERENT_CREDENTIALS"})
    calls=[]
    def readback():
       calls.append(1)
       return {"remote_readback":"PASS_MATCHED_REMOTE_CIPHERTEXT",
               "remote_full_sha256_readback_matches":4,
               "remote_unique_full_sha256_matches":3,
               "all_11_archives_offsite":False,"overall":"BLOCKED"}
    monkeypatch.setattr(vault,"audit",readback)
    assert vault.main(["diagnose-all"])==0
    assert calls==[1]
    import json
    x=json.loads(capsys.readouterr().out)
    assert x["remote_full_sha256_readback_matches"]==4
    assert x["all_11_archives_offsite"] is False
    assert x["overall"]=="BLOCKED"


def test_diagnose_all_halts_before_remote_on_unsafe_local_evidence(monkeypatch):
    monkeypatch.setattr(vault,"manifest_diagnostic",lambda:{
      "manifest_diagnostic":"BLOCKED","blocker":"UNSAFE_LOCAL_ARCHIVE"})
    monkeypatch.setattr(vault,"auth_probe",lambda:(_ for _ in ()).throw(
       AssertionError("must not contact remote")))
    assert vault.main(["diagnose-all"])==1



def test_vault_gh_cli_does_not_let_source_codespace_token_shadow_stored_login(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN","SOURCE_ONLY_FIXTURE_NOT_SECRET")
    monkeypatch.delenv("GH_TOKEN",raising=False)
    first=vault._vault_cli_env()
    assert "GITHUB_TOKEN" not in first and "GH_TOKEN" not in first
    assert os.environ.get("GITHUB_TOKEN")=="SOURCE_ONLY_FIXTURE_NOT_SECRET"
    monkeypatch.setenv("GH_TOKEN","VAULT_READ_ONLY_FIXTURE_NOT_SECRET")
    second=vault._vault_cli_env()
    assert "GITHUB_TOKEN" not in second
    assert second["GH_TOKEN"]=="VAULT_READ_ONLY_FIXTURE_NOT_SECRET"


def test_vault_gh_auth_probe_uses_secondary_login_not_source_token(monkeypatch):
    import subprocess
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.setenv("JW_PG_VAULT_READBACK_ACK",vault.ACK)
    monkeypatch.setenv("GITHUB_TOKEN","SOURCE_ONLY")
    monkeypatch.delenv("GH_TOKEN",raising=False)
    monkeypatch.setattr(vault.shutil,"which",lambda name:"/usr/bin/"+name)
    monkeypatch.setattr(vault,"git",lambda *args,**kw:
        subprocess.CompletedProcess([],128,b"",b"no private vault"))
    def runner(cmd,**kw):
        assert "GITHUB_TOKEN" not in kw["env"]
        assert kw["stderr"]==subprocess.DEVNULL
        return subprocess.CompletedProcess(cmd,0,b"true\n",b"")
    monkeypatch.setattr(subprocess,"run",runner)
    result=vault.auth_probe()
    assert result["gh_cli_private_api_access"]=="PASS"
    assert result["auth_diagnostic"]=="GIT_HELPER_USING_DIFFERENT_CREDENTIALS"


def test_readonly_gh_rest_binary_cipher_sha256_and_git_blob_integrity(monkeypatch):
    import base64
    import hashlib
    raw=b"JWPGBK1\x00\xfa\xfe\x10NONCUSTOMER_TEST_ENCRYPTED_CIPHER"
    sha=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
    good={"sha":sha,"size":len(raw),"encoding":"base64",
          "content":base64.b64encode(raw).decode()}
    monkeypatch.setattr(vault,"_vault_api_json",lambda *a,**kw:good)
    assert vault._vault_api_blob_sha256(sha)==(hashlib.sha256(raw).hexdigest(),len(raw))
    good["content"]=base64.b64encode(b"X"+raw[1:]).decode()
    with pytest.raises(vault.Blocked,match="GIT_BLOB_HASH_MISMATCH"):
        vault._vault_api_blob_sha256(sha)
    good["content"]="z%%%notbase64"
    with pytest.raises(vault.Blocked,match="BASE64_INVALID"):
        vault._vault_api_blob_sha256(sha)


def test_vault_api_tree_allows_duplicate_ciphertext_and_rejects_symlinks():
    token="a"*40
    data={"truncated":False,"tree":[
        {"type":"tree","mode":"040000","path":"archives"},
        {"type":"blob","mode":"100644","path":"archives/first.jwpgbk","sha":token,"size":99},
        {"type":"blob","mode":"100644","path":"archives/second.jwpgbk","sha":token,"size":99},
    ]}
    assert vault._vault_api_tree(data)==[token,token]
    data["tree"].append({"type":"blob","mode":"120000","path":"archives/evil.jwpgbk","sha":"b"*40,"size":19})
    with pytest.raises(vault.Blocked):
        vault._vault_api_tree(data)
    data.pop("tree")
    with pytest.raises(vault.Blocked):
        vault._vault_api_tree(data)


def test_vault_api_readback_with_4_paths_3_unique_preserves_offsite_block(monkeypatch):
    import hashlib
    sha_a,sha_b,sha_c="a"*40,"b"*40,"c"*40
    head="d"*40
    def provider(path,max_bytes=65536,timeout=45):
        if "/git/ref/heads/main" in path:
            return {"object":{"sha":head}}
        if "/git/commits/" in path:
            return {"sha":head,"tree":{"sha":"e"*40}}
        if "/git/trees/" in path:
            return {"truncated":False,"tree":[
                {"type":"blob","mode":"100644","path":f"archive/{i}.jwpgbk","sha":sha,"size":23}
                for i,sha in enumerate([sha_a,sha_b,sha_a,sha_c])]}
        raise AssertionError("bad resource")
    monkeypatch.setattr(vault.shutil,"which",lambda cmd:"/usr/bin/"+cmd)
    monkeypatch.setattr(vault,"_vault_api_json",provider)
    monkeypatch.setattr(vault,"_vault_api_blob_sha256",lambda sha:("f"*64,23))
    result=vault._vault_api_readback({sha_a:"f"*64,sha_b:"f"*64,
                                     **{str(i).zfill(40):"0"*64 for i in range(9)}},head)
    assert result["remote_ciphertext_count"]==4
    assert result["remote_unique_ciphertext_count"]==3
    assert result["remote_full_sha256_readback_matches"]==3
    assert result["remote_unique_full_sha256_matches"]==2
    assert result["local_archives_not_offsite"]==9
    assert result["all_11_archives_offsite"] is False
    assert result["remote_commit_pinned"] is True
    assert result["readback_transport"]=="GH_REST_BLOB_BASE64_VERIFIED"


def test_gh_api_refuses_using_untrusted_host_and_suppresses_all_stderr(monkeypatch):
    import subprocess
    monkeypatch.setenv("GITHUB_TOKEN","SOURCE_TOKEN_PRIVATE")
    def fake(cmd,**kw):
        assert cmd[0:2]==["gh","api"]
        assert "GITHUB_TOKEN" not in kw["env"]
        assert kw["stderr"]==subprocess.DEVNULL
        return subprocess.CompletedProcess(cmd,0,b'{"private": true}',b"token_not_logged")
    monkeypatch.setattr(subprocess,"run",fake)
    assert vault._vault_api_json("repos/guccizz1k/jw-backup-vault-261111/git/ref/heads/main")=={"private":True}
    with pytest.raises(vault.Blocked,match="ENDPOINT_INVALID"):
        vault._vault_api_json("repos/other/unsafe/data")
