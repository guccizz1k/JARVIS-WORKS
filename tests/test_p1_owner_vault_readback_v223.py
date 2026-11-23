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



def test_vault_only_codespaces_fine_grained_secret_does_not_replace_source_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN","SOURCE_ONLY_PLACEHOLDER")
    monkeypatch.setenv("JW_VAULT_READ_TOKEN","VAULT_READ_ONLY_PLACEHOLDER")
    monkeypatch.delenv("GH_TOKEN",raising=False)
    child=vault._vault_cli_env()
    assert child["GH_TOKEN"]=="VAULT_READ_ONLY_PLACEHOLDER"
    assert "JW_VAULT_READ_TOKEN" not in child
    assert "GITHUB_TOKEN" not in child
    assert os.environ["GITHUB_TOKEN"]=="SOURCE_ONLY_PLACEHOLDER"
    assert os.environ["JW_VAULT_READ_TOKEN"]=="VAULT_READ_ONLY_PLACEHOLDER"


def test_vault_specific_token_never_passes_into_git_clone_process(monkeypatch):
    import subprocess
    monkeypatch.setenv("JW_VAULT_READ_TOKEN","PRIVATE_VAULT_READ_PLACEHOLDER")
    def fake(cmd,**kwargs):
        assert "JW_VAULT_READ_TOKEN" not in kwargs["env"]
        assert kwargs["stderr"]==subprocess.DEVNULL
        return subprocess.CompletedProcess(cmd,128,b"",b"not permitted")
    monkeypatch.setattr(subprocess,"run",fake)
    result=vault.git(["ls-remote","--heads",vault.VAULT,"main"])
    assert result.returncode==128



def test_diagnose_remote_one_shot_wont_read_archive_if_private_auth_denied(monkeypatch,capsys):
    monkeypatch.setattr(vault,"auth_probe",lambda:{
        "auth_diagnostic":"CODESPACE_CREDENTIAL_CANNOT_READ_PRIVATE_VAULT",
        "git_read_only_private_access":"BLOCKED",
        "gh_cli_private_api_access":"BLOCKED"})
    monkeypatch.setattr(vault,"audit",lambda:(_ for _ in ()).throw(
        AssertionError("unauthorized remote download attempted")))
    assert vault.main(["diagnose-remote"])==0
    import json
    report=json.loads(capsys.readouterr().out)
    assert report["remote_readback"]=="NOT_RUN_AUTHORIZATION_REQUIRED"
    assert report["overall"]=="BLOCKED"


def test_diagnose_remote_authorized_calls_actual_cipher_readback_but_not_release(monkeypatch,capsys):
    monkeypatch.setattr(vault,"auth_probe",lambda:{
        "auth_diagnostic":"GIT_HELPER_USING_DIFFERENT_CREDENTIALS",
        "gh_cli_private_api_access":"PASS"})
    calls=[]
    def recovered():
        calls.append(1)
        return {"remote_readback":"PASS_MATCHED_REMOTE_CIPHERTEXT",
                "remote_unique_full_sha256_matches":2,
                "local_archives_not_offsite":9,
                "all_11_archives_offsite":False,
                "overall":"BLOCKED"}
    monkeypatch.setattr(vault,"audit",recovered)
    assert vault.main(["diagnose-remote"])==0
    import json
    result=json.loads(capsys.readouterr().out)
    assert calls==[1]
    assert result["remote_unique_full_sha256_matches"]==2
    assert result["local_archives_not_offsite"]==9
    assert result["all_11_archives_offsite"] is False
    assert result["overall"]=="BLOCKED"



def test_real_cause_gh_private_access_but_git_blobless_clone_fail_prevented(
    monkeypatch,tmp_path
):
    """2026-11-23 16:25 owner: Git helper BLOCKED, gh private API PASS,
    clone could succeed, but its --filter=blob:none lazy cat-file fails.
    Verify no git clone/cat-file even attempted and pinned API is used.
    """
    import os
    from pathlib import Path
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.setenv("JW_PG_VAULT_READBACK_ACK",vault.ACK)
    head="a"*40
    monkeypatch.setenv("JW_PG_VAULT_EXPECTED_SHA",head)
    f=tmp_path/"owner-only.jwpgbk"
    f.write_bytes(b"JWPGBK1\x00synthetic_private_cipher")
    f.chmod(0o600)
    monkeypatch.setattr(vault.owner,"discover_owner_archive",lambda:([f],"ONE_SYNTHETIC"))
    monkeypatch.setattr(vault.owner,"_private_cipher_file",lambda p:Path(p)==f)
    monkeypatch.setattr(vault.shutil,"which",lambda prog:"/usr/bin/"+prog)
    monkeypatch.setattr(vault,"auth_probe",lambda:{
        "auth_diagnostic":"GIT_HELPER_USING_DIFFERENT_CREDENTIALS",
        "git_read_only_private_access":"BLOCKED",
        "gh_cli_private_api_access":"PASS"})
    monkeypatch.setattr(vault,"_clone_with_approved_credentials",
        lambda *a,**kw:(_ for _ in ()).throw(
            AssertionError("do not clone partial Git blob tree")))
    called=[]
    def api(local,pin):
        called.append((len(local),pin))
        return {"remote_readback":"BLOCKED_REMOTE_NOT_LOCAL",
                "remote_ciphertext_count":4,
                "remote_unique_ciphertext_count":3,
                "remote_full_sha256_readback_matches":2,
                "remote_unique_full_sha256_matches":2,
                "remote_unmatched_ciphertext_count":1,
                "local_archives_not_offsite":9,
                "readback_transport":"GH_REST_BLOB_BASE64_VERIFIED",
                "remote_commit_pinned":True,
                "all_11_archives_offsite":False}
    monkeypatch.setattr(vault,"_vault_api_readback",api)
    result=vault.audit()
    assert called==[(1,head)]
    assert result["readback_transport"]=="GH_REST_BLOB_BASE64_VERIFIED"
    assert result["remote_readback"]=="BLOCKED_REMOTE_NOT_LOCAL"
    assert result["temporary_clone_removed"]=="PASS"
    assert result["overall"]=="BLOCKED"


def test_partial_clone_lazy_catfile_size_failure_retries_only_authorized_rest(
    monkeypatch,tmp_path
):
    import subprocess
    from pathlib import Path
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.setenv("JW_PG_VAULT_READBACK_ACK",vault.ACK)
    pin="b"*40
    monkeypatch.setenv("JW_PG_VAULT_EXPECTED_SHA",pin)
    encrypted=tmp_path/"local.jwpgbk"
    encrypted.write_bytes(b"JWPGBK2\x00unrelated_fixture")
    encrypted.chmod(0o600)
    monkeypatch.setattr(vault.owner,"discover_owner_archive",lambda:([encrypted],"ONE"))
    monkeypatch.setattr(vault.owner,"_private_cipher_file",lambda p:Path(p)==encrypted)
    monkeypatch.setattr(vault.shutil,"which",lambda x:"/usr/bin/"+x)
    monkeypatch.setattr(vault,"auth_probe",lambda:{
        "git_read_only_private_access":"PASS","gh_cli_private_api_access":"PASS"})
    monkeypatch.setattr(vault,"_clone_with_approved_credentials",lambda *a,**kw:None)
    def simulate_git(cmd,dir=None,timeout=60):
        if cmd[0]=="rev-parse":
            return subprocess.CompletedProcess(cmd,0,(pin+"\n").encode(),b"")
        if cmd[0]=="ls-tree":
            sha="c"*40
            return subprocess.CompletedProcess(cmd,0,
                b"100644 blob "+sha.encode()+b"\tarchived.jwpgbk\0",b"")
        raise AssertionError("unexpected network command")
    monkeypatch.setattr(vault,"git",simulate_git)
    monkeypatch.setattr(vault,"remote_sha256",
        lambda *args:(_ for _ in ()).throw(vault.Blocked("GIT_BLOB_SIZE_UNKNOWN")))
    calls=[]
    monkeypatch.setattr(vault,"_vault_api_readback",
        lambda local,head:(calls.append(1) or {
            "remote_readback":"BLOCKED_REMOTE_NOT_LOCAL",
            "readback_transport":"GH_REST_BLOB_BASE64_VERIFIED",
            "all_11_archives_offsite":False}))
    result=vault.audit()
    assert calls==[1]
    assert result["readback_transport"]=="GH_REST_BLOB_BASE64_VERIFIED"
    assert result["overall"]=="BLOCKED"


def test_corrupt_ciphertext_hash_never_falls_back_to_hide_integrity_failure(
    monkeypatch,tmp_path
):
    import subprocess
    from pathlib import Path
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.setenv("JW_PG_VAULT_READBACK_ACK",vault.ACK)
    pin="b"*40
    monkeypatch.setenv("JW_PG_VAULT_EXPECTED_SHA",pin)
    encrypted=tmp_path/"owner.jwpgbk"
    encrypted.write_bytes(b"JWPGBK1\x00integrity_control")
    encrypted.chmod(0o600)
    monkeypatch.setattr(vault.owner,"discover_owner_archive",lambda:([encrypted],"ONE"))
    monkeypatch.setattr(vault.owner,"_private_cipher_file",lambda p:Path(p)==encrypted)
    monkeypatch.setattr(vault.shutil,"which",lambda x:"/usr/bin/"+x)
    monkeypatch.setattr(vault,"auth_probe",lambda:{
        "git_read_only_private_access":"PASS","gh_cli_private_api_access":"PASS"})
    monkeypatch.setattr(vault,"_clone_with_approved_credentials",lambda *a,**kw:None)
    def git_ok(cmd,dir=None,timeout=60):
        if cmd[0]=="rev-parse":
            return subprocess.CompletedProcess(cmd,0,(pin+"\n").encode(),b"")
        if cmd[0]=="ls-tree":
            return subprocess.CompletedProcess(cmd,0,
                b"100644 blob "+b"c"*40+b"\tarchived.jwpgbk\0",b"")
        raise AssertionError("unexpected")
    monkeypatch.setattr(vault,"git",git_ok)
    monkeypatch.setattr(vault,"remote_sha256",lambda *a:("f"*64,100))
    monkeypatch.setattr(vault,"_vault_api_readback",
        lambda *a:(_ for _ in ()).throw(
            AssertionError("never bypass cryptographic mismatch")))
    # Not the local Git SHA -> may report NOT_LOCAL, not a digest mismatch.
    # Force the *same* Git SHA with a malicious SHA256 value.
    real_git_sha=vault.local_hash(encrypted)[0]
    def source_git(cmd,dir=None,timeout=60):
        if cmd[0]=="rev-parse":
            return subprocess.CompletedProcess(cmd,0,(pin+"\n").encode(),b"")
        if cmd[0]=="ls-tree":
            return subprocess.CompletedProcess(cmd,0,
                b"100644 blob "+real_git_sha.encode()+b"\tarchived.jwpgbk\0",b"")
        raise AssertionError("unexpected")
    monkeypatch.setattr(vault,"git",source_git)
    result=vault.audit()
    assert result["blocker"]=="REMOTE_CIPHERTEXT_SHA256_MISMATCH"
    assert result["remote_readback"]=="NOT_RUN"
    assert result["overall"]=="BLOCKED"



def test_all_11_owner_ciphertexts_can_pass_with_unrelated_private_vault_blob_and_duplicate_path(
    monkeypatch,tmp_path
):
    """A remaining historical extra + duplicate ciphertext must not prevent
    source-owner 11/11 coverage PASS after correctly authorized backup copy.
    """
    sha=[f"{i:040x}" for i in range(1,13)]
    content={key:(f"{i:064x}",100+i) for i,key in enumerate(sha,1)}
    local={key:content[key][0] for key in sha[:11]}
    all_remote=sha[:11]+[sha[11],sha[0]]
    observed=[]
    def remote_reader(key):
        observed.append(key)
        return content[key]
    r=vault.compare(all_remote,local,None,remote_reader=remote_reader)
    assert len(observed)==12 and len(set(observed))==12  # duplicate not downloaded twice
    assert r["remote_ciphertext_count"]==13
    assert r["remote_unique_ciphertext_count"]==12
    assert r["remote_duplicate_content_entries"]==1
    assert r["remote_unmatched_ciphertext_count"]==1
    assert r["remote_unique_ciphertexts_not_in_owner"]==1
    assert r["remote_full_sha256_readback_matches"]==12
    assert r["remote_unique_full_sha256_matches"]==11
    assert r["local_archives_not_offsite"]==0
    assert r["all_11_archives_offsite"] is True
    assert r["remote_readback"]=="PASS_ALL_11_OWNER_ARCHIVES_VERIFIED"


def test_remote_verified_4_entries_3_unique_2_matched_and_9_missing_stays_blocked():
    sha=[f"{i:040x}" for i in range(1,12)]
    local={x:"f"*64 for x in sha}
    remote=[sha[0],sha[1],sha[0],"a"*40]
    called=[]
    def verified(key):
        called.append(key)
        return ("f"*64,485000)
    r=vault.compare(remote,local,None,remote_reader=verified)
    assert len(called)==3
    assert r["remote_ciphertext_count"]==4
    assert r["remote_unique_ciphertext_count"]==3
    assert r["remote_duplicate_content_entries"]==1
    assert r["remote_full_sha256_readback_matches"]==3
    assert r["remote_unique_full_sha256_matches"]==2
    assert r["remote_unique_ciphertexts_not_in_owner"]==1
    assert r["local_archives_not_offsite"]==9
    assert r["all_11_archives_offsite"] is False
    assert r["remote_readback"]=="BLOCKED_REMOTE_NOT_LOCAL"


def test_remote_forget_one_owner_archive_always_fails_even_with_many_remote_duplicates():
    sha=[f"{i:040x}" for i in range(1,12)]
    local={x:"e"*64 for x in sha}
    remote=sha[:10]+[sha[0]]*4
    r=vault.compare(remote,local,None,remote_reader=lambda x:("e"*64,400))
    assert r["remote_unique_full_sha256_matches"]==10
    assert r["local_archives_not_offsite"]==1
    assert r["all_11_archives_offsite"] is False


def test_remote_sha256_tamper_cannot_be_hidden_by_duplicate_archive_path():
    owner_sha="a"*40
    remote=[owner_sha,owner_sha]
    with pytest.raises(vault.Blocked,match="SHA256_MISMATCH"):
        vault.compare(remote,{owner_sha:"f"*64},None,
                      remote_reader=lambda x:("0"*64,400))


def test_offsite_preflight_exposes_only_counts_never_performs_upload(monkeypatch,capsys):
    audit={
        "remote_commit_pinned":True,
        "temporary_clone_removed":"PASS",
        "readback_transport":"GH_REST_BLOB_BASE64_VERIFIED",
        "remote_ciphertext_count":4,
        "remote_unique_ciphertext_count":3,
        "remote_downloaded_unique_objects_count":3,
        "remote_unique_full_sha256_matches":2,
        "local_archives_not_offsite":9,
        "overall":"BLOCKED",
    }
    monkeypatch.setattr(vault,"audit",lambda:audit.copy())
    assert vault.main(["plan-offsite"])==0
    import json
    report=json.loads(capsys.readouterr().out)
    assert report["offsite_plan"]=="PASS_READ_ONLY_GAP_PREFLIGHT"
    assert report["missing_unique_archive_upload_candidates"]==9
    assert report["predicted_unique_ciphertexts_after_owner_approved_copy"]==12
    assert report["predicted_vault_file_entries_after_owner_approved_copy"]==13
    assert report["offsite_upload_execution"]=="NOT_RUN_REQUIRES_SEPARATE_APPROVAL"
    assert report["overall"]=="BLOCKED"


def test_offsite_preflight_refuses_unverified_provider_results(monkeypatch,capsys):
    monkeypatch.setattr(vault,"audit",lambda:{
       "remote_commit_pinned":False,"temporary_clone_removed":"NOT_STARTED",
       "remote_ciphertext_count":4,"remote_unique_ciphertext_count":3,
       "remote_downloaded_unique_objects_count":0,"local_archives_not_offsite":9,
       "overall":"BLOCKED"})
    assert vault.main(["plan-offsite"])==1
    assert "BLOCKED_INCOMPLETE_PROVIDER_EVIDENCE" in capsys.readouterr().out
