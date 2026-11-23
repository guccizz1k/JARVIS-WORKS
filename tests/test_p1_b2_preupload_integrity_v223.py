"""Offline/negative tests for pre-upload 30-day COMPLIANCE scope proof.

Synthetic owner ciphertext only. No real private GitHub vault/B2 API calls,
no recovery key, upload credential, DB, provider write or customer data.
"""
import base64
import hashlib
import json
import os
import stat
import subprocess
from types import SimpleNamespace
import pytest

from scripts import p1_b2_preupload_integrity_v223 as gate


def fixture():
    raw={}
    for i in range(11):
        data=b"JWPGBK2\n"+bytes([i])*390+(i+1).to_bytes(8,"big")
        blob=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
        raw[blob]=(data,hashlib.sha256(data).hexdigest())
    local={k:v[1] for k,v in raw.items()}
    historical=b"JWPGBK1\n"+b"old-historical-encrypted-only"*20
    extra=hashlib.sha1(b"blob "+str(len(historical)).encode()+b"\0"+historical).hexdigest()
    tree_items=[{"type":"tree","mode":"040000","path":"owner-v223","sha":"e"*40}]
    for index,sha in enumerate([*local,extra,*list(local)[:1]]):
        tree_items.append({"type":"blob","mode":"100644","sha":sha,
                           "path":f"owner-v223/synthetic-{index:02}.jwpgbk"})
    assert len(tree_items)==14
    def get(path):
        assert path.startswith(gate.VAULT_REPO+"/git/")
        kind=path[len(gate.VAULT_REPO+"/git/"):]
        if kind=="ref/heads/main":
            return {"object":{"sha":gate.VAULT_SHA}}
        if kind=="commits/"+gate.VAULT_SHA:
            return {"sha":gate.VAULT_SHA,"tree":{"sha":"a"*40}}
        if kind=="trees/"+"a"*40+"?recursive=1":
            return {"truncated":False,"tree":tree_items}
        if kind.startswith("blobs/"):
            blob=kind.removeprefix("blobs/")
            data=raw[blob][0]
            return {"sha":blob,"size":len(data),"encoding":"base64",
                    "content":base64.b64encode(data).decode()}
        raise AssertionError("unexpected GitHub read")
    return local,raw,extra,tree_items,get


def test_exact_owner_11_subset_of_vault_12_with_sha256_content_readback():
    local,raw,extra,items,get=fixture()
    result=gate._verify_remote(local,get)
    assert result["verified_archive_count"]==11
    assert result["vault_cipher_paths"]==13
    assert result["vault_unique_cipher_blobs"]==12
    assert result["excluded_extra_unique_blob"]==1
    assert len(result["owner_scope_digest"])==64


def test_full_read_only_stage_pass_never_implies_upload_or_30d_worm():
    local,raw,extra,items,get=fixture()
    result=gate.verify(local=local,get=get,b2=lambda:True,env={"CODESPACES":"true"})
    assert result["preupload"]=="PASS_OWNER_AND_B2_READ_ONLY"
    assert result["owner_source_eleven_sha256"]=="PASS"
    assert result["private_vault_readback"]=="PASS"
    assert result["backblaze_empty_bucket_readonly"]=="PASS"
    assert result["retention_mode_approved"]=="COMPLIANCE"
    assert result["approved_retention_days"]==30
    assert result["upload_count"]==0
    assert result["compliance_object_versions_verified"]==0
    assert result["uploader_write_and_retention_scope"]=="NOT_CONFIGURED"
    assert result["blocker"]=="DISTINCT_MINIMAL_UPLOADER_KEY_NOT_CONFIGURED"
    assert result["recovery_key_accessed"] is False
    assert result["original_archive_mutated"] is False
    assert result["overall"]=="BLOCKED"


def test_no_owner_codespace_blocks_before_any_read():
    local,raw,extra,items,get=fixture()
    called=[]
    result=gate.verify(local=local,get=lambda x:called.append(x),
                       b2=lambda:called.append("B2"),env={"CODESPACES":"false"})
    assert result["blocker"]=="OWNER_CODESPACE_REQUIRED"
    assert called==[]


def test_fail_closed_if_pinned_private_git_vault_has_changed():
    local,raw,extra,items,get=fixture()
    def moved(path):
        if path.endswith("ref/heads/main"):
            return {"object":{"sha":"a"*40}}
        return get(path)
    with pytest.raises(gate.Blocked,match="PRIVATE_VAULT_MAIN_MOVED"):
        gate._verify_remote(local,moved)


def test_reject_archive_manifest_drift_before_any_remote_cipher_read():
    local,raw,extra,items,get=fixture()
    bad={**local}
    bad.pop(next(iter(bad)))
    bad[extra]="f"*64
    with pytest.raises(gate.Blocked,match="ELEVEN_OWNER_CIPHERS_NOT_EXACT_VAULT_SUBSET"):
        gate._verify_remote(bad,get)


def test_reject_same_git_blob_twice_even_with_distinct_names():
    local,raw,extra,items,get=fixture()
    items[1]["sha"]=items[2]["sha"]
    with pytest.raises(gate.Blocked,match="PRIVATE_VAULT_12_UNIQUE_CIPHER_BASELINE_CHANGED"):
        gate._verify_remote(local,get)


def test_reject_tree_extension_or_truncation():
    local,raw,extra,items,get=fixture()
    items.append({"type":"blob","mode":"100644","sha":"f"*40,
                  "path":"unapproved/additional.jwpgbk"})
    with pytest.raises(gate.Blocked,match="PRIVATE_VAULT_13_CIPHER_TREE_CHANGED"):
        gate._verify_remote(local,get)
    items.pop()
    def truncate(path):
        r=get(path)
        return {**r,"truncated":True} if "trees/" in path else r
    with pytest.raises(gate.Blocked,match="PRIVATE_VAULT_TREE_TRUNCATED"):
        gate._verify_remote(local,truncate)


def test_git_blob_sha1_and_sha256_both_bound_to_remote_cipher_bytes():
    local,raw,extra,items,get=fixture()
    target=list(local)[4]
    def tamper(path):
        doc=get(path)
        if path.endswith("/blobs/"+target):
            actual=raw[target][0]
            counterfeit=actual[:-1]+bytes([actual[-1]^7])
            return {**doc,"content":base64.b64encode(counterfeit).decode()}
        return doc
    with pytest.raises(gate.Blocked,match="PRIVATE_VAULT_CIPHER_CONTENT_DIFFERENT"):
        gate._verify_remote(local,tamper)


def test_reject_untrusted_cipher_header_even_when_both_hashes_match():
    local,raw,extra,items,get=fixture()
    target=list(local)[0]
    wrong=b"NOTPGDMP"+b"C"*400
    replacement_sha1=hashlib.sha1(b"blob "+str(len(wrong)).encode()+b"\0"+wrong).hexdigest()
    replacement_sha256=hashlib.sha256(wrong).hexdigest()
    local[replacement_sha1]=local.pop(target)
    local[replacement_sha1]=replacement_sha256
    items[1]["sha"]=replacement_sha1
    def changed_get(path):
        if path.endswith("/blobs/"+replacement_sha1):
            return {"sha":replacement_sha1,"encoding":"base64",
                    "size":len(wrong),"content":base64.b64encode(wrong).decode()}
        return get(path)
    with pytest.raises(gate.Blocked,match="PRIVATE_VAULT_CIPHER_CONTENT_DIFFERENT"):
        gate._verify_remote(local,changed_get)


def test_local_owner_cipher_0600_verified_and_owner_archive_not_modified(tmp_path):
    data=b"JWPGBK2\n"+b"X"*400
    f=tmp_path/"probe.jwpgbk"
    f.write_bytes(data)
    f.chmod(0o600)
    before=f.stat()
    sha1,sha256,n=gate._hash_file(f)
    assert n==len(data)
    assert sha256==hashlib.sha256(data).hexdigest()
    assert sha1==hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
    assert f.read_bytes()==data
    assert f.stat().st_mtime_ns==before.st_mtime_ns
    f.chmod(0o644)
    with pytest.raises(gate.Blocked,match="OWNER_CIPHER_PERMISSIONS_INVALID"):
        gate._hash_file(f)


def test_local_symlinks_and_nonapproved_files_are_rejected(tmp_path):
    root=tmp_path/"backups"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    outside=tmp_path/"outside"
    outside.write_bytes(b"JWPGBK2\n"+b"Y"*400)
    (root/"accidental.jwpgbk").symlink_to(outside)
    with pytest.raises(gate.Blocked,match="OWNER_ELEVEN_ARCHIVES_REQUIRED"):
        gate._local_files(root)
    outside.chmod(0o600)
    (root/"accidental.jwpgbk").unlink()
    for i in range(11):
        f=root/f"archive_{i}.jwpgbk"
        f.write_bytes(b"JWPGBK2\n"+bytes([i])*350)
        f.chmod(0o600)
    local=gate._local_files(root)
    assert len(local)==11


@pytest.mark.parametrize(("caps","expected"),[
    (["writeFiles","writeFileRetentions"],"UPLOAD_KEY_CAPABILITY_SCOPE_VALID"),
    (["writeFiles"],"UPLOAD_KEY_MISSING_COMPLIANCE_OR_WRITE_PERMISSION"),
    (["writeFileRetentions"],"UPLOAD_KEY_MISSING_COMPLIANCE_OR_WRITE_PERMISSION"),
    (["writeFiles","writeFileRetentions","deleteFiles"],
     "UPLOAD_KEY_UNNECESSARY_OR_DESTRUCTIVE_PERMISSION"),
    (["writeFiles","writeFileRetentions","bypassGovernance"],
     "UPLOAD_KEY_UNNECESSARY_OR_DESTRUCTIVE_PERMISSION"),
    (["writeFiles","writeFileRetentions","writeBucketRetentions"],
     "UPLOAD_KEY_UNNECESSARY_OR_DESTRUCTIVE_PERMISSION"),
    (["writeFiles","writeFileRetentions","writeFileLegalHolds"],
     "UPLOAD_KEY_UNNECESSARY_OR_DESTRUCTIVE_PERMISSION"),
    (["writeFiles","writeFileRetentions","listAllBucketNames"],
     "UPLOAD_KEY_UNNECESSARY_OR_DESTRUCTIVE_PERMISSION"),
])
def test_future_writer_least_privilege_contract(caps,expected):
    allowed={"buckets":[{"name":"naruv-jw-backup-worm-2026","id":"fake"}],
             "namePrefix":gate.UPLOAD_PREFIX,"capabilities":caps}
    assert gate.validate_upload_key_capabilities(allowed,now_ms=0)==expected


def test_wrong_bucket_or_prefix_denied_even_with_write_permission():
    allowed={"buckets":[{"name":"other-bucket"}],
             "namePrefix":gate.UPLOAD_PREFIX,
             "capabilities":["writeFiles","writeFileRetentions"]}
    assert gate.validate_upload_key_capabilities(allowed,now_ms=0)==(
        "UPLOAD_KEY_NOT_RESTRICTED_TO_OWNER_BUCKET")
    allowed["buckets"]=[{"name":"naruv-jw-backup-worm-2026"}]
    allowed["namePrefix"]="unbounded-other-prefix"
    assert gate.validate_upload_key_capabilities(allowed,now_ms=0)==(
        "UPLOAD_KEY_PREFIX_MISMATCH")


def test_fail_closed_when_b2_bucket_read_only_reverification_fails():
    local,raw,extra,items,get=fixture()
    result=gate.verify(local=local,get=get,b2=lambda:False,env={"CODESPACES":"true"})
    assert result["owner_source_eleven_sha256"]=="PASS"
    assert result["private_vault_readback"]=="PASS"
    assert result["preupload"]=="BLOCKED"
    assert result["blocker"]=="REAL_B2_EMPTY_BUCKET_READONLY_FAILED"
    assert result["upload_count"]==0


def test_invalid_cli_action_never_reads_or_uploads(capsys):
    assert gate.main(["upload-30-days"])==2
    assert "USAGE" in capsys.readouterr().err
