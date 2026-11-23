"""Upload exactly nine approved, already encrypted owner archives to PRIVATE vault.

Only run from owner Codespaces. Existing remote paths, local ciphertext files,
backup keys, database, UI, main and Render are never modified. Each GitHub
write is fail-closed; the visible branch is moved once (force=false) only
after all bytes and resulting tree have been independently verified.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from scripts import p1_owner_one_shot_v223 as owner
from scripts import p1_owner_vault_readback_v223 as vault

REPO="repos/guccizz1k/jw-backup-vault-261111"
WRITE_ACK="OWNER_APPROVES_NINE_ENCRYPTED_ARCHIVES_PRIVATE_VAULT"
MAX_SINGLE=32*1024*1024
MAX_BATCH=128*1024*1024
SHA=re.compile(r"^[0-9a-f]{40}$")
MAGIC=(b"JWPGBK1\n",b"JWPGBK2\n")

class Blocked(vault.Blocked):
    pass


def api(method,path,data=None):
    if (method not in ("GET","POST","PATCH") or
        (path!=REPO and not path.startswith(REPO+"/")) or
        len(path)>200 or "\r" in path or "\n" in path):
        raise Blocked("UNSAFE_VAULT_API_ENDPOINT")
    if method=="GET" and data is not None or method!="GET" and not isinstance(data,dict):
        raise Blocked("UNSAFE_VAULT_API_PAYLOAD")
    raw=(json.dumps(data,separators=(",",":")).encode("ascii") if data is not None
         else None)
    if raw is not None and len(raw)>MAX_SINGLE*2+8192:
        raise Blocked("UPLOAD_BODY_SIZE_EXCEEDED")
    args=["gh","api",path,"--method",method,
          "--header","Accept: application/vnd.github+json"]
    if raw is not None:
        args.extend(["--input","-"])
    try:
        done=subprocess.run(args,input=raw,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            env=vault._vault_cli_env(),timeout=120,check=False)
        if done.returncode or len(done.stdout)>250000:
            raise Blocked("PRIVATE_VAULT_API_AUTH_OR_WRITE_BLOCKED")
        output=json.loads(done.stdout)
        if not isinstance(output,dict):
            raise Blocked("PRIVATE_VAULT_API_UNEXPECTED_RESPONSE")
        return output
    except (ValueError,UnicodeError,OSError,subprocess.TimeoutExpired):
        raise Blocked("PRIVATE_VAULT_API_UNAVAILABLE") from None


def head_state(expected):
    if not SHA.fullmatch(expected):
        raise Blocked("VAULT_EXPECTED_SHA_REQUIRED")
    prefix=REPO+"/git/"
    ref=api("GET",prefix+"ref/heads/main")
    if ref.get("object",{}).get("sha")!=expected:
        raise Blocked("VAULT_MAIN_HEAD_CHANGED")
    commit=api("GET",prefix+"commits/"+expected)
    tree=commit.get("tree")
    if (commit.get("sha")!=expected or not isinstance(tree,dict) or
        not SHA.fullmatch(tree.get("sha",""))):
        raise Blocked("VAULT_COMMIT_TREE_UNVERIFIED")
    original_tree=api("GET",prefix+"trees/"+tree["sha"]+"?recursive=1")
    ids=vault._vault_api_tree(original_tree)
    files={row["path"]:row["sha"] for row in original_tree["tree"]
           if row.get("type")=="blob"}
    if len(files)!=len(ids):
        raise Blocked("VAULT_DUPLICATE_TREE_PATH")
    return tree["sha"],files


def local_files():
    items,status=owner.discover_owner_archive()
    if status!="MULTIPLE_ARCHIVES" or len(items)!=11:
        raise Blocked("EXPECTED_ELEVEN_OWNER_ARCHIVES")
    seen={}
    total=0
    for item in items:
        path=Path(item)
        if not owner._private_cipher_file(path) or path.is_symlink():
            raise Blocked("LOCAL_CIPHER_PERMISSIONS_INVALID")
        st=path.lstat()
        total+=st.st_size
        if not 0<st.st_size<=MAX_SINGLE or total>MAX_BATCH:
            raise Blocked("LOCAL_CIPHER_SIZE_LIMIT")
        key,strong=vault.local_hash(path)
        if key in seen:
            raise Blocked("DUPLICATE_OWNER_CIPHERTEXT")
        with os.fdopen(os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)),"rb") as f:
            if f.read(8) not in MAGIC:
                raise Blocked("LOCAL_CIPHER_HEADER_INVALID")
        seen[key]=(path,strong,st.st_size,(st.st_dev,st.st_ino,st.st_mtime_ns,st.st_ctime_ns))
    return seen


def ciphertext(item,expected_key):
    path,strong,size,identity=item
    try:
        with os.fdopen(os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)),"rb") as f:
            st=os.fstat(f.fileno())
            if (not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode)!=0o600
                or st.st_uid!=os.getuid() or st.st_size!=size
                or (st.st_dev,st.st_ino,st.st_mtime_ns,st.st_ctime_ns)!=identity):
                raise Blocked("LOCAL_SOURCE_IDENTITY_CHANGED")
            raw=f.read(MAX_SINGLE+1)
            after=os.fstat(f.fileno())
            if (after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns)!=identity:
                raise Blocked("LOCAL_CIPHER_CHANGED_DURING_UPLOAD")
        if (len(raw)!=size or raw[:8] not in MAGIC
            or hashlib.sha256(raw).hexdigest()!=strong
            or hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()!=expected_key):
            raise Blocked("LOCAL_CIPHER_SHA256_OR_HEADER_CHANGED")
        return raw
    except OSError:
        raise Blocked("LOCAL_CIPHER_READ_ERROR") from None


def approved_preflight():
    if os.environ.get("CODESPACES","").lower()!="true":
        raise Blocked("CODESPACES_OWNER_REQUIRED")
    if os.environ.get("JW_PG_VAULT_READBACK_ACK")!=vault.ACK:
        raise Blocked("VAULT_READBACK_APPROVAL_REQUIRED")
    if os.environ.get("JW_PG_VAULT_WRITE_ACK")!=WRITE_ACK:
        raise Blocked("NINE_ENCRYPTED_ARCHIVES_APPROVAL_REQUIRED")
    expected=os.environ.get("JW_PG_VAULT_EXPECTED_SHA","")
    if not SHA.fullmatch(expected):
        raise Blocked("EXPECTED_VAULT_HEAD_REQUIRED")
    local=local_files()
    meta=api("GET",REPO)
    permissions=meta.get("permissions")
    if (meta.get("private") is not True or
        meta.get("full_name")!="guccizz1k/jw-backup-vault-261111" or
        meta.get("default_branch")!="main" or
        meta.get("archived") is True or meta.get("disabled") is True or
        not isinstance(permissions,dict) or permissions.get("push") is not True):
        raise Blocked("PRIVATE_VAULT_CONTENTS_WRITE_NOT_PROVEN")
    original_tree,original=head_state(expected)
    if len(original)!=4 or len(set(original.values()))!=3:
        raise Blocked("VAULT_4_PATHS_3_UNIQUE_BASELINE_CHANGED")
    proof=vault._vault_api_readback({k:x[1] for k,x in local.items()},expected)
    if not (proof.get("remote_commit_pinned") is True and
        proof.get("readback_transport")=="GH_REST_BLOB_BASE64_VERIFIED" and
        proof.get("remote_ciphertext_count")==4 and
        proof.get("remote_unique_ciphertext_count")==3 and
        proof.get("remote_unique_full_sha256_matches")==2 and
        proof.get("local_archives_not_offsite")==9):
        raise Blocked("VAULT_PREUPLOAD_CIPHER_READBACK_NOT_PASS")
    missing=sorted(set(local)-set(original.values()))
    if len(missing)!=9:
        raise Blocked("MISSING_CIPHER_COUNT_NOT_NINE")
    new={f"owner-v223/approved-20261123/{key}.jwpgbk":key for key in missing}
    if len(new)!=9 or set(original)&set(new):
        raise Blocked("VAULT_NEW_PATH_CONFLICT")
    return expected,original_tree,original,local,new


def upload():
    expected,base_tree,old,local,new=approved_preflight()
    for path,key in new.items():
        raw=ciphertext(local[key],key)
        created=api("POST",REPO+"/git/blobs",{
            "content":base64.b64encode(raw).decode("ascii"),
            "encoding":"base64"})
        if created.get("sha")!=key:
            raise Blocked("UPLOADED_CIPHER_GIT_SHA1_MISMATCH")
    # All nine blobs exist only as unreachable Git objects until publication.
    for key in new.values():
        actual,_=vault._vault_api_blob_sha256(key)
        if actual!=local[key][1]:
            raise Blocked("UPLOADED_CIPHER_SHA256_MISMATCH")
    add=[{"path":path,"mode":"100644","type":"blob","sha":key}
         for path,key in new.items()]
    created_tree=api("POST",REPO+"/git/trees",
                     {"base_tree":base_tree,"tree":add})
    target=created_tree.get("sha","")
    if not SHA.fullmatch(target):
        raise Blocked("STAGED_VAULT_TREE_INVALID")
    tree=api("GET",REPO+"/git/trees/"+target+"?recursive=1")
    vault._vault_api_tree(tree)
    entries={x["path"]:x["sha"] for x in tree["tree"]
             if x.get("type")=="blob"}
    if (len(entries)!=13 or
        any(entries.get(path)!=key for path,key in old.items()) or
        any(entries.get(path)!=key for path,key in new.items())):
        raise Blocked("STAGED_VAULT_MUTATES_EXISTING_FILES")
    commit=api("POST",REPO+"/git/commits",{
        "message":"Store nine owner-approved encrypted V22.3 archives",
        "tree":target,"parents":[expected]})
    new_head=commit.get("sha","")
    if not SHA.fullmatch(new_head):
        raise Blocked("VAULT_COMMIT_CREATE_INVALID")
    # Both a HEAD recheck and force=false: never overwrite concurrent writers.
    if api("GET",REPO+"/git/ref/heads/main").get("object",{}).get("sha")!=expected:
        raise Blocked("VAULT_CHANGED_BEFORE_PUBLISH")
    result=api("PATCH",REPO+"/git/refs/heads/main",
               {"sha":new_head,"force":False})
    if result.get("object",{}).get("sha")!=new_head:
        raise Blocked("VAULT_REF_PUBLISH_UNCONFIRMED")
    # No rollback/deletions: fail closed and report if provider readback fails.
    check_tree,check_entries=head_state(new_head)
    if check_tree!=target or check_entries!=entries:
        raise Blocked("PUBLISHED_VAULT_TREE_NOT_IDENTICAL")
    proof=vault._vault_api_readback({k:v[1] for k,v in local.items()},new_head)
    if not (proof.get("all_11_archives_offsite") is True and
        proof.get("remote_unique_full_sha256_matches")==11 and
        proof.get("local_archives_not_offsite")==0 and
        proof.get("remote_ciphertext_count")==13 and
        proof.get("remote_unique_ciphertext_count")==12 and
        proof.get("readback_transport")=="GH_REST_BLOB_BASE64_VERIFIED"):
        raise Blocked("POSTUPLOAD_ELEVEN_CIPHERS_SHA256_NOT_PROVEN")
    for key,(path,strong,_,_) in local.items():
        if vault.local_hash(path)!=(key,strong):
            raise Blocked("OWNER_CIPHER_CHANGED_AFTER_UPLOAD")
    return {
        "upload_execution":"PASS_NINE_ENCRYPTED_FILES_REMOTE_STORED",
        "new_ciphertext_file_count":9,
        "vault_original_file_count_preserved":4,
        "vault_remote_file_count":13,
        "vault_remote_unique_cipher_count":12,
        "owner_eleven_full_sha256_remote_readback":"PASS",
        "owner_original_eleven_archives_unchanged":"PASS",
        "remote_commit_pinned":True,
        "independent_key_escrow":"NOT_VERIFIED",
        "historical_backup_time_signature":"NOT_VERIFIED",
        "immutable_retention":"NOT_VERIFIED",
        "overall":"BLOCKED",
    }


def main(argv=None):
    args=sys.argv[1:] if argv is None else argv
    if args!=["upload-approved"]:
        print("USAGE: python -m scripts.p1_owner_vault_upload_v223 upload-approved",
              file=sys.stderr)
        return 2
    try:
        answer=upload()
    except Blocked as error:
        answer={"upload_execution":"BLOCKED","blocker":str(error),"overall":"BLOCKED"}
    except Exception:
        answer={"upload_execution":"BLOCKED","blocker":"SAFE_VAULT_UPLOAD_ERROR",
                "overall":"BLOCKED"}
    print(json.dumps(answer,sort_keys=True,separators=(",",":")))
    return 0 if answer.get("upload_execution")=="PASS_NINE_ENCRYPTED_FILES_REMOTE_STORED" else 1


if __name__=="__main__":
    raise SystemExit(main())
