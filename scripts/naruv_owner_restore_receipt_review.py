"""Offline receipt consistency checker; not an attestation or release gate.
V3 receipts do not embed scope or run ID. Two files can even be byte-identical.
Never infer independent provenance, historical ACL/RLS or key custody from them.
"""
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

COUNTS=("verified_provider_cipher_count","restored_pg17_archive_count","restored_65_table_archive_count","matched_archives","catalog_matched_archives")
FLAGS=("b2_staged_scope_bound","owner_scope_pin_checked","cleanup_pass")
FALSES=("decrypted_dump_written_to_host","source_codespaces_key_used","row_digest_collision_proof","production_release_ready","icloud_custody_verified","offline_key_copy_verified")
STATUS={
 "custody_model":"OWNER_SELF_CUSTODY","ciphertext_path":"B2_STAGED_OFFLINE",
 "owner_site_restore":"PASS_ELEVEN_OWNER_SITE_CIPHERS",
 "external_pg17_restore":"NOT_APPLICABLE_OWNER_SITE",
 "normalized_archive_comparison":"PASS_11_ARCHIVE_CHECKPOINTS",
 "normalized_catalog_comparison":"PASS_11_SCOPED_CATALOG_CHECKPOINTS",
 "rls_policy_definition_comparison":"PASS_11_ARCHIVE_POLICY_AND_FLAGS",
 "disposable_pg17_removed":"PASS","overall":"BLOCKED",
 "rls_effective_enforcement":"NOT_RUN","rls_policy_equivalence":"NOT_RUN",
 "original_owner_acl_equivalence":"NOT_RUN_RESTORE_STRIPS_OWNER_ACL",
 "role_membership_equivalence":"NOT_ATTESTED_CLUSTER_GLOBALS_NOT_BACKED_UP",
 "full_schema_equivalence":"NOT_ATTESTED_SCOPED_CATALOG_ONLY",
 "independent_key_custody":"DEFERRED_NOT_ATTESTED",
 "independent_legal_retention":"NOT_ATTESTED","historic_source_signature":"NOT_ATTESTED"}
FIELDS=set(COUNTS+FLAGS+FALSES)|set(STATUS)|{"restore_failures"}

def require(ok,code):
    if not ok:raise ValueError(code)

def unique(items):
    d={}
    for k,v in items:
        require(k not in d,"DUPLICATE_FIELD")
        d[k]=v
    return d

def check(raw):
    require(type(raw) is bytes and 0<len(raw)<=16384,"RECEIPT_SIZE")
    try:r=json.loads(raw.decode("ascii"),object_pairs_hook=unique)
    except (UnicodeError,ValueError,RecursionError):raise ValueError("RECEIPT_JSON") from None
    require(type(r) is dict and set(r)==FIELDS,"RECEIPT_FIELDS")
    require(all(type(r[k]) is int and r[k]==11 for k in COUNTS),"RECEIPT_COUNTS")
    require(type(r["restore_failures"]) is int and r["restore_failures"]==0,"RESTORE_FAILURES")
    require(all(r[k] is True for k in FLAGS),"RECEIPT_REQUIRED_FLAGS")
    require(all(r[k] is False for k in FALSES),"RECEIPT_DENIAL_FLAGS")
    require(all(r[k]==v for k,v in STATUS.items()),"RECEIPT_STATUS")
    return hashlib.sha256(raw).hexdigest()

def _stamp(s):
    return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)

def _private_file(s):
    return (stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1
            and s.st_mode&0o077==0 and 0<s.st_size<=16384)

def _read_at(directory_fd,name):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory_fd)
    with os.fdopen(fd,"rb") as f:
        a=os.fstat(f.fileno())
        require(_private_file(a),"PRIVATE_RECEIPT")
        raw=f.read(16385);b=os.fstat(f.fileno())
        require(len(raw)==a.st_size and _stamp(a)==_stamp(b),"RECEIPT_CHANGED")
        return raw,_stamp(a)

def _open_path(directory):
    d=Path(directory)
    require(".." not in d.parts and d.anchor in ("","/"),"UNSAFE_DIRECTORY_PATH")
    if not d.is_absolute():d=Path.cwd()/d
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
    fd=os.open("/",flags);chain=[]
    try:
        for name in (None,*d.parts[1:]):
            if name is not None:
                new=os.open(name,flags,dir_fd=fd);os.close(fd);fd=new
            s=os.fstat(fd)
            require(stat.S_ISDIR(s.st_mode) and s.st_uid in (0,os.geteuid())
                    and (s.st_mode&0o022==0 or (s.st_uid==0 and s.st_mode&stat.S_ISVTX)),"UNTRUSTED_ANCESTOR")
            chain.append((s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid))
        return fd,tuple(chain)
    except BaseException:
        os.close(fd);raise

def review(directory):
    fd,chain=_open_path(directory)
    try:
        s=os.fstat(fd)
        require(stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and s.st_mode&0o077==0,"PRIVATE_DIRECTORY")
        names={"legacy.json","staged.json"}
        require(set(os.listdir(fd))==names,"RECEIPT_SET")
        pins={};stamps={}
        for scope in ("legacy","staged"):
            name=scope+".json"
            raw,stamps[name]=_read_at(fd,name)
            pins[scope]=check(raw)
        for name in names:
            require(_stamp(os.stat(name,dir_fd=fd,follow_symlinks=False))==stamps[name],"RECEIPT_CHANGED")
        end_fd,end_chain=_open_path(directory)
        try:
            require(set(os.listdir(fd))==names and _stamp(os.fstat(fd))==_stamp(s)
                    and end_chain==chain and _stamp(os.fstat(end_fd))==_stamp(s),"DIRECTORY_CHANGED")
        finally:
            os.close(end_fd)
    finally:
        os.close(fd)
    return {"receipt_consistency":"PASS_TWO_11_COUNT_RECEIPTS",
            "receipt_sha256":pins,"scope_binding_in_receipts":False,
            "independent_provenance":"NOT_ATTESTED","historical_acl":"NOT_RUN",
            "historical_role_graph":"NOT_ATTESTED","effective_rls":"NOT_RUN",
            "offline_key_copy":"NOT_VERIFIED","p2_acceptance":"BLOCKED"}

def main():
    try:
        require(len(sys.argv)==2,"DIRECTORY_REQUIRED")
        print(json.dumps(review(sys.argv[1]),sort_keys=True))
        return 0
    except Exception:
        print("BLOCKED=RESTORE_RECEIPT_INCONSISTENT")
        return 1

if __name__=="__main__":raise SystemExit(main())
