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

def private_read(p):
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as f:
        a=os.fstat(f.fileno())
        require(stat.S_ISREG(a.st_mode) and a.st_mode&0o077==0 and 0<a.st_size<=16384,"PRIVATE_RECEIPT")
        raw=f.read(16385);b=os.fstat(f.fileno())
        require(len(raw)==a.st_size and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns),"RECEIPT_CHANGED")
        return raw

def review(directory):
    d=Path(directory);s=d.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_mode&0o077==0,"PRIVATE_DIRECTORY")
    require({p.name for p in d.iterdir()}=={"legacy.json","staged.json"},"RECEIPT_SET")
    pins={scope:check(private_read(d/(scope+".json"))) for scope in ("legacy","staged")}
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
