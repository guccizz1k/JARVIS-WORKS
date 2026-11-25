"""Verify exact source custody of an unpublished two-lineage candidate.

Checks files only. Does not execute imported code, authorize any merge, prove
runtime compatibility or change the active workflow.
"""
import hashlib,json,os
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MANIFEST=ROOT/"docs/NARUV_V223_SOURCE_RECONCILIATION.json"

def blob_oid(path):
    if path.is_symlink() or not path.is_file():raise ValueError("unsafe source")
    raw=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(raw)).encode("ascii")+b"\0"+raw).hexdigest()

def verify(root=ROOT,manifest=MANIFEST):
    data=json.loads(Path(manifest).read_text("utf-8"))
    if data["status"]!="UNVERIFIED_DETACHED_SOURCE_CANDIDATE_NOT_RELEASE":raise ValueError("invalid status")
    errors=[]
    root=Path(root).resolve()
    for name,entry in sorted(data["expected_blob_inventory"].items()):
        path=Path(name)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError("unsafe manifest path")
        target=root/path
        if any(p.is_symlink() for p in (target,*target.parents) if p!=root):
            errors.append(name);continue
        try:
            if entry["mode"] not in ("100644","100755") or blob_oid(target)!=entry["sha"]:
                errors.append(name)
            elif (bool(target.stat().st_mode & 0o111))!=(entry["mode"]=="100755"):
                errors.append(name)
        except (OSError,ValueError):errors.append(name)
    return errors

if __name__=="__main__":
    errors=verify()
    for item in errors:print("CUSTODY_MISMATCH",item)
    if errors:raise SystemExit(1)
    print("SOURCE_CUSTODY_ONLY_PASS; runtime, browser, operations and release NOT verified")
