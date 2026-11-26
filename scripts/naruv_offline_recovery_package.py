"""Deterministic source-only recovery ZIP. No key, data, credentials or runtime.
Independent owner-approved SHA256 required for verification. No extraction.
"""
import argparse
import hashlib
import hmac
import io
import json
import re
import stat
import subprocess
import zipfile
from pathlib import Path

FILES=tuple(sorted("scripts/"+n+".py" for n in (
    "p1_external_custodian_pg17_v223","p1_cleanroom_key_recovery_v223",
    "p1_owner_offline_restore_v223","p1_owner_one_shot_v223",
    "p1_owner_archive_deep_v223","p1_owner_archive_inventory_v223","pg_backup_v223",
    "jw_independent_equivalence_v223","jw_independent_catalog_v223","naruv_b2_offline_stage")))
MANIFEST="RECOVERY-SOURCE.json"
MAX_FILE=512*1024
MAX_ZIP=6*1024*1024
HEX=re.compile(r"[0-9a-f]{64}")
COMMIT=re.compile(r"[0-9a-f]{40}")

def need(ok):
    if not ok:raise ValueError("RECOVERY_PACKAGE_INVALID")

def sha(data):return hashlib.sha256(data).hexdigest()

def canon(doc):return json.dumps(doc,sort_keys=True,separators=(",",":")).encode("ascii")+b"\n"

def build(commit,files):
    need(type(commit) is str and COMMIT.fullmatch(commit) and set(files)==set(FILES))
    need(all(type(v) is bytes and 0<len(v)<=MAX_FILE for v in files.values()))
    for path,data in files.items():compile(data,path,"exec")
    doc=dict(version=1,source_commit=commit,files={p:sha(files[p]) for p in FILES})
    payload={**files,MANIFEST:canon(doc)}
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,"w",compression=zipfile.ZIP_STORED) as z:
        for path in sorted(payload):
            item=zipfile.ZipInfo(path,date_time=(1980,1,1,0,0,0))
            item.create_system=3;item.external_attr=(stat.S_IFREG|0o600)<<16
            z.writestr(item,payload[path])
    raw=buf.getvalue();need(len(raw)<=MAX_ZIP)
    return raw

def verify(raw,expected_sha256,expected_commit):
    need(type(raw) is bytes and 0<len(raw)<=MAX_ZIP and type(expected_sha256) is str
         and HEX.fullmatch(expected_sha256) and hmac.compare_digest(sha(raw),expected_sha256)
         and type(expected_commit) is str and COMMIT.fullmatch(expected_commit))
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        infos=z.infolist()
        need([i.filename for i in infos]==sorted((*FILES,MANIFEST)))
        for i in infos:
            need(i.compress_type==zipfile.ZIP_STORED and not i.flag_bits&1 and
                 0<i.file_size<=MAX_FILE and i.compress_size==i.file_size and
                 stat.S_ISREG(i.external_attr>>16))
        files={p:z.read(p) for p in FILES}
        # Rebuild exact canonical bytes. Reject extra metadata, ambiguous JSON,
        # appended payloads and any manifest drift without extracting files.
        need(hmac.compare_digest(build(expected_commit,files),raw))
    return {"status":"SOURCE_PACKAGE_VERIFIED","source_commit":expected_commit,
            "file_count":len(FILES),"runtime_verified":False,"custody_verified":False}

def from_git(repo,commit):
    need(type(commit) is str and COMMIT.fullmatch(commit))
    def git(*args):
        return subprocess.run(["git","-C",str(repo),*args],check=True,capture_output=True,
                              timeout=20).stdout
    need(git("rev-parse","--verify",commit+"^{commit}").decode().strip()==commit)
    files={}
    for p in FILES:
        entry=git("ls-tree",commit,"--",p).decode("ascii").strip()
        need(entry.startswith("100644 blob ") and entry.endswith("\t"+p))
        obj=commit+":"+p
        size=int(git("cat-file","-s",obj))
        need(0<size<=MAX_FILE)
        files[p]=git("cat-file","blob",obj)
        need(len(files[p])==size)
    return build(commit,files)

def main():
    ap=argparse.ArgumentParser()
    sub=ap.add_subparsers(dest="mode",required=True)
    b=sub.add_parser("build");b.add_argument("repo");b.add_argument("commit");b.add_argument("output")
    v=sub.add_parser("verify");v.add_argument("package");v.add_argument("commit");v.add_argument("sha256")
    a=ap.parse_args()
    try:
        if a.mode=="build":
            raw=from_git(a.repo,a.commit)
            with open(a.output,"xb") as f:f.write(raw)
            print(json.dumps({"status":"SOURCE_PACKAGE_BUILT","sha256":sha(raw),"source_commit":a.commit}))
        else:
            with open(a.package,"rb") as f:raw=f.read(MAX_ZIP+1)
            print(json.dumps(verify(raw,a.sha256,a.commit)))
    except Exception:
        print("RECOVERY_PACKAGE_BLOCKED");return 1
    return 0

if __name__=="__main__":raise SystemExit(main())
