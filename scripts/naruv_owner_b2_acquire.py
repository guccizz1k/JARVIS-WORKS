"""Owner-approved exact-version B2 acquisition. No recovery key, remote writes or restore."""
import base64
import hashlib
import http.client
import json
import os
import re
import resource
import ssl
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit
from scripts import naruv_b2_offline_stage as stage
from scripts import jw_independent_catalog_v223 as catalog

MANIFEST="684d41254d8ffda4c97a56648d2d0e1bd290ceea1838ddd33ebf0b4983b8ccc4"
BUCKET="818b599eca5772d820b2b04ba3e192b5e40688fb9a715b4b1082d7b5aed2be5c"
REFS={
 "legacy":("reference-legacy-candidate.json","b48bb73fda20488f6c37d04b2976de11cfbdb753986e3106f711fa8af82794c1","65d2d4b98badd8231d65bf8553cb434a4a5141f9","7b87c985452ee4d3a00049971380414ef436646516fa9d745ef878e267188147"),
 "staged":("reference-staged.json","32a5955d2d6dc90427ea46ecd35ba93f9615a6002d5a4a473a86b88f8d71b56e","415ad1c54df44841245fb653ddeda5a2c0ea016d","d5c6d89f31487158630f6e3f18ce578248883cd95a7e2b0eaac0a38d365e5ee9")}
AUDIT=("JW_B2_AUDIT_KEY_ID","JW_B2_AUDIT_APPLICATION_KEY")
ALLOWED={"listBuckets","listFiles","readFiles","readFileRetentions","readBucketRetentions","readBucketEncryption","readFileLegalHolds","readBuckets","listAllBucketNames"}

def need(ok,code):
    if not ok:raise ValueError(code)

def private_read(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as f:
        a=os.fstat(f.fileno())
        need(stat.S_ISREG(a.st_mode) and a.st_uid==os.getuid() and a.st_mode&0o077==0 and 0<a.st_size<=limit,"LOCAL_PRIVATE_FILE")
        raw=f.read(limit+1);b=os.fstat(f.fileno())
        need(len(raw)==a.st_size and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns),"LOCAL_INPUT_CHANGED")
        return raw

def approved_inputs(directory):
    d=Path(directory)
    st=d.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.getuid() and st.st_mode&0o077==0,"LOCAL_PRIVATE_DIR")
    raw=private_read(d/"b2-manifest.json",65536)
    rows=stage.parse_manifest(raw,MANIFEST)
    for scope,(name,pin,vault,owner_scope) in REFS.items():
        ref=private_read(d/name,catalog.eq.MAX_JSON)
        pairs=[(r["git_blob_sha1"],r["sha256"]) for r in rows if r["scope"]==scope]
        catalog.load_reference(ref,expected_reference_sha256=pin,expected_vault=vault,expected_scope=owner_scope,provider_pairs=pairs)
    return raw

def read_authorization(i,k):
    need(all(type(x) is str and 0<len(x)<=4096 and all(33<=ord(c)<=126 for c in x) for x in (i,k)) and ":" not in i,"B2_READ_CREDENTIAL_FORMAT")
    conn=http.client.HTTPSConnection("api.backblazeb2.com",timeout=30,context=ssl.create_default_context())
    try:
        auth=base64.b64encode((i+":"+k).encode("ascii")).decode("ascii")
        conn.request("GET","/b2api/v4/b2_authorize_account",headers={"Authorization":"Basic "+auth})
        r=conn.getresponse()
        need(r.status==200,"B2_AUTH_FAILED")
        raw=r.read(65537)
        need(len(raw)<=65536,"B2_AUTH_SIZE")
        return json.loads(raw)
    finally:conn.close()

def authorized_download(doc):
    s=doc["apiInfo"]["storageApi"];a=s["allowed"];caps=set(a["capabilities"]);b=a["buckets"]
    need("readFiles" in caps and caps<=ALLOWED and type(b) is list and len(b)==1 and not a["namePrefix"] and hashlib.sha256(b[0]["name"].encode()).hexdigest()==BUCKET,"B2_READ_SCOPE")
    url=urlsplit(s["downloadUrl"])
    need(url.scheme=="https" and stage.HOST.fullmatch(url.netloc) and url.path in ("","/") and not url.query and not url.fragment,"B2_DOWNLOAD_HOST")
    token=doc["authorizationToken"]
    need(type(token) is str and 1<=len(token)<=8192,"B2_TOKEN")
    return url.netloc,token

def acquire(directory):
    raw=approved_inputs(directory)
    need(all(os.environ.get(k) for k in AUDIT),"B2_AUDIT_CREDENTIALS_REQUIRED")
    host,token=authorized_download(read_authorization(*(os.environ[k] for k in AUDIT)))
    dest=stage.stage(raw,MANIFEST,directory,lambda row:stage.native_download(host,token,row))
    print("B2_EXACT_CIPHERTEXT_STAGE=PASS_22")
    print("CIPHERTEXT_DIRECTORY="+str(dest))
    print("NO_KEY_READ / NO_REMOTE_WRITE / LIVE_RESTORE_NOT_RUN")

def main():
    try:
        os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        need(len(sys.argv)==2,"INPUT_DIRECTORY_REQUIRED")
        need(os.environ.get("CODESPACES","").lower()=="true","OWNER_CODESPACE_REQUIRED")
        keep={k:v for k,v in os.environ.items() if k in ("HOME","PATH","LANG","CODESPACES",*AUDIT)}
        os.environ.clear();os.environ.update(keep)
        acquire(Path(sys.argv[1]))
        return 0
    except Exception as exc:
        code=str(exc)
        print("BLOCKED="+(code if type(exc) is ValueError and re.fullmatch(r"[A-Z0-9_]{3,80}",code) else "B2_ACQUIRE_FAIL_CLOSED"))
        return 1

if __name__=="__main__":raise SystemExit(main())
