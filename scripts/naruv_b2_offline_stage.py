"""Review-only B2 ciphertext staging; no key, write API, restore or custody claim.
The manifest pin MUST arrive through an independently trusted owner channel.
Only use a short-lived bucket/prefix scoped readFiles credential.
"""
import hashlib
import hmac
import http.client
import json
import os
import re
import shutil
import ssl
import tempfile
from pathlib import Path
from urllib.parse import urlencode

MAX_ONE=32*1024*1024
MAX_TOTAL=128*1024*1024
HEX64=re.compile(r"[0-9a-f]{64}")
HEX40=re.compile(r"[0-9a-f]{40}")
FILE_ID=re.compile(r"[A-Za-z0-9_-]{1,256}")
HOST=re.compile(r"f[0-9]{3,6}\.backblazeb2\.com")

def need(ok,code):
    if not ok: raise ValueError(code)

def hash256(data):
    return hashlib.sha256(data).hexdigest()

def git_blob(data):
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()

def parse_manifest(raw,pin):
    need(type(raw) is bytes and len(raw)<=65536 and type(pin) is str and HEX64.fullmatch(pin)
         and hmac.compare_digest(hash256(raw),pin),"B2_MANIFEST_PIN")
    def pairs(items):
        d={}
        for k,v in items:
            need(k not in d,"B2_DUPLICATE_JSON")
            d[k]=v
        return d
    obj=json.loads(raw,object_pairs_hook=pairs)
    need(type(obj) is dict and set(obj)=={"version","archives"} and type(obj["version"]) is int and obj["version"]==1,"B2_MANIFEST_SCHEMA")
    rows=obj["archives"]
    need(type(rows) is list and len(rows)==22,"B2_MANIFEST_COUNT")
    seen=set(); blobs=set(); groups={"legacy":0,"staged":0}
    total=0
    for row in rows:
        need(type(row) is dict and set(row)=={"scope","file_id","size","sha256","git_blob_sha1"},"B2_MANIFEST_ROW")
        f=row["file_id"]; b=row["git_blob_sha1"]; h=row["sha256"]; n=row["size"]; g=row["scope"]
        need(type(f) is str and FILE_ID.fullmatch(f) and f not in seen and type(b) is str and HEX40.fullmatch(b) and b not in blobs
             and type(h) is str and HEX64.fullmatch(h) and type(n) is int and 24<n<=MAX_ONE
             and type(g) is str and g in groups,"B2_MANIFEST_ROW")
        seen.add(f);blobs.add(b);groups[g]+=1;total+=n
    need(groups=={"legacy":11,"staged":11} and total<=MAX_TOTAL,"B2_SCOPE_OR_SIZE")
    return rows

def verify_bytes(row,data):
    need(type(data) is bytes and len(data)==row["size"] and hmac.compare_digest(hash256(data),row["sha256"])
         and hmac.compare_digest(git_blob(data),row["git_blob_sha1"]),"B2_CIPHERTEXT_MISMATCH")

def native_download(host,token,row):
    """HTTPS GET only. No redirects, proxy environment, or token in URL."""
    need(type(host) is str and HOST.fullmatch(host),"B2_HOST")
    need(type(token) is str and 1<=len(token)<=8192 and all(33<=ord(c)<=126 for c in token),"B2_TOKEN")
    conn=http.client.HTTPSConnection(host,timeout=30,context=ssl.create_default_context())
    try:
        conn.request("GET","/b2api/v4/b2_download_file_by_id?"+urlencode({"fileId":row["file_id"]}),
                     headers={"Authorization":token,"Accept-Encoding":"identity"})
        r=conn.getresponse()
        need(r.status==200,"B2_HTTP_STATUS")
        need(r.getheader("X-Bz-File-Id")==row["file_id"],"B2_FILE_ID")
        need(r.getheader("Content-Length")==str(row["size"]),"B2_LENGTH")
        data=r.read(row["size"]+1)
        need(r.getheader("X-Bz-Content-Sha1")==hashlib.sha1(data).hexdigest(),"B2_PROVIDER_SHA1")
        verify_bytes(row,data)
        return data
    except (OSError,http.client.HTTPException):
        raise ValueError("B2_TRANSPORT_FAILED") from None
    finally:
        conn.close()

def stage(raw,pin,parent,download):
    """Create a new private directory of ciphertext only, rollback on failure."""
    rows=parse_manifest(raw,pin)
    dest=Path(tempfile.mkdtemp(prefix="naruv-b2-",dir=parent))
    try:
        for row in rows:
            data=download(dict(row))
            verify_bytes(row,data)
            with (dest/(row["git_blob_sha1"]+".cipher")).open("xb") as f:
                os.fchmod(f.fileno(),0o600)
                f.write(data);f.flush();os.fsync(f.fileno())
        return dest
    except BaseException:
        shutil.rmtree(dest)
        raise

def read_staged(raw,pin,directory,scope):
    """Re-check exact local ciphertext set without any network or key access.
    Call from a dedicated local trusted directory; no concurrent untrusted writer.
    """
    rows=parse_manifest(raw,pin)
    need(scope in ("legacy","staged"),"B2_SCOPE")
    d=Path(directory)
    need(not d.is_symlink() and d.is_dir(),"B2_STAGE_DIR")
    expected={r["git_blob_sha1"]+".cipher" for r in rows}
    need({p.name for p in d.iterdir()}==expected,"B2_STAGE_SET")
    out={}
    for row in rows:
        path=d/(row["git_blob_sha1"]+".cipher")
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,"rb") as f:
            import stat
            st=os.fstat(f.fileno())
            need(stat.S_ISREG(st.st_mode) and st.st_size==row["size"] and st.st_nlink==1 and st.st_mode&0o077==0,"B2_STAGE_FILE")
            data=f.read(row["size"]+1)
        verify_bytes(row,data)
        if row["scope"]==scope:out[row["git_blob_sha1"]]=data
    return out
