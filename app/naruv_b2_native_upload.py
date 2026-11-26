"""Owner-only B2 Native API upload candidate. Not mounted or invoked by the app.
The independently approved scope pin and verified encrypted input must come
from the owner, not a client. No key creation, deletion, retention updates,
automatic retry or access to existing backup prefixes. B2 has no atomic
create-if-absent here: a single exclusive writer per approved object is required.
"""
import base64, hashlib, hmac, json, os, re, stat, time
from email.utils import parsedate_to_datetime
from urllib import request, parse
from .naruv_b2_upload_policy import upload_policy_plan, verify_uploaded_metadata
from .naruv_b2_retention_journal import need, legal_hold_state
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import struct

AUDIT_CAPS={"listBuckets","listFiles","readFiles","readFileRetentions",
    "readBucketRetentions","readBucketEncryption","readFileLegalHolds"}
WRITER_CAPS={"writeFiles","writeFileRetentions"}
HEX=re.compile(r"[0-9a-f]{64}")
ID=re.compile(r"[A-Za-z0-9_-]{1,128}")
MAX_BYTES=32*1024*1024
SCOPE_FIELDS={"account_id","bucket_id","bucket_name_sha256","name","sha256","size",
    "approval_expires_ms","approved_until_ms","max_upload_ms","max_clock_skew_ms"}

def now_ms():return int(time.time()*1000)
def sha(b):return hashlib.sha256(b).hexdigest()
def scope_digest(scope):
    return sha(json.dumps(scope,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii"))

def _scope(scope,pin,raw,*,check_expiry=True):
    need(type(scope) is dict and set(scope)==SCOPE_FIELDS,"NATIVE_SCOPE")
    need(type(pin) is str and HEX.fullmatch(pin) and hmac.compare_digest(scope_digest(scope),pin),"NATIVE_APPROVAL_PIN")
    need(all(type(scope[k]) is str and ID.fullmatch(scope[k]) for k in ("account_id","bucket_id")),"NATIVE_SCOPE")
    need(all(type(scope[k]) is str and HEX.fullmatch(scope[k]) for k in ("sha256","bucket_name_sha256")),"NATIVE_SCOPE")
    need(type(scope["name"]) is str and re.fullmatch(r"naruv-one/new-backup/[0-9a-f]{32}/"+scope["sha256"]+r"\.jwpgbk",scope["name"]),"NATIVE_NEW_PREFIX")
    need(type(raw) is bytes and 8<len(raw)<=MAX_BYTES and raw[:8]==b"JWPGBK2\n"
        and type(scope["size"]) is int and len(raw)==scope["size"] and hmac.compare_digest(sha(raw),scope["sha256"]),"NATIVE_CIPHERTEXT_PIN")
    need(type(scope["approval_expires_ms"]) is int and scope["approval_expires_ms"]>0,"NATIVE_APPROVAL_EXPIRY_FORMAT")
    if check_expiry:
        need(now_ms()<scope["approval_expires_ms"],"NATIVE_APPROVAL_EXPIRED")
        return _plan(scope)

def authenticate_new_archive(raw, key):
    """Check all existing V2 AES-GCM chunk tags locally before any network call.
    This authenticates a PG custom archive prefix, not actual DB restore.
    No plaintext output or file writes. Python cannot guarantee memory erasure.
    V1 historical archives are intentionally excluded from NEW upload.
    """
    need(type(raw) is bytes and 36<=len(raw)<=MAX_BYTES and raw[:8]==b"JWPGBK2\n","NATIVE_ARCHIVE_FORMAT")
    need(type(key) is bytes and len(key)==32,"NATIVE_ARCHIVE_KEY")
    aes=AESGCM(key);prefix=raw[8:16];pos=16;count=0;total=0
    while pos<len(raw):
        need(len(raw)-pos>=4 and count<2**32,"NATIVE_ARCHIVE_TRUNCATED")
        n=int.from_bytes(raw[pos:pos+4],"big");start=pos+4;end=start+n
        need(16<=n<=1048576+16 and end<=len(raw),"NATIVE_ARCHIVE_RECORD")
        final=end==len(raw)
        try:
            plain=aes.decrypt(prefix+struct.pack(">I",count),raw[start:end],
                b"JWPGBK2\n"+struct.pack(">QB",count,int(final)))
        except InvalidTag:
            raise ValueError("NATIVE_ARCHIVE_AUTH") from None
        try:
            need((count!=0 or plain.startswith(b"PGDMP")) and (final or len(plain)==1048576),"NATIVE_ARCHIVE_CONTENT")
            total+=len(plain)
            need(total<=MAX_BYTES,"NATIVE_ARCHIVE_SIZE")
        finally:del plain
        pos=end;count+=1
    need(count>0 and total>=5,"NATIVE_ARCHIVE_CONTENT")
    return {"archive_format":"JWPGBK2","authenticated_chunks":count,"ciphertext_sha256":sha(raw),
        "restore_verified":False}

def _plan(s):
    return upload_policy_plan(planned_at_ms=now_ms(),max_upload_ms=s["max_upload_ms"],
        max_clock_skew_ms=s["max_clock_skew_ms"],approved_until_ms=s["approved_until_ms"])

class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
OP=request.build_opener(request.ProxyHandler({}),NoRedirect())

def _base(url,download=False):
    p=parse.urlsplit(url)
    pattern=r"f[0-9]+\.backblazeb2\.com" if download else r"api[0-9]*\.backblazeb2\.com"
    need(p.scheme=="https" and re.fullmatch(pattern,p.hostname or "") and p.netloc==p.hostname
        and p.path in ("","/") and not p.query and not p.fragment,"NATIVE_BASE_URL")
    return "https://"+p.hostname

def _upload_url(url,bid):
    p=parse.urlsplit(url);parts=p.path.split("/")
    need(p.scheme=="https" and re.fullmatch(r"pod-[0-9-]+\.backblaze(?:b2)?\.com",p.hostname or "")
        and p.netloc==p.hostname and not p.fragment
        and re.fullmatch(r"/b2api/v[1-4]/b2_upload_file(?:/[^?#]*)?",p.path),"NATIVE_UPLOAD_URL")
    query=parse.parse_qs(p.query,keep_blank_values=True).get("bucket",[])
    need((len(parts)>=6 and parts[4]==bid and (not query or query==[bid]))
        or (len(parts)==4 and query==[bid]),"NATIVE_UPLOAD_BUCKET")
    return url

def _request(url,token,body=None,headers=None,limit=1048576):
    try:
        h={"Authorization":token};h.update(headers or {})
        with OP.open(request.Request(url,data=body,headers=h),timeout=45) as r:
            b=r.read(limit+1)
            need(len(b)<=limit,"NATIVE_RESPONSE_LIMIT")
            return b,r.headers
    except Exception:
        raise ValueError("NATIVE_HTTP_FAILED_NO_RETRY") from None

def _json(url,token,params):
    raw,_=_request(url,token,json.dumps(params).encode(),{"Content-Type":"application/json"})
    try:
        result=json.loads(raw);need(type(result) is dict,"NATIVE_RESPONSE")
        return result
    except (ValueError,UnicodeError):raise ValueError("NATIVE_RESPONSE") from None

def _auth(credentials):
    need(type(credentials) is tuple and len(credentials)==2 and all(type(x) is str and 0<len(x)<=2048 for x in credentials),"NATIVE_CREDENTIALS")
    token="Basic "+base64.b64encode((credentials[0]+":"+credentials[1]).encode()).decode()
    raw,h=_request("https://api.backblazeb2.com/b2api/v4/b2_authorize_account",token)
    need(abs(now_ms()-int(parsedate_to_datetime(h["Date"]).timestamp()*1000))<=60000,"NATIVE_CLOCK")
    a=json.loads(raw);return a,a["apiInfo"]["storageApi"]

def _api(a,s,method,params):
    need(method in ("b2_list_buckets","b2_list_file_versions","b2_get_upload_url","b2_get_file_info"),"NATIVE_METHOD")
    return _json(_base(s["apiUrl"])+"/b2api/v4/"+method,a["authorizationToken"],params)

def _scope_session(a,s,scope,writer):
    v=s["allowed"];b=v["buckets"]
    need(a["accountId"]==scope["account_id"] and type(b) is list and len(b)==1
        and b[0]["id"]==scope["bucket_id"] and sha(b[0]["name"].encode())==scope["bucket_name_sha256"],"NATIVE_SESSION_BUCKET")
    caps=v["capabilities"];expected=WRITER_CAPS if writer else AUDIT_CAPS
    need(type(caps) is list and len(caps)==len(expected) and set(caps)==expected,"NATIVE_SESSION_CAPS")
    need(v["namePrefix"]==(scope["name"] if writer else None),"NATIVE_SESSION_PREFIX")
    _base(s["apiUrl"])
    if not writer:_base(s["downloadUrl"],download=True)
    else:
        t=a.get("applicationKeyExpirationTimestamp")
        need(type(t) is int and now_ms()+scope["max_upload_ms"]+60000<t<=scope["approval_expires_ms"],"NATIVE_WRITER_EXPIRY")

def _versions(a,s,scope):
    r=_api(a,s,"b2_list_file_versions",{"bucketId":scope["bucket_id"],"prefix":scope["name"],"maxFileCount":2})
    need(r.get("nextFileName") is None and r.get("nextFileId") is None and type(r.get("files")) is list,"NATIVE_VERSION_PAGINATION")
    return r["files"]

def _upload(url,token,name,raw,until):
    h={"Content-Type":"application/octet-stream","Content-Length":str(len(raw)),
        "X-Bz-File-Name":parse.quote(name,safe="/"),"X-Bz-Content-Sha1":hashlib.sha1(raw).hexdigest(),
        "X-Bz-File-Retention-Mode":"compliance","X-Bz-File-Retention-Retain-Until-Timestamp":str(until),
        "X-Bz-Server-Side-Encryption":"AES256"}
    b,_=_request(url,token,raw,h)
    return json.loads(b)

def _download(a,s,fid,length):
    url=_base(s["downloadUrl"],True)+"/b2api/v4/b2_download_file_by_id?"+parse.urlencode({"fileId":fid})
    return _request(url,a["authorizationToken"],limit=length)

def execute_approved_upload(*,scope,approved_scope_sha256,raw,archive_key,writer_credentials,audit_credentials,journal_dir):
    """Requires separately authorized single-object operation; never called by CI against B2."""
    _scope(scope,approved_scope_sha256,raw)
    verified_archive=authenticate_new_archive(raw,archive_key)
    del archive_key
    name=scope["name"];bid=scope["bucket_id"]
    need(writer_credentials[0]!=audit_credentials[0],"NATIVE_DISTINCT_KEYS")
    wa,ws=_auth(writer_credentials);aa,rs=_auth(audit_credentials)
    _scope_session(wa,ws,scope,True);_scope_session(aa,rs,scope,False)
    b=_api(aa,rs,"b2_list_buckets",{"accountId":scope["account_id"],"bucketId":bid})["buckets"]
    need(type(b) is list and len(b)==1 and b[0]["bucketId"]==bid
        and sha(b[0]["bucketName"].encode())==scope["bucket_name_sha256"] and b[0]["bucketType"]=="allPrivate"
        and b[0]["fileLockConfiguration"]["value"]["isFileLockEnabled"] is True
        and b[0]["defaultServerSideEncryption"]["value"]=={"mode":"SSE-B2","algorithm":"AES256"},"NATIVE_BUCKET_SECURITY")
    need(_versions(aa,rs,scope)==[],"NATIVE_EXISTING_VERSION")
    d=os.open(journal_dir,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        st=os.fstat(d);need(st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o700,"NATIVE_JOURNAL_DIR")
        # Same object name always uses the same journal, even if scope changes.
        jname=sha((bid+":"+name).encode())+".jsonl"
        fd=os.open(jname,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=d)
        with os.fdopen(fd,"w") as f:
            def log(stage,**data):
                f.write(json.dumps(dict(stage=stage,**data),sort_keys=True)+"\n");f.flush();os.fsync(f.fileno())
            plan=_plan(scope)
            log("attempt",approval_sha256=approved_scope_sha256,scope=scope,plan=plan,archive_authentication=verified_archive);os.fsync(d)
            u=_api(wa,ws,"b2_get_upload_url",{"bucketId":bid})
            need(u["bucketId"]==bid,"NATIVE_UPLOAD_BUCKET")
            url=_upload_url(u["uploadUrl"],bid)
            _scope_session(wa,ws,scope,True)
            need(now_ms()+scope["max_upload_ms"]<scope["approval_expires_ms"],"NATIVE_APPROVAL_EXPIRED")
            need(now_ms()<=plan["planned_at_ms"]+scope["max_clock_skew_ms"],"NATIVE_PLAN_STALE")
            ack=_upload(url,u["authorizationToken"],name,raw,plan["retain_until_ms"])
            fid=ack.get("fileId")
            expected=dict(bucketId=bid,fileName=name,fileId=fid,contentLength=len(raw),contentSha1=hashlib.sha1(raw).hexdigest())
            need(type(fid) is str and bool(fid) and all(type(ack.get(k)) is type(v) and ack[k]==v for k,v in expected.items()),"NATIVE_ACK")
            log("ack",file_id=fid)
            info=_api(aa,rs,"b2_get_file_info",{"fileId":fid})
            review=verify_uploaded_metadata(plan=plan,expected=expected,info=info,now_ms=now_ms())
            hold=legal_hold_state(info)
            got,h=_download(aa,rs,fid,len(raw))
            need(got==raw and h.get("X-Bz-File-Id")==fid and h.get("X-Bz-Content-Sha1")==expected["contentSha1"]
                and h.get("X-Bz-File-Retention-Mode")=="compliance"
                and h.get("X-Bz-File-Retention-Retain-Until-Timestamp")==str(plan["retain_until_ms"]),"NATIVE_READBACK")
            rows=_versions(aa,rs,scope)
            need(len(rows)==1,"NATIVE_FINAL_VERSION_COUNT")
            verify_uploaded_metadata(plan=plan,expected=expected,info=rows[0],now_ms=now_ms())
            need(legal_hold_state(rows[0])==hold,"NATIVE_HOLD_DRIFT")
            log("verified",file_id=fid,sha256=scope["sha256"],retain_until_ms=plan["retain_until_ms"])
            log("complete",verified=1)
        return dict(review,status="NATIVE_UPLOAD_READBACK_VERIFIED",ciphertext_verified=True,
            remote_write=True,archive_authenticated=True,restore_verified=False,key_retirement_authorized=False,production_authorized=False)
    finally:os.close(d)


def _journal_pairs(pairs):
    d={}
    for k,v in pairs:
        need(k not in d,"NATIVE_RECOVERY_DUPLICATE_JSON")
        d[k]=v
    return d

def recovery_plan(*,scope,approved_scope_sha256,raw,journal_raw,journal_sha256):
    """Offline validation of an interrupted upload receipt. Separate owner
    approval is required for any subsequent remote read. No retry authority.
    The caller must independently trust both pins and read protected local bytes.
    """
    _scope(scope,approved_scope_sha256,raw,check_expiry=False)
    need(type(journal_raw) is bytes and 0<len(journal_raw)<=65536 and journal_raw.endswith(b"\n")
        and type(journal_sha256) is str and HEX.fullmatch(journal_sha256)
        and hmac.compare_digest(sha(journal_raw),journal_sha256),"NATIVE_RECOVERY_JOURNAL_PIN")
    try:
        lines=[json.loads(x,object_pairs_hook=_journal_pairs) for x in journal_raw.splitlines()]
    except (UnicodeError,json.JSONDecodeError):raise ValueError("NATIVE_RECOVERY_JOURNAL_JSON") from None
    need(1<=len(lines)<=4 and all(type(x) is dict for x in lines),"NATIVE_RECOVERY_JOURNAL_SHAPE")
    a=lines[0]
    need(set(a)=={"stage","approval_sha256","scope","plan","archive_authentication"}
        and a["stage"]=="attempt" and a["approval_sha256"]==approved_scope_sha256 and a["scope"]==scope,"NATIVE_RECOVERY_JOURNAL_SCOPE")
    p=a["plan"]
    need(type(p) is dict and type(p.get("planned_at_ms")) is int
        and p["planned_at_ms"]+scope["max_upload_ms"]<scope["approval_expires_ms"],"NATIVE_RECOVERY_PLAN")
    expected_plan=upload_policy_plan(planned_at_ms=p["planned_at_ms"],max_upload_ms=scope["max_upload_ms"],
        max_clock_skew_ms=scope["max_clock_skew_ms"],approved_until_ms=scope["approved_until_ms"])
    need(p==expected_plan and all(type(p[k]) is type(v) for k,v in expected_plan.items()),"NATIVE_RECOVERY_PLAN")
    auth=a["archive_authentication"]
    need(type(auth) is dict and set(auth)=={"archive_format","authenticated_chunks","ciphertext_sha256","restore_verified"}
        and auth["archive_format"]=="JWPGBK2" and auth["ciphertext_sha256"]==scope["sha256"]
        and type(auth["authenticated_chunks"]) is int and 1<=auth["authenticated_chunks"]<=32
        and auth["restore_verified"] is False,"NATIVE_RECOVERY_ARCHIVE_RECORD")
    fid=None
    if len(lines)>=2:
        ack=lines[1];fid=ack.get("file_id")
        need(set(ack)=={"stage","file_id"} and ack["stage"]=="ack" and type(fid) is str and 0<len(fid)<=1024,"NATIVE_RECOVERY_ACK")
    if len(lines)>=3:
        need(lines[2]=={"stage":"verified","file_id":fid,"sha256":scope["sha256"],"retain_until_ms":p["retain_until_ms"]},"NATIVE_RECOVERY_VERIFIED")
    if len(lines)==4:
        need(lines[3]=={"stage":"complete","verified":1},"NATIVE_RECOVERY_COMPLETE")
    return {"plan":p,"file_id":fid,"already_complete":len(lines)==4,"prior_stage":lines[-1]["stage"]}

def reconcile_interrupted_upload(*,scope,approved_scope_sha256,raw,journal_raw,journal_sha256,audit_credentials):
    """Owner-approved read-only reconciliation of an uncertain write outcome.
    Never creates, retries, updates, deletes, or modifies the original journal.
    Remote absence is not proof that another attempt is safe.
    """
    j=recovery_plan(scope=scope,approved_scope_sha256=approved_scope_sha256,raw=raw,
        journal_raw=journal_raw,journal_sha256=journal_sha256)
    common={"journal_sha256":journal_sha256,"retry_authorized":False,"remote_write":False,
        "restore_verified":False,"archive_authentication_reverified":False,"production_authorized":False}
    if j["already_complete"]:
        return dict(common,status="NATIVE_RECOVERY_ALREADY_COMPLETE_NO_REMOTE_READ",remote_read=False,ciphertext_reverified=False)
    aa,rs=_auth(audit_credentials);_scope_session(aa,rs,scope,False)
    rows=_versions(aa,rs,scope)
    if not rows:
        return dict(common,status="NATIVE_RECOVERY_REMOTE_ABSENT_UNCERTAIN",remote_read=True,ciphertext_reverified=False)
    need(len(rows)==1,"NATIVE_RECOVERY_MULTIPLE_VERSIONS")
    row=rows[0];fid=row.get("fileId")
    need(type(fid) is str and 0<len(fid)<=1024 and (j["file_id"] is None or fid==j["file_id"]),"NATIVE_RECOVERY_FILE_ID")
    expected=dict(bucketId=scope["bucket_id"],fileName=scope["name"],fileId=fid,
        contentLength=len(raw),contentSha1=hashlib.sha1(raw).hexdigest())
    plan=j["plan"]
    verify_uploaded_metadata(plan=plan,expected=expected,info=row,now_ms=now_ms())
    info=_api(aa,rs,"b2_get_file_info",{"fileId":fid})
    verify_uploaded_metadata(plan=plan,expected=expected,info=info,now_ms=now_ms())
    hold=legal_hold_state(info)
    need(legal_hold_state(row)==hold and row["uploadTimestamp"]==info["uploadTimestamp"],"NATIVE_RECOVERY_METADATA_DRIFT")
    got,h=_download(aa,rs,fid,len(raw))
    need(got==raw and h.get("X-Bz-File-Id")==fid and h.get("X-Bz-Content-Sha1")==expected["contentSha1"]
        and h.get("X-Bz-File-Retention-Mode")=="compliance"
        and h.get("X-Bz-File-Retention-Retain-Until-Timestamp")==str(plan["retain_until_ms"]),"NATIVE_RECOVERY_READBACK")
    final=_versions(aa,rs,scope)
    need(len(final)==1,"NATIVE_RECOVERY_FINAL_VERSION_COUNT")
    verify_uploaded_metadata(plan=plan,expected=expected,info=final[0],now_ms=now_ms())
    need(legal_hold_state(final[0])==hold and final[0]["uploadTimestamp"]==info["uploadTimestamp"],"NATIVE_RECOVERY_METADATA_DRIFT")
    return dict(common,status="NATIVE_RECOVERY_REMOTE_MATCH_READ_ONLY",remote_read=True,ciphertext_reverified=True,
        file_id=fid,ciphertext_sha256=scope["sha256"],retain_until_ms=plan["retain_until_ms"])
