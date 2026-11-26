"""Owner-operated metadata-only B2 review. No download, backup write, or key read."""
import base64,getpass,hashlib,http.client,json,os,re,resource,signal,ssl,stat,subprocess,sys,time,uuid,warnings
from pathlib import Path
from urllib.parse import urlencode,urlsplit

CAPS={"listBuckets","listFiles","readBucketRetentions","readBucketEncryption","readFileRetentions","readFileLegalHolds"}
BUCKET="818b599eca5772d820b2b04ba3e192b5e40688fb9a715b4b1082d7b5aed2be5c"
PREFIX="jw-v223/"
PIN="738a22b35033d6bd898e3824ba74d8005f508f82516d6362c375743b5f83040d"
MANIFEST="684d41254d8ffda4c97a56648d2d0e1bd290ceea1838ddd33ebf0b4983b8ccc4"
AUDIT=("JW_B2_AUDIT_KEY_ID","JW_B2_AUDIT_APPLICATION_KEY")
SOURCE="0fb0c5b0b83bc0c98bf874d54c8a0dbc410a7971:scripts/naruv_owner_retention_evidence.py"
STAGE="20833f63cc85e76d30b3cda860f0567bd7d9b39e:scripts/naruv_b2_offline_stage.py"

def need(ok,code):
    if not ok:raise ValueError(code)
def now():return int(time.time()*1000)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(ref,oid):
    env={k:v for k,v in os.environ.items() if k in ("HOME","PATH","LANG")}
    env.update(GIT_NO_REPLACE_OBJECTS="1",GIT_CONFIG_NOSYSTEM="1",GIT_CONFIG_GLOBAL="/dev/null",GIT_TERMINAL_PROMPT="0")
    raw=subprocess.check_output(["git","show",ref],env=env,stdin=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
    need(hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==oid,"SOURCE_PIN")
    ns={"__name__":"pinned_review"};exec(compile(raw,"pinned_review","exec"),ns);return ns

def request(host,method,path,token,body=None):
    need(type(host) is str and re.fullmatch(r"api[0-9]*\.backblazeb2\.com",host),"API_HOST")
    need(type(token) is str and 0<len(token)<=8192 and all(32<=ord(c)<=126 for c in token),"API_TOKEN")
    c=http.client.HTTPSConnection(host,timeout=30,context=ssl.create_default_context())
    try:
        c.request(method,path,body=body,headers={"Authorization":token,"Content-Type":"application/json","Accept-Encoding":"identity"})
        r=c.getresponse()
        need(r.status==200,"B2_HTTP_"+str(r.status))
        raw=r.read(2097153);need(0<len(raw)<=2097152,"API_RESPONSE_SIZE")
        return json.loads(raw)
    finally:c.close()

def auth(i,k):
    need(all(type(v) is str and 0<len(v)<=4096 and all(33<=ord(c)<=126 for c in v) for v in (i,k)) and ":" not in i,"AUTH_FORMAT")
    return request("api.backblazeb2.com","GET","/b2api/v4/b2_authorize_account","Basic "+base64.b64encode((i+":"+k).encode("ascii")).decode("ascii"))

def storage(d):return d["apiInfo"]["storageApi"]
def api(d,name,args):
    methods={"b2_create_key":"POST","b2_delete_key":"POST","b2_list_buckets":"POST","b2_list_file_versions":"GET"}
    need(name in methods,"METHOD_DENIED")
    u=urlsplit(storage(d)["apiUrl"])
    need(u.scheme=="https" and u.path in ("","/") and not u.query and not u.fragment,"API_URL")
    path="/b2api/v4/"+name
    if methods[name]=="GET":return request(u.netloc,"GET",path+"?"+urlencode(args),d["authorizationToken"])
    return request(u.netloc,"POST",path,d["authorizationToken"],json.dumps(args).encode())

def target(d):
    b=storage(d)["allowed"]["buckets"]
    need(type(b) is list and len(b)==1 and sha(b[0]["name"].encode())==BUCKET,"BUCKET_PIN")
    need(type(b[0]["id"]) is str and bool(b[0]["id"]),"BUCKET_ID")
    return b[0]["id"],b[0]["name"]

def scope(d,account,bid,expiry):
    a=storage(d)["allowed"]
    need(d["accountId"]==account and target(d)[0]==bid and set(a["capabilities"])==CAPS and a["namePrefix"]==PREFIX and d["applicationKeyExpirationTimestamp"]==expiry and now()<expiry,"TEMP_SCOPE")

def bucket_check(d,bid,bname,account):
    bs=d["buckets"]
    need(type(bs) is list and len(bs)==1,"BUCKET_COUNT")
    b=bs[0]
    need(b["bucketId"]==bid and b["bucketName"]==bname and b["accountId"]==account and b["bucketType"]=="allPrivate","BUCKET_SECURITY")
    lock=b["fileLockConfiguration"];enc=b["defaultServerSideEncryption"]
    need(lock["isClientAuthorizedToRead"] is True and lock["value"]["isFileLockEnabled"] is True,"BUCKET_LOCK")
    need(enc["isClientAuthorizedToRead"] is True and enc["value"]=={"mode":"SSE-B2","algorithm":"AES256"},"BUCKET_ENCRYPTION")

def exact_row(d,name,fid,size,account):
    rows=d["files"]
    need(type(rows) is list and len(rows)==1,"EXACT_VERSION_COUNT")
    r=rows[0]
    need(r["fileName"]==name and r["fileId"]==fid and type(r["contentLength"]) is int and r["contentLength"]==size and r["accountId"]==account,"EXACT_VERSION_IDENTITY")
    return r

def inputs():
    e=load(SOURCE,"8138b19f4ea47c4c361653914acf5095acc0a24c")
    a=e["load_pinned"](e["AUDIT_REF"],e["AUDIT_BLOB"]);j=e["load_pinned"](e["JOURNAL_REF"],e["JOURNAL_BLOB"])
    h=Path.home();read=e["secure_read"];original={}
    for prefix,filename,pin in a["GROUPS"]:
        group=a["parse_receipt"](read(h/filename,65536),prefix,pin)
        need(not set(group)&set(original),"ORIGINAL_SCOPE");original.update(group)
    corrected=j["reconcile"](read(h/e["JOURNAL_NAME"],262144),PIN,original)
    st=load(STAGE,"8c4fd632e3c79d6d4a756a46a760888aad0eeb14")
    raw=read(h/"naruv-restore-prep-zkjdfvg0"/"b2-manifest.json",65536)
    rows=st["parse_manifest"](raw,MANIFEST)
    names={}
    for r in rows:
        prefix=a["GROUPS"][int(r["scope"]=="staged")][0]
        n=prefix+r["git_blob_sha1"]+".jwpgbk"
        need(n in corrected and corrected[n]["file_id"]==r["file_id"] and corrected[n]["sha256"]==r["sha256"],"MANIFEST_RECEIPT_BINDING")
        names[n]=r
    need(set(names)==set(corrected) and len(names)==22,"MANIFEST_SCOPE")
    return corrected,names,j["check_live_metadata"]

def main():
    need(os.environ.get("CODESPACES","").lower()=="true","OWNER_CODESPACE_REQUIRED")
    os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0));warnings.simplefilter("error",getpass.GetPassWarning)
    corrected,names,check=inputs()
    print("PINNED_INPUTS=PASS",flush=True)
    audit=auth(*(os.environ[k] for k in AUDIT));bid,bname=target(audit);account=audit["accountId"];aid=os.environ[AUDIT[0]]
    audit=None
    keep={k:v for k,v in os.environ.items() if k in ("HOME","PATH","LANG","TERM")};os.environ.clear();os.environ.update(keep)
    mid=getpass.getpass("Master keyID: ");secret=getpass.getpass("Master applicationKey: ")
    master=auth(mid,secret);secret=None
    need(master["accountId"]==account and {"writeKeys","deleteKeys"}<=set(storage(master)["allowed"]["capabilities"]),"MASTER_SCOPE")
    name="naruv-meta-"+uuid.uuid4().hex[:20];kid=None;ok=False;clean=False
    print("TEMP_KEY_NAME="+name,flush=True)
    try:
        start=now()
        c=api(master,"b2_create_key",{"accountId":account,"capabilities":sorted(CAPS),"keyName":name,"validDurationInSeconds":3600,"bucketIds":[bid],"namePrefix":PREFIX})
        candidate=c["applicationKeyId"]
        need(type(candidate) is str and bool(candidate) and candidate not in (mid,aid,account),"NEW_KEY_ID")
        kid=candidate
        expiry=c["expirationTimestamp"]
        need(c["keyName"]==name and c["accountId"]==account and c["bucketIds"]==[bid] and set(c["capabilities"])==CAPS and c["namePrefix"]==PREFIX and type(expiry) is int and start<expiry<=now()+3600000,"KEY_CREATION_SCOPE")
        d=auth(kid,c["applicationKey"]);c=None
        scope(d,account,bid,expiry)
        print("METADATA_ONLY_KEY=PASS",flush=True)
        bucket_check(api(d,"b2_list_buckets",{"accountId":account,"bucketId":bid}),bid,bname,account)
        rows=[]
        for n,r in sorted(names.items()):
            need(now()<expiry,"TEMP_EXPIRED")
            response=api(d,"b2_list_file_versions",{"bucketId":bid,"prefix":n,"startFileName":n,"startFileId":r["file_id"],"maxFileCount":1})
            rows.append(exact_row(response,n,r["file_id"],r["size"],account))
        result=check(rows,corrected,bid,now())
        need(result["metadata_verified"]==22 and result["strict_30day_shortfall_count"]==0,"RETENTION_RESULT")
        print(json.dumps(result,sort_keys=True),flush=True)
        print("B2_LIVE_METADATA=PASS_22",flush=True)
        d=None;ok=True
    finally:
        if kid is not None:
            try:
                r=api(master,"b2_delete_key",{"applicationKeyId":kid})
                need(r["applicationKeyId"]==kid,"KEY_DELETE_ID")
                clean=True;print("TEMP_KEY_CLEANUP=PASS",flush=True)
            except Exception:print("TEMP_KEY_CLEANUP=BLOCKED",flush=True)
        else:print("TEMP_KEY_CREATION_UNCONFIRMED_CHECK_NAME",flush=True)
    need(ok and clean,"REVIEW_OR_CLEANUP_INCOMPLETE")
    print("METADATA_REVIEW_COMPLETE / NO_BACKUP_WRITE / NO_DOWNLOAD",flush=True)

if __name__=="__main__":
    try:
        signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        main()
    except (Exception,KeyboardInterrupt) as exc:
        code=str(exc)
        print("BLOCKED="+(code if type(exc) is ValueError and re.fullmatch(r"[A-Z0-9_]{3,100}",code) else type(exc).__name__))
        sys.exit(1)
