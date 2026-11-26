"""Owner-only, one-shot synthetic B2 probe. No production data or keys.
Run pinned source via python -I in owner Codespace. No network until owner
confirms free allowance; no upload until owner confirms exact scope.
Existing 22 objects and all operational keys are out of scope.
"""
import getpass,hashlib,json,os,re,resource,secrets,stat,struct,subprocess,sys,time,types
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SOURCE="5c3fc3a9f7bd50e6ec281460cb79c37c18d531d5"
PINS={
    "naruv_b2_retention_journal":"241397b9ff941b6a46cb20119633c94215796540",
    "naruv_b2_upload_policy":"a1d619e7dd8034638f69f9b1fd50a44e60f67f7b",
    "naruv_b2_native_upload":"5147fe77491f06fa0466e0473fce567b3a8069bc",
    "naruv_recovery_custody_review":"6aafed77f21a775cf9b478035d3b77ed2a8b31bd",
    "naruv_operational_readiness":"e05f1f5b6107a6e8318147ef3ca17229bffdb0e0",
}
BUCKET_PIN="818b599eca5772d820b2b04ba3e192b5e40688fb9a715b4b1082d7b5aed2be5c"
DAY=86400000
MAX=1024*1024
IMAGE="postgres:17"
ROOT=".naruv-one-b2-synthetic-probe-20261126"
AUDIT_EXTRA={"readBucketLifecycleRules","readBucketLogging","readBucketNotifications",
    "readBucketReplications","shareFiles","readBuckets","listAllBucketNames"}

def need(ok,code):
    if not ok:raise ValueError(code)
def sha(b):return hashlib.sha256(b).hexdigest()
def env():
    return {k:v for k,v in os.environ.items() if k in ("HOME","PATH","LANG","LC_ALL")}
def run(args,*,data=None,timeout=45,check=True):
    r=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env(),timeout=timeout)
    need(not check or r.returncode==0,"OWNER_LOCAL_COMMAND_FAILED")
    return r
def load_modules():
    pkg=types.ModuleType("app");pkg.__path__=[];sys.modules["app"]=pkg
    for name,pin in PINS.items():
        raw=run(["git","--no-replace-objects","show",SOURCE+":app/"+name+".py"]).stdout
        need(hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==pin,"OWNER_SOURCE_PIN")
        m=types.ModuleType("app."+name);m.__package__="app";sys.modules[m.__name__]=m
        setattr(pkg,name,m);exec(compile(raw,m.__name__,"exec"),m.__dict__)
    return pkg.naruv_b2_native_upload,pkg.naruv_operational_readiness
def docker(args,**kw):
    return run(["docker","-H","unix:///var/run/docker.sock",*args],**kw)

def synthetic_dump():
    # Cached image only. No mounts, no exposed ports, no network or external DB.
    docker(["image","inspect",IMAGE])
    name="naruv-synthetic-"+secrets.token_hex(12)
    cid=docker(["run","--rm","--pull=never","-d","--name",name,"--network","none",
        "--publish-all=false","--memory","512m","--cpus","1",
        "-e","POSTGRES_HOST_AUTH_METHOD=trust",IMAGE]).stdout.decode().strip()
    need(re.fullmatch("[0-9a-f]{64}",cid),"OWNER_CONTAINER_ID")
    try:
        for _ in range(40):
            if docker(["exec",cid,"pg_isready","-h","127.0.0.1","-U","postgres"],check=False).returncode==0:
                # Ensure init has finished and the isolated server remains up.
                time.sleep(1)
                if docker(["exec",cid,"pg_isready","-h","127.0.0.1","-U","postgres"],check=False).returncode==0:break
            time.sleep(1)
        else:raise ValueError("OWNER_PG17_NOT_READY")
        inspect=json.loads(docker(["inspect",cid]).stdout)
        need(len(inspect)==1 and inspect[0]["HostConfig"]["NetworkMode"]=="none"
            and not inspect[0]["HostConfig"]["Binds"] and not inspect[0]["HostConfig"]["PortBindings"],"OWNER_CONTAINER_ISOLATION")
        def sql(db,q):return docker(["exec",cid,"psql","-X","-U","postgres","-d",db,"-At","-v","ON_ERROR_STOP=1","-c",q]).stdout.strip()
        version=sql("postgres","SHOW server_version_num")
        need(version.isdigit() and 170000<=int(version)<180000,"OWNER_PG17_VERSION")
        docker(["exec",cid,"createdb","-U","postgres","naruv_fixture"])
        sql("naruv_fixture","CREATE TABLE public.probe(id integer PRIMARY KEY, label text NOT NULL); INSERT INTO public.probe VALUES (1,'synthetic-a'),(2,'synthetic-b');")
        dump=docker(["exec",cid,"pg_dump","-U","postgres","-Fc","--no-owner","--no-acl","naruv_fixture"]).stdout
        need(dump.startswith(b"PGDMP") and 5<len(dump)<MAX-36,"OWNER_DUMP_SIZE")
        docker(["exec",cid,"createdb","-U","postgres","naruv_restored"])
        docker(["exec","-i",cid,"pg_restore","-U","postgres","--exit-on-error","--no-owner","--no-acl","-d","naruv_restored"],data=dump)
        need(sql("naruv_restored","SELECT id||':'||label FROM public.probe ORDER BY id")==b"1:synthetic-a\n2:synthetic-b","OWNER_PG17_RESTORE")
    finally:
        # Only remove the newly created disposable container, never an existing one.
        docker(["stop","-t","5",cid],timeout=20)
    return dump

def encrypt_dump(dump,key):
    need(type(dump) is bytes and 5<len(dump)<MAX-36 and dump.startswith(b"PGDMP")
        and type(key) is bytes and len(key)==32,"OWNER_DUMP_FORMAT")
    prefix=secrets.token_bytes(8)
    blob=AESGCM(key).encrypt(prefix+struct.pack(">I",0),dump,b"JWPGBK2\n"+struct.pack(">QB",0,1))
    raw=b"JWPGBK2\n"+prefix+struct.pack(">I",len(blob))+blob
    need(len(raw)<=MAX,"OWNER_CIPHER_LIMIT")
    return raw

def store(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
    d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(d)
    finally:os.close(d)

def read_owner_audit(n):
    creds=(os.environ.get("JW_B2_AUDIT_KEY_ID"),os.environ.get("JW_B2_AUDIT_APPLICATION_KEY"))
    if not all(creds):creds=(getpass.getpass("Existing read-only B2 key ID: "),getpass.getpass("Existing read-only B2 key secret: "))
    a,s=n._auth(creds);v=s["allowed"];b=v["buckets"];caps=set(v["capabilities"])
    need(type(b) is list and len(b)==1 and sha(b[0]["name"].encode())==BUCKET_PIN
        and not v["namePrefix"] and n.AUDIT_CAPS<=caps<=n.AUDIT_CAPS|AUDIT_EXTRA,"OWNER_AUDIT_SCOPE")
    bid=b[0]["id"];name=b[0]["name"]
    buckets=n._api(a,s,"b2_list_buckets",{"accountId":a["accountId"],"bucketId":bid})["buckets"]
    need(len(buckets)==1 and buckets[0]["bucketId"]==bid and buckets[0]["bucketName"]==name
        and buckets[0]["bucketType"]=="allPrivate"
        and buckets[0]["fileLockConfiguration"]["isClientAuthorizedToRead"] is True
        and buckets[0]["fileLockConfiguration"]["value"]["isFileLockEnabled"] is True
        and buckets[0]["defaultServerSideEncryption"]["isClientAuthorizedToRead"] is True
        and buckets[0]["defaultServerSideEncryption"]["value"]=={"mode":"SSE-B2","algorithm":"AES256"},"OWNER_BUCKET_SECURITY")
    return a["accountId"],bid,name

def create_temp(n,a,s,scope,caps,prefix,suffix):
    now=n.now_ms()
    need(now+3600000+60000<scope["approval_expires_ms"],"OWNER_KEY_APPROVAL_WINDOW")
    params=dict(accountId=scope["account_id"],capabilities=sorted(caps),
        keyName="naruv-probe-"+scope["name"].split("/")[2]+"-"+suffix,
        validDurationInSeconds=3600,bucketIds=[scope["bucket_id"]])
    if prefix is not None:params["namePrefix"]=prefix
    r=n._json(n._base(s["apiUrl"])+"/b2api/v4/b2_create_key",a["authorizationToken"],params)
    need(r["accountId"]==scope["account_id"] and r["bucketIds"]==[scope["bucket_id"]]
        and set(r["capabilities"])==caps and len(r["capabilities"])==len(caps)
        and r.get("namePrefix")==prefix and type(r["expirationTimestamp"]) is int
        and now<r["expirationTimestamp"]<=min(now+3660000,scope["approval_expires_ms"])
        and all(type(r.get(k)) is str and bool(r[k]) for k in ("applicationKeyId","applicationKey")),"OWNER_TEMP_KEY_SCOPE")
    return r["applicationKeyId"],r["applicationKey"]

def confirm(prompt,token):
    with open("/dev/tty","r",encoding="utf-8") as tty:
        print(prompt,flush=True)
        need(tty.readline().strip()==token,"OWNER_CONFIRMATION_MISSING")
def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
    need(os.environ.get("CODESPACES","").lower()=="true","OWNER_CODESPACE_REQUIRED")
    need(not (Path.home()/ROOT).exists(),"OWNER_EXISTING_PROBE_NO_RETRY")
    # Free allowance is owner-attested, not independently measured by API.
    confirm("Confirm B2 dashboard storage below 9.99 GB and free egress allowance >= 1 MiB. Type FREE10","FREE10")
    n,ready=load_modules()
    dump=synthetic_dump()
    key=AESGCM.generate_key(256);raw=encrypt_dump(dump,key);del dump
    print("LOCAL_SYNTHETIC_PG17_RESTORE_PASS",flush=True)
    account,bid,bname=read_owner_audit(n)
    ts=n.now_ms()
    proposed=ready.prepare_upload_scope(account_id=account,bucket_id=bid,bucket_name=bname,
        operation_id=secrets.token_hex(16),raw=raw,archive_key=key,planned_at_ms=ts,
        approval_expires_ms=ts+5*3600000,approved_until_ms=ts+30*DAY+900000,
        max_upload_ms=120000,max_clock_skew_ms=60000)
    scope=proposed["scope"];pin=proposed["scope_sha256"]
    print(json.dumps({"status":"SCOPE_PROPOSAL","scope_sha256":pin,"size_bytes":len(raw),
        "max_retention_from_proposal_ms":30*DAY+900000,"temporary_key_hours":1,
        "existing_backup_changes":0,"production_data":False}),flush=True)
    confirm("Authorize this exact proposal, 1 synthetic object, 2 temporary keys. Type UPLOAD","UPLOAD")
    root=Path.home()/ROOT
    root.mkdir(mode=0o700,exist_ok=False)
    store(root/"synthetic.jwpgbk",raw)
    # Newly generated fixture-only key. Never read or use an existing backup key.
    store(root/"synthetic.key",key)
    store(root/"scope.json",json.dumps(dict(scope=scope,scope_sha256=pin),sort_keys=True).encode()+b"\n")
    print("LOCAL_PROBE_EVIDENCE_SAVED",flush=True)
    master=(getpass.getpass("B2 master key ID: "),getpass.getpass("B2 master application key: "))
    a,s=n._auth(master);del master
    need(a["accountId"]==account and "writeKeys" in s["allowed"]["capabilities"],"OWNER_MASTER_ACCOUNT")
    writer=create_temp(n,a,s,scope,n.WRITER_CAPS,scope["name"],"write")
    print("TEMP_WRITER_CREATED_1H",flush=True)
    audit=create_temp(n,a,s,scope,n.AUDIT_CAPS,None,"audit")
    print("TEMP_AUDIT_CREATED_1H",flush=True)
    del a,s
    result=n.execute_approved_upload(scope=scope,approved_scope_sha256=pin,raw=raw,
        archive_key=key,writer_credentials=writer,audit_credentials=audit,journal_dir=root)
    del writer,audit,key
    need(result["status"]=="NATIVE_UPLOAD_READBACK_VERIFIED" and result["ciphertext_verified"] is True,"OWNER_UPLOAD_RESULT")
    output=dict(status="SYNTHETIC_B2_LIVE_PROBE_PASS",verified_objects=1,local_synthetic_pg17_restore=True,
        provider_readback_verified=True,compliance_minimum_30days=True,existing_backups_modified=0,
        operational_keys_modified=0,physical_custody_verified=False,production_authorized=False,
        scope_sha256=pin,scope_size_bytes=len(raw))
    store(root/"result.json",json.dumps(output,sort_keys=True).encode()+b"\n")
    print(json.dumps(output,sort_keys=True),flush=True)

if __name__=="__main__":
    try:main()
    except BaseException as exc:
        code=str(exc) if type(exc) is ValueError and re.fullmatch("[A-Z_]{3,100}",str(exc)) else type(exc).__name__
        print("BLOCKED",code,"DO_NOT_RETRY_CHECK_LOCAL_EVIDENCE",file=sys.stderr,flush=True);sys.exit(1)
