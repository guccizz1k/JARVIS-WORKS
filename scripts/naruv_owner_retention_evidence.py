"""Owner-only offline reconciliation. No B2 calls, keys, or database access.

Run from owner Codespace using pinned Git objects. The correction journal pin
must come from the previously recorded successful owner execution.
"""
import hashlib,json,os,re,resource,stat,subprocess,sys
from pathlib import Path

AUDIT_REF="36d48ecf8814d42ae517ce6efd16f5f5212e43d0:scripts/jw_b2_readonly_audit.py"
AUDIT_BLOB="2c9a5266c84e8f52669d2789beb2708a4d4ca689"
JOURNAL_REF="c7266e76b8934b0385d237dba475bfad210ccf98:app/naruv_b2_retention_journal.py"
JOURNAL_BLOB="241397b9ff941b6a46cb20119633c94215796540"
JOURNAL_NAME=".naruv-b2-retention-correction-20261126.jsonl"

def need(ok,code):
    if not ok:raise ValueError(code)

def secure_read(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as f:
        s=os.fstat(f.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and 0<s.st_size<=limit,"PRIVATE_EVIDENCE")
        raw=f.read(limit+1);z=os.fstat(f.fileno())
        need(len(raw)==s.st_size and (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns),"EVIDENCE_DRIFT")
        return raw

def load_pinned(ref,oid):
    env={k:v for k,v in os.environ.items() if k in ("HOME","PATH","LANG")}
    env.update(GIT_NO_REPLACE_OBJECTS="1",GIT_TERMINAL_PROMPT="0",GIT_CONFIG_NOSYSTEM="1",GIT_CONFIG_GLOBAL="/dev/null")
    raw=subprocess.check_output(["git","show",ref],env=env,stdin=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
    need(hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==oid,"SOURCE_PIN")
    d={"__name__":"offline_review"};exec(compile(raw,"offline_review","exec"),d);return d

def check(home,pin,parser,reconciler,groups,reader=secure_read):
    need(type(pin) is str and re.fullmatch("[0-9a-f]{64}",pin),"JOURNAL_PIN_FORMAT")
    expected={};original_hashes=[]
    for prefix,filename,scope in groups:
        raw=reader(home/filename,65536)
        parsed=parser(raw,prefix,scope)
        need(len(parsed)==11 and not set(parsed)&set(expected),"RECEIPT_SCOPE")
        expected.update(parsed);original_hashes.append(hashlib.sha256(raw).hexdigest())
    need(len(expected)==22 and len({r["file_id"] for r in expected.values()})==22,"RECEIPT_SCOPE")
    journal=reader(home/JOURNAL_NAME,262144)
    corrected=reconciler(journal,pin,expected)
    need(set(corrected)==set(expected) and all(corrected[n]["file_id"]==expected[n]["file_id"] and corrected[n]["sha256"]==expected[n]["sha256"] and 0<corrected[n]["retain_until_ms"]-expected[n]["retain_until_ms"]<=1000 for n in expected),"CORRECTION_SCOPE")
    # Repeat local reads only, to reject concurrent changes during evidence assembly.
    for i,(_,filename,_) in enumerate(groups):
        need(hashlib.sha256(reader(home/filename,65536)).hexdigest()==original_hashes[i],"ORIGINAL_EVIDENCE_DRIFT")
    need(hashlib.sha256(reader(home/JOURNAL_NAME,262144)).hexdigest()==pin,"JOURNAL_DRIFT")
    return {"status":"OWNER_RETENTION_JOURNAL_RECONCILED","original_receipts":22,"corrected_receipts":22,"journal_sha256":pin,"remote_write":False,"remote_read":False,"restore_verified":False,"key_custody_verified":False,"production_authorized":False}

def main():
    os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    need(os.environ.get("CODESPACES","").lower()=="true","OWNER_CODESPACE_REQUIRED")
    need(len(sys.argv)==2,"JOURNAL_PIN_REQUIRED")
    env={k:v for k,v in os.environ.items() if k in ("HOME","PATH","LANG","CODESPACES")}
    os.environ.clear();os.environ.update(env)
    a=load_pinned(AUDIT_REF,AUDIT_BLOB);j=load_pinned(JOURNAL_REF,JOURNAL_BLOB)
    print(json.dumps(check(Path.home(),sys.argv[1],a["parse_receipt"],j["reconcile"],a["GROUPS"]),sort_keys=True),flush=True)

if __name__=="__main__":
    try:main()
    except Exception as e:
        code=str(e) if type(e) is ValueError and re.fullmatch("[A-Z_]{3,80}",str(e)) else type(e).__name__
        print("BLOCKED",code,"NO_REMOTE_ACCESS",file=sys.stderr);sys.exit(1)
