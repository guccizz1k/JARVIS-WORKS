"""Representative local recovery ACL comparison, no source DB/network access.
Reuses verified encrypted archive, preserves ACLs but intentionally does not
restore owners or cluster globals. A mismatch is evidence, never auto-granted.
"""
import csv
import getpass
import hashlib
import io
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
import warnings
from pathlib import Path
from scripts import jw_key_escrow_v223 as escrow
from scripts import p1_external_custodian_pg17_v223 as recovery

IMAGE="sha256:ff87138949ad9a46f32ff23bd6852b52ce024a13dffe9b4087be98292cdd3b4f"
BLOB="58942e8de3e1e70fbf1c0cad98b4ae51a6ccef3f"
CIPHER="993430a862fa080756419357009db82ef7467e3dc2c06e389778d89ea5fec5e3"
PLAIN="c9566b8bd2202e822ad520c706b4dd7023eaa95610ec81eb7e01c30efef39da3"
CATEGORIES={"acl","defaults","members","owners","roles"}

def need(ok,label):
    if not ok: raise RuntimeError(label)

def run(args,*,data=None,timeout=60):
    q=subprocess.run(args,input=data,capture_output=True,timeout=timeout)
    if q.returncode:
        # Never print raw SQL, role names, or provider data.
        code=re.search(rb"ERROR:\s+([0-9A-Z]{5}):",q.stderr)
        label=code.group(1).decode() if code else "UNCLASSIFIED"
        raise RuntimeError("COMMAND_FAILED_"+label)
    return q.stdout

def local_cipher(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as f:
        st=os.fstat(f.fileno())
        need(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o600,"PRIVATE_CIPHER_REQUIRED")
        need(0<st.st_size<=recovery.clean.MAX_OBJECT,"CIPHER_SIZE")
        data=f.read(st.st_size+1)
        end=os.fstat(f.fileno())
        need(len(data)==st.st_size and (st.st_mtime_ns,st.st_ctime_ns)==(end.st_mtime_ns,end.st_ctime_ns),"CIPHER_CHANGED")
    need(hashlib.sha256(data).hexdigest()==CIPHER,"CIPHER_HASH")
    need(hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()==BLOB,"BLOB_HASH")
    return data

def parse(text):
    reader=csv.reader(io.StringIO(text))
    out={}
    for row in reader:
        need(len(row)==8 and row[0]=="JW-PG17-AUTHZ-SQL-V1" and row[1] in CATEGORIES and row[1] not in out,"PROFILE_FORMAT")
        need(row[2].isdigit() and re.fullmatch(r"[a-f0-9]{64}",row[3]) and row[4]=="2" and row[5].isdigit() and row[6]=="0" and row[7]=="t","PROFILE_INCOMPLETE")
        out[row[1]]=(int(row[2]),row[3],int(row[5]))
    need(set(out)==CATEGORIES and len({r[2] for r in out.values()})==1 and out["acl"][0]==out["owners"][0]==out["acl"][2],"PROFILE_COUNT")
    return out

def compare(actual,reference):
    need(set(actual)==set(reference)==CATEGORIES,"REFERENCE_SCOPE")
    result={}
    for k in sorted(CATEGORIES):
        n,h=reference[k]
        need(type(n) is int and n>=0 and re.fullmatch(r"[a-f0-9]{64}",h),"REFERENCE_FORMAT")
        result[k]={"source_records":n,"restored_records":actual[k][0],
            "match":actual[k][:2]==(n,h)}
    return result

def main():
    need(len(sys.argv)==2,"REFERENCE_REQUIRED")
    reference=json.loads(sys.argv[1])
    need(type(reference) is dict and set(reference)==CATEGORIES,"REFERENCE_FORMAT")
    need(not sys.flags.optimize and not os.environ.get("DOCKER_HOST") and not os.environ.get("DOCKER_TLS_VERIFY"),"LOCAL_DOCKER_REQUIRED")
    need(run(["docker","context","inspect","--format","{{.Endpoints.docker.Host}}"]).strip().startswith(b"unix://"),"LOCAL_DOCKER_REQUIRED")
    need(run(["docker","image","inspect","postgres:17","--format","{{.Id}}"]).strip().decode()==IMAGE,"IMAGE_ID_CHANGED")
    need(b"17." in run(["pg_restore","--version"]),"CLIENT_VERSION")
    home=Path.home()
    data=local_cipher(home/".jw-rekey-candidate-20261124"/(BLOB+".jwpgbk"))
    envelope=escrow.read_private(home/".jw-key-escrow-20261124/candidate-key.jwescrow")
    need(hashlib.sha256(envelope).hexdigest()=="43c4ddbab98ba2a4978bf7aaa910378f20ac9c1c1900ea3d472c4a8fcc0e6151","ESCROW_HASH")
    warnings.simplefilter("error",getpass.GetPassWarning)
    print("AUTHZ_RESTORE_PREFLIGHT_PASS",flush=True)
    key=escrow.unseal(envelope,getpass.getpass("Escrow passphrase: ").encode())
    plain=recovery.decrypt_verified(data,key);del key
    name="jw-authz-compare-"+secrets.token_hex(10)
    started=False; result=None
    try:
        need(hashlib.sha256(plain).hexdigest()==PLAIN,"PLAINTEXT_HASH")
        schema=run(["pg_restore","--schema-only","--file","-"],data=bytes(plain),timeout=50).decode()
        roles=set()
        for line in schema.splitlines():
            if line.startswith(("GRANT ","REVOKE ","ALTER DEFAULT PRIVILEGES ","CREATE POLICY ")):
                for match in re.finditer(r"\b(?:TO|FROM|FOR ROLE)\s+([^;]+)",line):
                    for part in match.group(1).split(","):
                        token=part.strip().split()[0].strip('"') if part.strip() else ""
                        if re.fullmatch(r"[a-z][a-z0-9_]{0,62}",token) and token not in ("postgres","public") and not token.startswith("pg_"):
                            roles.add(token)
        del schema
        roles.update(("jw_auth_stage_v85","jw_dev_import_review_executor_v201"))
        need(len(roles)<=64,"ROLE_COUNT")
        run(["docker","run","-d","--rm","--pull","never","--name",name,
             "--network","none","--read-only","--memory","768m","--cpus","1","--pids-limit","128",
             "--tmpfs","/var/lib/postgresql/data:rw,nosuid,size=384m",
             "--tmpfs","/var/run/postgresql:rw,nosuid,size=16m",
             "--tmpfs","/tmp:rw,nosuid,size=32m","--log-driver","none",
             "-e","POSTGRES_HOST_AUTH_METHOD=trust",IMAGE],timeout=45)
        started=True
        need(run(["docker","inspect",name,"--format","{{.HostConfig.NetworkMode}}"]).strip()==b"none","NETWORK_MODE")
        need(not any(m.get("Type") in ("bind","volume") for m in json.loads(run(["docker","inspect",name,"--format","{{json .Mounts}}"]))),"PERSISTENT_MOUNT")
        for _ in range(90):
            q=subprocess.run(["docker","exec",name,"sh","-c",'test "$(cat /proc/1/comm)" = postgres && pg_isready -q -U postgres'],capture_output=True,timeout=5)
            if q.returncode==0:break
            time.sleep(1)
        else:raise RuntimeError("PG17_NOT_READY")
        def sql(q,db="restore"):
            return run(["docker","exec","-i",name,"psql","-X","-qAt","-U","postgres","-d",db,"-v","ON_ERROR_STOP=1","-v","VERBOSITY=verbose"],data=q.encode()).decode().strip()
        need(sql("SHOW server_version;","postgres").startswith("17."),"SERVER_VERSION")
        for r in sorted(roles):
            sql('CREATE ROLE "'+r+'" NOLOGIN;',"postgres")
        run(["docker","exec",name,"createdb","-U","postgres","restore"])
        sql("CREATE SCHEMA IF NOT EXISTS extensions; CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;")
        run(["docker","exec","-i",name,"pg_restore","--no-owner","--exit-on-error","-U","postgres","-d","restore"],data=bytes(plain),timeout=180)
        q=(Path(__file__).resolve().parents[1]/"db/review/jw_current_authz_sql_v1.sql").read_text()
        # Single read-only statement, explicit CSV unaligned result.
        out=run(["docker","exec","-i",name,"psql","-X","--csv","-qt","-U","postgres","-d","restore","-v","ON_ERROR_STOP=1","-v","VERBOSITY=verbose"],data=("BEGIN READ ONLY; SET LOCAL statement_timeout='30s';\n"+q+"\nROLLBACK;\n").encode(),timeout=60)
        result=compare(parse(out.decode()),reference)
    finally:
        plain.clear()
        if started:
            run(["docker","rm","-f",name],timeout=40)
            need(not run(["docker","ps","-aq","--filter","name=^/"+name+"$"]).strip(),"CLEANUP_FAILED")
    need(result is not None,"COMPARISON_MISSING")
    print(json.dumps({"profile":"JW-PG17-AUTHZ-SQL-V1","categories":result,
        "comparison_executed":"PASS","disposable_cleanup":"PASS",
        "ownership_restore":"NOT_RUN_NO_OWNER","cluster_globals":"NOT_BACKED_UP",
        "historical_source":"NOT_ATTESTED","overall":"BLOCKED","activation_allowed":False},sort_keys=True))

if __name__=="__main__":
    try:main()
    except Exception as exc:
        s=str(exc)
        print("AUTHZ_RESTORE_BLOCKED:"+ (s if re.fullmatch(r"[A-Z0-9_]{1,100}",s) else type(exc).__name__),file=sys.stderr)
        sys.exit(1)
