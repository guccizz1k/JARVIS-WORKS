"""Verified PostgreSQL TLS acceptance on the exact disposable CI source only.

No production endpoints, no system trust-store changes, no hosted credentials.
Temporary server settings and keys are removed before returning.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import tempfile
import time
import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict,make_conninfo
from scripts.naruv_erp_restore_ci import docker_guard,need,identity

def command(args,*,data=None):
    p=subprocess.run(args,input=data,capture_output=True,timeout=20)
    need(p.returncode==0,"NARUV_PG_TLS_FIXTURE_COMMAND")
    return p.stdout

def cert_pair(path,name):
    key=path/(name+".key");cert=path/(name+".crt")
    command(["openssl","req","-x509","-newkey","rsa:2048","-nodes",
        "-keyout",str(key),"-out",str(cert),"-days","1","-subj","/CN=localhost",
        "-addext","subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-addext","basicConstraints=critical,CA:TRUE",
        "-addext","extendedKeyUsage=serverAuth"])
    key.chmod(0o600)
    return key,cert

@contextmanager
def verified_pg_tls(root_dsn):
    need(os.getenv("GITHUB_ACTIONS")=="true"
        and os.getenv("JW_PG_CI_ALLOW")=="ONLY_EPHEMERAL_LOCAL_DATABASE"
        and os.getenv("NARUV_ERP_RESTORE_ALLOW")=="TWO_DISPOSABLE_SERVICES_ONLY","NARUV_PG_TLS_SCOPE")
    opts=conninfo_to_dict(root_dsn)
    need(opts.get("host")=="127.0.0.1" and opts.get("port")=="5432"
        and opts.get("dbname")=="postgres" and opts.get("user")=="postgres"
        and opts.get("password")=="ci-only-ephemeral-test-password","NARUV_PG_TLS_DSN")
    cid=os.getenv("NARUV_ERP_SOURCE_SERVICE","")
    need(cid!=os.getenv("NARUV_ERP_DEST_SERVICE"),"NARUV_PG_TLS_SAME_SERVICE")
    docker_guard(cid,5432,"ci-only-ephemeral-test-password")
    admin_dsn=make_conninfo(root_dsn,sslmode="disable",gssencmode="disable")
    with tempfile.TemporaryDirectory(prefix="naruv-pg-tls-") as directory:
        path=Path(directory);key,cert=cert_pair(path,"trusted");_,wrong=cert_pair(path,"untrusted")
        with psycopg.connect(admin_dsn,autocommit=True) as admin:
            cluster=identity(admin)
            # Prove the container and loopback SQL connection are the same cluster.
            observed=command(["docker","exec",cid,"psql","-U","postgres","-d","postgres","-Atc",
                "SELECT system_identifier::text FROM pg_control_system()"]).decode().strip()
            need(cluster==observed,"NARUV_PG_TLS_CLUSTER_MISMATCH")
            need(admin.execute("SHOW ssl").fetchone()==("off",),"NARUV_PG_TLS_ALREADY_ENABLED")
            settings=("ssl","ssl_cert_file","ssl_key_file")
            need(admin.execute("""SELECT count(*) FROM pg_file_settings
                WHERE name=ANY(%s) AND sourcefile LIKE '%%/postgresql.auto.conf'""",(list(settings),)).fetchone()==(0,),
                "NARUV_PG_TLS_EXISTING_OVERRIDE")
            target=command(["docker","exec","-u","postgres",cid,"mktemp","-d","/tmp/naruv-ci-tls.XXXXXXXX"]).decode().strip()
            import re
            need(re.fullmatch(r"/tmp/naruv-ci-tls\.[A-Za-z0-9]{8}",target) is not None,"NARUV_PG_TLS_TMP_PATH")
            changed=[]
            try:
                for name,data in (("server.key",key.read_bytes()),("server.crt",cert.read_bytes())):
                    command(["docker","exec","-i","-u","postgres",cid,"sh","-c",
                        'umask 077; cat > "$1"',"sh",target+"/"+name],data=data)
                for name,value in (("ssl_cert_file",target+"/server.crt"),("ssl_key_file",target+"/server.key"),("ssl","on")):
                    admin.execute(sql.SQL("ALTER SYSTEM SET {} TO {}").format(sql.Identifier(name),sql.Literal(value)))
                    changed.append(name)
                need(admin.execute("SELECT pg_reload_conf()").fetchone()==(True,),"NARUV_PG_TLS_RELOAD")
                for _ in range(30):
                    try:
                        with psycopg.connect(root_dsn,sslmode="verify-full",sslrootcert=str(cert),
                            gssencmode="disable",connect_timeout=2) as probe:
                            need(identity(probe)==cluster,"NARUV_PG_TLS_IDENTITY")
                            need(probe.execute("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()").fetchone()==(True,),
                                "NARUV_PG_TLS_NOT_NEGOTIATED")
                        break
                    except psycopg.OperationalError:time.sleep(.2)
                else:raise RuntimeError("NARUV_PG_TLS_STARTUP")
                yield cert,wrong
            finally:
                for name in reversed(changed):
                    admin.execute(sql.SQL("ALTER SYSTEM RESET {}").format(sql.Identifier(name)))
                if changed:
                    need(admin.execute("SELECT pg_reload_conf()").fetchone()==(True,),"NARUV_PG_TLS_RESET_RELOAD")
                    for _ in range(30):
                        with psycopg.connect(admin_dsn) as probe:
                            if probe.execute("SHOW ssl").fetchone()==("off",):break
                        time.sleep(.2)
                    else:raise RuntimeError("NARUV_PG_TLS_RESET_FAILED")
                command(["docker","exec","-u","postgres",cid,"rm","-f",target+"/server.key",target+"/server.crt"])
                command(["docker","exec","-u","postgres",cid,"rmdir",target])
    print("NARUV_PG_TLS_FIXTURE_CLEANUP_PASS settings restored and temporary certs removed",flush=True)
