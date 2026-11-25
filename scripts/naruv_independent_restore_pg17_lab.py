"""Restore a synthetic schema to a second independent disposable PG17 cluster.

No production, external storage, real credentials or cluster-wide role dump.
Reconstruct only the explicitly specified synthetic roles, with fresh fixture
passwords. Separate cluster identifier and exact service guards are mandatory.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

import psycopg

from scripts.naruv_recovery_pg17_lab import guarded_container, db_identity, CID
from scripts.naruv_backup_restore_pg17_lab import (
    snapshot, dump_archive, verify_archive, SOURCE_DB, need,
)
from scripts.naruv_approval_pg17_lab import actor, inspect
from scripts.naruv_atomic_fixture_pg17_lab import AtomicFixtureTests,commit_fixture,receipt

DEST=os.environ.get("NARUV_INDEPENDENT_SERVICE_ID","")
DB="naruv_independent_ci"
PORT=5433
ROLES=("naruv_lab_owner","naruv_lab_a","naruv_lab_b")

def destination_guard():
    need(os.environ.get("NARUV_INDEPENDENT_ALLOW")=="ONLY_TWO_DISPOSABLE_CI_SERVICES"
        and os.environ.get("GITHUB_ACTIONS")=="true","INDEPENDENT_SCOPE")
    guarded_container(running=True)
    need(re.fullmatch(r"[a-f0-9]{64}",DEST) is not None and DEST!=CID,
         "INDEPENDENT_SERVICE_ID")
    rows=json.loads(subprocess.run(["docker","inspect",DEST],check=True,
                    capture_output=True,text=True,timeout=10).stdout)
    need(type(rows) is list and len(rows)==1,"INDEPENDENT_CONTAINER_LOOKUP")
    c=rows[0]
    env=dict(s.split("=",1) for s in c["Config"].get("Env",[]) if "=" in s)
    need(c["Id"]==DEST and c["Config"]["Image"]=="postgres:17"
         and c["State"]["Running"] is True
         and env.get("POSTGRES_DB")==DB
         and env.get("POSTGRES_USER")=="postgres"
         and env.get("POSTGRES_PASSWORD")=="naruv-independent-root-fixture",
         "INDEPENDENT_WRONG_CONTAINER")
    bindings=c["HostConfig"]["PortBindings"].get("5432/tcp",[])
    need(any(b.get("HostPort")==str(PORT) for b in bindings),"INDEPENDENT_PORT")
    # Different mounts as well as different PostgreSQL system IDs.
    src=guarded_container(running=True)
    mounts=lambda v:{m["Source"] for m in v.get("Mounts",[]) if m.get("Source")}
    need(not mounts(src).intersection(mounts(c)),"INDEPENDENT_SHARED_STORAGE")

def dest_connect(org=None):
    destination_guard()
    need(org in (None,"org-a","org-b"),"INDEPENDENT_ROLE")
    suffix={"org-a":"a","org-b":"b"}.get(org)
    user,pw=("postgres","naruv-independent-root-fixture") if org is None else (
        "naruv_lab_"+suffix,"naruv-independent-"+suffix+"-fixture")
    c=psycopg.connect(dbname=DB,user=user,password=pw,host="127.0.0.1",port=PORT,
        connect_timeout=5,options="-c statement_timeout=5000 -c lock_timeout=4000")
    try:
        actual,version,login=c.execute("SELECT current_database(),current_setting('server_version_num')::int,session_user").fetchone()
        need((actual,login)==(DB,user) and 170000<=version<180000,"INDEPENDENT_DB_IDENTITY")
        c.rollback()
        return c
    except BaseException:
        c.close()
        raise

def provision_roles():
    with dest_connect() as c:
        need(c.execute("SELECT to_regnamespace('naruv_approval_lab')").fetchone()[0] is None,
             "INDEPENDENT_SCHEMA_EXISTS")
        need(c.execute("SELECT count(*) FROM pg_roles WHERE rolname=ANY(%s)",(list(ROLES),)).fetchone()[0]==0,
             "INDEPENDENT_ROLES_EXIST")
        c.execute("""CREATE ROLE naruv_lab_owner NOLOGIN NOSUPERUSER NOBYPASSRLS;
          CREATE ROLE naruv_lab_a LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'naruv-independent-a-fixture';
          CREATE ROLE naruv_lab_b LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'naruv-independent-b-fixture'""")

def role_proof():
    with dest_connect() as c:
        rows=c.execute("""SELECT rolname,rolcanlogin,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,
                rolreplication,rolpassword IS NULL FROM pg_authid WHERE rolname=ANY(%s)
                ORDER BY rolname""",(list(ROLES),)).fetchall()
        need(rows==[("naruv_lab_a",True,False,False,False,False,False,False),
                   ("naruv_lab_b",True,False,False,False,False,False,False),
                   ("naruv_lab_owner",False,False,False,False,False,False,True)],
             "INDEPENDENT_ROLE_ATTRIBUTES")
        count=c.execute("""SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid
             JOIN pg_roles u ON u.oid=m.member WHERE r.rolname=ANY(%s) OR u.rolname=ANY(%s)""",
             (list(ROLES),list(ROLES))).fetchone()[0]
        need(count==0,"INDEPENDENT_ROLE_MEMBERSHIP")

def exact_state():
    # Reuse the previous catalog/data comparator without changing its trusted
    # fixed source connector. Explicitly inject only our guarded destination.
    from scripts import naruv_backup_restore_pg17_lab as prior
    original=prior.connect
    def connector(db,org=None):
        need(db==DB,"INDEPENDENT_SNAPSHOT_SCOPE")
        return dest_connect(org)
    prior.connect=connector
    try:return prior.snapshot(DB)
    finally:prior.connect=original

def reject(org,reason,fn):
    with dest_connect(org) as c:
        try:fn(c)
        except psycopg.Error as exc:
            need(reason in (exc.diag.message_primary or ""),"INDEPENDENT_WRONG_REJECTION")
            c.rollback()
        else:raise RuntimeError("INDEPENDENT_EXPECTED_REJECTION")

def main():
    start=time.monotonic()
    destination_guard()
    source_id,_=db_identity()
    with dest_connect() as c:
        dest_id=c.execute("SELECT system_identifier::text FROM pg_control_system()").fetchone()[0]
        need(source_id!=dest_id,"INDEPENDENT_CLUSTER_ID_MATCH")
    print("NARUV_INDEPENDENT_DISTINCT_CLUSTERS_PASS")
    AtomicFixtureTests.setUpClass()
    f=AtomicFixtureTests("test_commit_and_receipt_after_reconnect")
    f.setUp()
    target=f.stage("org-a")
    f.stage("org-b")
    with actor("org-a") as c:need(commit_fixture(c)=="FIXTURE_COMMITTED","INDEPENDENT_SOURCE_COMMIT")
    before=snapshot(SOURCE_DB)
    with tempfile.TemporaryDirectory(prefix="naruv-independent-") as tmp:
        archive=Path(tmp)/"fixture.dump"
        sha=dump_archive(archive)
        need(snapshot(SOURCE_DB)==before,"INDEPENDENT_SOURCE_CHANGED")
        provision_roles()
        role_proof()
        destination_guard()
        verify_archive(archive,sha)
        with archive.open("rb") as inp:
            p=subprocess.run(["docker","exec","-i",DEST,"pg_restore","-U","postgres","-d",DB,
                  "--exit-on-error","--single-transaction","--no-password"],
                  stdin=inp,capture_output=True,timeout=30)
        need(p.returncode==0,"INDEPENDENT_RESTORE_FAILED")
        verify_archive(archive,sha)
        need(exact_state()==before,"INDEPENDENT_DATA_SCHEMA_MISMATCH")
        role_proof()
        print("NARUV_INDEPENDENT_DATA_SCHEMA_ROLES_PASS")
        # A restored pending approval is deliberately never executed. Treat
        # destination as isolated evidence only, not an active primary.
        with dest_connect("org-a") as c:
            need(inspect(c,"org-a")==("RESERVED","request-1",False),"INDEPENDENT_APPROVAL")
            need(receipt(c)==("FIXTURE_COMMITTED",2,False),"INDEPENDENT_RECEIPT")
        with dest_connect("org-b") as c:
            need(inspect(c,"org-b")==("APPROVED",None,False),"INDEPENDENT_PENDING")
            need(receipt(c,"org-b") is None,"INDEPENDENT_PENDING_RECEIPT")
        reject("org-a","APPROVAL_TARGET_CHANGED",commit_fixture)
        reject("org-b","FIXTURE_SCOPE",lambda c:receipt(c,"org-a"))
        reject("org-a","permission denied",lambda c:c.execute("DELETE FROM naruv_approval_lab.fixture_items"))
        reject("org-a","permission denied",lambda c:c.execute("SET ROLE naruv_lab_owner"))
        with dest_connect() as c:
            need(c.execute("SELECT organization_id,source_item_id,name FROM naruv_approval_lab.fixture_items ORDER BY organization_id,source_item_id").fetchall()
              ==[("org-a","001","품목 A"),("org-a","002","품목 B")],"INDEPENDENT_ROW_VALUES")
            need(c.execute("SELECT snapshot_sha256 FROM naruv_approval_lab.targets WHERE organization_id='org-a'").fetchone()[0]
              ==target.snapshot_sha256,"INDEPENDENT_TARGET")
        need(snapshot(SOURCE_DB)==before,"INDEPENDENT_RESTORE_TOUCHED_SOURCE")
        verify_archive(archive,sha)
        print("NARUV_INDEPENDENT_REPLAY_SCOPE_SOURCE_UNCHANGED_PASS")
        print("NARUV_INDEPENDENT_PG17_PASS", "archive_bytes="+str(archive.stat().st_size),
              "sha256="+sha,"elapsed_ms="+str(int((time.monotonic()-start)*1000)),
              "independent_clusters=true synthetic_roles_reprovisioned=true production_import_authorized=false")
if __name__=="__main__":
    main()
