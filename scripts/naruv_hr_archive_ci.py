"""Offline data-only HR archive acceptance on two disposable PG17 services.

Separate from full ERP restore. No real PII, key-store change or backup upload.
The restored tables are intentionally quarantine tables, not live HR schema.
The old archive remains immutable; a trusted newer purge record must be
reconciled before any hypothetical release. No release path is implemented.
"""
import hashlib
import os
import subprocess
import psycopg
from psycopg.conninfo import conninfo_to_dict,make_conninfo
from scripts.naruv_erp_restore_ci import DEST_DSN,docker_guard,identity,need
from app.naruv_hr_profile_envelope import open_profile,ProfileBlocked

TABLES=("profile_envelopes","profile_revision_history","profile_retention")
DB="naruv_profile_quarantine_ci"

def boundary(source):
    opts=conninfo_to_dict(source)
    need(os.getenv("GITHUB_ACTIONS")=="true" and os.getenv("JW_PG_CI_ALLOW")=="ONLY_EPHEMERAL_LOCAL_DATABASE"
        and os.getenv("NARUV_ERP_RESTORE_ALLOW")=="TWO_DISPOSABLE_SERVICES_ONLY","PROFILE_RESTORE_SCOPE")
    need((opts.get("host"),opts.get("port"),opts.get("dbname"),opts.get("user"),opts.get("password"))==
        ("127.0.0.1","5432","postgres","postgres","ci-only-ephemeral-test-password"),"PROFILE_RESTORE_SOURCE")
    src=os.getenv("NARUV_ERP_SOURCE_SERVICE","");dst=os.getenv("NARUV_ERP_DEST_SERVICE","")
    need(src!=dst and not docker_guard(src,5432,"ci-only-ephemeral-test-password").intersection(
        docker_guard(dst,5433,"naruv-erp-restore-ci-only")),"PROFILE_RESTORE_SERVICE_BOUNDARY")
    with psycopg.connect(source) as a,psycopg.connect(DEST_DSN) as b:
        need(identity(a)!=identity(b),"PROFILE_RESTORE_SAME_CLUSTER")
        need(b.execute("SELECT to_regnamespace('jw_dev') IS NULL AND to_regnamespace('naruv_draft') IS NULL").fetchone()==(True,),
            "PROFILE_RESTORE_DEST_NOT_EMPTY")
    return src,dst

def command(args,data=None):
    p=subprocess.run(args,input=data,capture_output=True,timeout=30)
    need(p.returncode==0,"PROFILE_RESTORE_TOOL_FAILED")
    return p.stdout

def snapshot(db):
    result=[]
    for table in TABLES:
        # Fixed internal table names, no external interpolation.
        h=hashlib.sha256();count=0
        for (row,) in db.execute("SELECT to_jsonb(x)::text FROM naruv_draft."+table+" x ORDER BY to_jsonb(x)::text COLLATE \"C\""):
            value=row.encode();h.update(len(value).to_bytes(8,"big"));h.update(value);count+=1
        result.append((table,count,h.hexdigest()))
    return tuple(result)

def capture(source):
    src,_=boundary(source)
    with psycopg.connect(source) as db:
        before=snapshot(db)
        row=db.execute("SELECT org_id,worker_id,revision,envelope FROM naruv_draft.profile_envelopes").fetchall()
        need(len(row)==1 and row[0][:3]==("ci-a","worker-1","r3") and row[0][3]["key_id"]=="ci-profile-key-2",
            "PROFILE_RESTORE_EXPECTED_ROTATION")
    archive=command(["docker","exec",src,"pg_dump","-U","postgres","-d","postgres","-Fc","--data-only","--no-password",
        *["--table=naruv_draft."+table for table in TABLES]])
    need(0<len(archive)<=1024*1024,"PROFILE_RESTORE_ARCHIVE_LIMIT")
    with psycopg.connect(source) as db:need(snapshot(db)==before,"PROFILE_RESTORE_SOURCE_DRIFT")
    return archive,hashlib.sha256(archive).hexdigest(),before

def verify_after_purge(source,captured,new_key,old_key,expected_profile):
    _,dst=boundary(source)
    archive,digest,before=captured
    need(hashlib.sha256(archive).hexdigest()==digest,"PROFILE_RESTORE_ARCHIVE_CHANGED")
    # The current source is the independent authority, not the old archive.
    with psycopg.connect(source) as a:
        after=snapshot(a)
        tombstones=a.execute("""SELECT org_id,worker_id,eligible_at,legal_hold,approval_sha256,purged_at
          FROM naruv_draft.profile_retention WHERE purged_at IS NOT NULL""").fetchall()
        need(len(tombstones)==1 and tombstones[0][:2]==("ci-a","worker-1") and tombstones[0][3] is False,
            "PROFILE_RESTORE_TOMBSTONE_MISSING")
        need(a.execute("SELECT count(*) FROM naruv_draft.profile_envelopes").fetchone()==(0,),"PROFILE_RESTORE_SOURCE_NOT_PURGED")
    created=False
    with psycopg.connect(DEST_DSN,autocommit=True) as admin:
        need(admin.execute("SELECT count(*) FROM pg_database WHERE datname=%s",(DB,)).fetchone()==(0,),"PROFILE_RESTORE_DB_EXISTS")
        try:
            admin.execute("CREATE DATABASE naruv_profile_quarantine_ci TEMPLATE template0")
            created=True
            dsn=make_conninfo(DEST_DSN,dbname=DB)
            with psycopg.connect(dsn) as b:
                b.execute("REVOKE CONNECT ON DATABASE naruv_profile_quarantine_ci FROM PUBLIC")
                b.execute("CREATE SCHEMA naruv_draft")
                b.execute("REVOKE ALL ON SCHEMA naruv_draft FROM PUBLIC")
                b.execute("""CREATE TABLE naruv_draft.profile_envelopes(
                  org_id text NOT NULL,worker_id text NOT NULL,revision text NOT NULL,actor_id text NOT NULL,
                  envelope jsonb NOT NULL,created_at timestamptz NOT NULL,PRIMARY KEY(org_id,worker_id));
                  CREATE TABLE naruv_draft.profile_revision_history(
                  org_id text NOT NULL,worker_id text NOT NULL,revision text NOT NULL,previous_revision text,
                  actor_id text NOT NULL,recorded_at timestamptz NOT NULL,PRIMARY KEY(org_id,worker_id,revision));
                  CREATE TABLE naruv_draft.profile_retention(
                  org_id text NOT NULL,worker_id text NOT NULL,eligible_at timestamptz NOT NULL,legal_hold boolean NOT NULL,
                  approval_sha256 text NOT NULL,purged_at timestamptz,PRIMARY KEY(org_id,worker_id));
                  REVOKE ALL ON ALL TABLES IN SCHEMA naruv_draft FROM PUBLIC""")
            command(["docker","exec","-i",dst,"pg_restore","-U","postgres","-d",DB,
                "--data-only","--no-owner","--no-acl","--exit-on-error","--single-transaction","--no-password"],archive)
            with psycopg.connect(dsn) as b:
                need(snapshot(b)==before,"PROFILE_RESTORE_DATA_MISMATCH")
                org,worker,revision,envelope=b.execute("SELECT org_id,worker_id,revision,envelope FROM naruv_draft.profile_envelopes").fetchone()
                scope=dict(tenant=org,worker=worker,revision=revision,key_id="ci-profile-key-2",envelope=envelope)
                need(open_profile(**scope,key=new_key)==expected_profile,"PROFILE_RESTORE_DECRYPT_MISMATCH")
                for bad in (dict(scope,key=old_key),dict(scope,tenant="ci-b",key=new_key)):
                    try:open_profile(**bad)
                    except ProfileBlocked:pass
                    else:raise RuntimeError("PROFILE_RESTORE_WRONG_SCOPE_ACCEPTED")
                # Restoring stale archives does not authorize re-exposure.
                # Reconcile trusted source tombstone in the offline quarantine.
                need(b.execute("SELECT count(*) FROM naruv_draft.profile_retention").fetchone()==(0,),"PROFILE_RESTORE_UNEXPECTED_RETENTION")
                b.execute("INSERT INTO naruv_draft.profile_retention VALUES(%s,%s,%s,%s,%s,%s)",tombstones[0])
                n=b.execute("DELETE FROM naruv_draft.profile_envelopes x USING naruv_draft.profile_retention r WHERE (x.org_id,x.worker_id)=(r.org_id,r.worker_id) AND r.purged_at IS NOT NULL").rowcount
                need(n==1 and snapshot(b)==after,"PROFILE_RESTORE_RECONCILIATION_MISMATCH")
            need(hashlib.sha256(archive).hexdigest()==digest,"PROFILE_RESTORE_ARCHIVE_CHANGED")
        finally:
            if created:admin.execute("DROP DATABASE naruv_profile_quarantine_ci")
    print("NARUV_HR_ARCHIVE_QUARANTINE_PASS independent PG17 data-only restore, new-key recovery, old-key/tenant denial, current purge reconciliation; no release",flush=True)
