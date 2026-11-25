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

def validate_archive(archive,digest):
    need(type(archive) is bytes and 0<len(archive)<=1024*1024 and type(digest) is str
        and len(digest)==64 and hashlib.sha256(archive).hexdigest()==digest,"PROFILE_RESTORE_ARCHIVE_CHANGED")

def verify_after_purge(source,captured,new_key,old_key,expected_profile):
    _,dst=boundary(source)
    archive,digest,before=captured
    validate_archive(archive,digest)
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
            verify_single_use_attestations(dsn,digest)
            need(hashlib.sha256(archive).hexdigest()==digest,"PROFILE_RESTORE_ARCHIVE_CHANGED")
        finally:
            if created:admin.execute("DROP DATABASE naruv_profile_quarantine_ci")
    print("NARUV_HR_ARCHIVE_QUARANTINE_PASS independent PG17 data-only restore, new-key recovery, old-key/tenant denial, current purge reconciliation; no release",flush=True)


def verify_single_use_attestations(dsn,archive_digest):
    from datetime import datetime,timezone
    from concurrent.futures import ThreadPoolExecutor
    import secrets
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    from app.naruv_hr_profile_envelope import (_canonical,key_retirement_review,
        retirement_inventory_digest,consume_retirement_attestation_ci)
    opts=conninfo_to_dict(dsn)
    need(opts.get("host")=="127.0.0.1" and opts.get("port")=="5433" and opts.get("dbname")==DB,
        "RETIREMENT_LEDGER_SCOPE")
    scope=dict(tenant="ci-a",old_key_id="ci-profile-key",new_key_id="ci-profile-key-2",
               expected_assets=["verified-quarantine-archive"])
    inventory=retirement_inventory_digest(**scope)
    review=key_retirement_review(**scope,inventory_sha256=inventory,observations=[
        dict(asset="verified-quarantine-archive",tenant="ci-a",key_id="ci-profile-key-2",
             restore_sha256=archive_digest,old_key_denied=True)])
    now=datetime.now(timezone.utc);challenge=secrets.token_hex(32)
    a,b=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    msg=_canonical(["NARUV_RETIREMENT_ATTESTATION_V1",inventory,review["review_sha256"],challenge,now.isoformat()])
    args=dict(review=review,inventory_sha256=inventory,challenge=challenge,issued_at=now,as_of=now,
        inventory_public_key=a.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw),
        recovery_public_key=b.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw),
        inventory_signature=a.sign(b"inventory:"+msg),recovery_signature=b.sign(b"recovery:"+msg))
    with psycopg.connect(dsn) as db:
        db.execute("""CREATE SCHEMA naruv_retirement_ci;
          REVOKE ALL ON SCHEMA naruv_retirement_ci FROM PUBLIC;
          CREATE TABLE naruv_retirement_ci.challenge(
          challenge text PRIMARY KEY,inventory_sha256 text NOT NULL,review_sha256 text NOT NULL,
          issued_at timestamptz NOT NULL,consumed_at timestamptz);
          REVOKE ALL ON ALL TABLES IN SCHEMA naruv_retirement_ci FROM PUBLIC""")
        db.execute("INSERT INTO naruv_retirement_ci.challenge VALUES(%s,%s,%s,%s,NULL)",
            (challenge,inventory,review["review_sha256"],now))
    def attempt():
        with psycopg.connect(dsn) as db:
            with db.cursor() as cur:
                try:r=consume_retirement_attestation_ci(cur,**args)
                except ProfileBlocked:return False
                need(r["key_retirement_authorized"] is False,"RETIREMENT_UNEXPECTED_AUTHORIZATION")
                return True
    # Failed signature and rolled-back consumption must leave the challenge available.
    with psycopg.connect(dsn) as db:
        with db.cursor() as cur:
            try:consume_retirement_attestation_ci(cur,**dict(args,recovery_signature=b"x"*64))
            except ProfileBlocked:pass
            else:raise RuntimeError("RETIREMENT_TAMPER_ACCEPTED")
        need(db.execute("SELECT consumed_at IS NULL FROM naruv_retirement_ci.challenge").fetchone()==(True,),
             "RETIREMENT_INVALID_SIGNATURE_MUTATED")
    with psycopg.connect(dsn) as db:
        with db.cursor() as cur:consume_retirement_attestation_ci(cur,**args)
        db.rollback()
        need(db.execute("SELECT consumed_at IS NULL FROM naruv_retirement_ci.challenge").fetchone()==(True,),
             "RETIREMENT_ROLLBACK_LOST_CHALLENGE")
    # An expired signed challenge cannot be accepted by supplying an old
    # application-side as_of time; the database independently checks its clock.
    from datetime import timedelta
    expired=now-timedelta(minutes=11)
    expired_challenge=secrets.token_hex(32)
    expired_msg=_canonical(["NARUV_RETIREMENT_ATTESTATION_V1",inventory,review["review_sha256"],expired_challenge,expired.isoformat()])
    expired_args=dict(args,challenge=expired_challenge,issued_at=expired,as_of=expired,
        inventory_signature=a.sign(b"inventory:"+expired_msg),recovery_signature=b.sign(b"recovery:"+expired_msg))
    with psycopg.connect(dsn) as db:
        db.execute("INSERT INTO naruv_retirement_ci.challenge VALUES(%s,%s,%s,%s,NULL)",
                   (expired_challenge,inventory,review["review_sha256"],expired))
        with db.cursor() as cur:
            try:consume_retirement_attestation_ci(cur,**expired_args)
            except ProfileBlocked:pass
            else:raise RuntimeError("RETIREMENT_EXPIRED_REPLAY_ACCEPTED")
        need(db.execute("SELECT consumed_at IS NULL FROM naruv_retirement_ci.challenge WHERE challenge=%s",
                       (expired_challenge,)).fetchone()==(True,),"RETIREMENT_EXPIRED_MUTATED")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:attempt(),range(2)))
    need(sorted(results)==[False,True] and not attempt(),"RETIREMENT_REPLAY_ACCEPTED")
    with psycopg.connect(dsn) as db:
        need(db.execute("SELECT count(*) FROM naruv_retirement_ci.challenge WHERE consumed_at IS NOT NULL").fetchone()==(1,),
             "RETIREMENT_LEDGER_INCOMPLETE")
        need(db.execute("SELECT consumed_at>=issued_at AND consumed_at<=clock_timestamp() FROM naruv_retirement_ci.challenge WHERE challenge=%s",(challenge,)).fetchone()==(True,),
             "RETIREMENT_LEDGER_CLOCK_MISMATCH")
    print("NARUV_RETIREMENT_SINGLE_USE_CI_PASS independent signed verified archive evidence, atomic replay refusal, no retirement",flush=True)
