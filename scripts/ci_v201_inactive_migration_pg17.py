"""V20.1: true PostgreSQL17 NOLOGIN migration/rollback + independent RLS and HMAC.

Disposable GitHub Actions postgres:17 only. No hosted database, no credentials,
no customer documents, no Render, no real migration or deployment.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
import psycopg
from psycopg import sql
from scripts import ci_v195_atomic_approval_receipt_https as upstream
from scripts import ci_v157_real_pg_delivery_http as fixture

ROOT=Path(__file__).resolve().parents[1]
MIG=ROOT/"scripts/review/v201_proposed_dev_no_login_migration.sql"
DOWN=ROOT/"scripts/review/v201_proposed_dev_no_login_rollback.sql"
WRITER="jw_dev_import_writer_v201"
REVIEWER="jw_dev_import_review_executor_v201"
OWNER="jw_dev_import_approval_owner_v201"
ORGA="a"*32
ORG_B="b"*32
ACTOR_A="1"*32
PID="6"*32
DIGEST="5"*64
SHA="3"*64
SQL_WRITE="""INSERT INTO jw_dev.import_previews
(id,org_id,uploaded_by,file_sha256,filename,normalized_json,
 preview_digest,status,created_at)
VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
DEFAULT=[PID,ORGA,ACTOR_A,SHA,"source.xlsx","synthetic-sealed-body",DIGEST,
         "pending","2026-11-01T01:00:00+00:00"]
PASS_COUNT=0

def pass_case(label: str):
    global PASS_COUNT
    PASS_COUNT+=1
    print("PASS_V201_"+label,flush=True)

def check_as(role: str, actor: str, statement: str, args=(), accepted=False):
    with psycopg.connect(fixture.DSN) as conn:
        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        conn.execute("SELECT pg_catalog.set_config('jw.session_hash',%s,true)",
            (hashlib.sha256(fixture.TOKENS[actor].encode()).hexdigest()
               if actor in fixture.TOKENS else "bogus" * 12,))
        try:
            if statement.lstrip().upper().startswith("SELECT"):
                row=conn.execute(statement,args).fetchone()
            else:
                conn.execute(statement,args)
                row=None
        except psycopg.Error:
            if accepted:
                raise
            return False
        if not accepted:
            raise AssertionError(("V201_UNEXPECTED_ALLOW",role,actor,statement[:70]))
        return row

def root(statement: str,args=()):
    with psycopg.connect(fixture.DSN) as conn:
        return conn.execute(statement,args).fetchall() if statement.lstrip().upper().startswith("SELECT") else conn.execute(statement,args)

def main():
    if os.getenv("JW_ENV")!="review" or os.getenv("JW_PG_CI_ALLOW")!="ONLY_EPHEMERAL_LOCAL_DATABASE":
        raise RuntimeError("BLOCKED_V201_ONLY_ISOLATED_REVIEW")
    fixture.disposable_root_check()
    upstream.prepare()
    # Reproduce the verified 12-column DEV shape on the original real PG17 fixture.
    with psycopg.connect(fixture.DSN) as conn:
        conn.execute("""CREATE ROLE jw_ci_v199_import_writer
             NOLOGIN NOINHERIT NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE""")
        conn.execute((ROOT/"scripts/review/v199_disposable_actual_shape_import_writer.sql").read_text())
        conn.execute("CREATE SCHEMA extensions")
        conn.execute("ALTER EXTENSION pgcrypto SET SCHEMA extensions")
        # Existing synthetic import records are throwaway fixture data only.
        # Preserve customer/order/quote fixture and verify an EMPTY import table.
        conn.execute("DELETE FROM jw_dev.import_previews")
        assert conn.execute("SELECT count(*) FROM jw_dev.import_previews").fetchone()==(0,)
    root(MIG.read_text())
    roles=root("""SELECT rolname,rolcanlogin,rolsuper,rolbypassrls,rolinherit
       FROM pg_roles WHERE rolname IN (%s,%s,%s) ORDER BY rolname""",
       (WRITER,REVIEWER,OWNER))
    assert len(roles)==3 and all(row[1:]==(False,False,False,False) for row in roles),roles
    pass_case("THREE_NOLOGIN_NOBYPASSRLS_ROLES")
    assert root("SELECT count(*) FROM jw_dev.v201_approval_secrets")==[(0,)]
    assert root("SELECT count(*) FROM jw_dev.v201_approval_receipts")==[(0,)]
    pass_case("NO_APPROVAL_KEY_ENROLLED")
    assert root("""SELECT count(*) FROM pg_auth_members WHERE
       member IN (SELECT oid FROM pg_roles WHERE rolname IN (%s,%s,%s))""",
       (WRITER,REVIEWER,OWNER))==[(0,)]
    pass_case("ZERO_ROLE_MEMBERSHIPS")
    assert root("""SELECT has_table_privilege('jw_app_dev',
        'jw_dev.import_previews','INSERT'),
        has_table_privilege('jw_app_dev','jw_dev.import_previews','UPDATE'),
        has_table_privilege('anon','jw_dev.import_previews','INSERT'),
        has_table_privilege('authenticated','jw_dev.import_previews','INSERT')""")==[(False,False,False,False)]
    pass_case("EXISTING_PROTECTED_CLIENTS_NOT_WIDENED")
    # Prove successful rollback on empty previews; no dummy credentials needed.
    root(DOWN.read_text())
    assert root("""SELECT count(*) FROM pg_roles WHERE rolname IN(%s,%s,%s)""",
                (WRITER,REVIEWER,OWNER))==[(0,)]
    assert root("SELECT to_regclass('jw_dev.v201_approval_receipts')")==[(None,)]
    pass_case("EMPTY_CANDIDATE_ROLLBACK_AND_REMOVAL")
    root(MIG.read_text())
    pass_case("REAPPLY_ON_CLEAN_DISPOSABLE_PG17")
    assert check_as(WRITER,"bogus",SQL_WRITE,DEFAULT) is False
    pass_case("MISSING_SESSION_DENIED")
    assert check_as(WRITER,"B",SQL_WRITE,DEFAULT) is False
    pass_case("TENANT_B_FORGED_ORG_DENIED")
    bad=list(DEFAULT);bad[2]="2"*32
    assert check_as(WRITER,"A",SQL_WRITE,bad) is False
    pass_case("FORGED_ACTOR_DENIED")
    for i,field in enumerate([0,3,6]):
        bad=list(DEFAULT);bad[field]="x"*(32 if i==0 else 64)
        assert check_as(WRITER,"A",SQL_WRITE,bad) is False
    pass_case("MALFORMED_ID_SHA_AND_DIGEST_DENIED")
    for name in ("../evil.xlsx","x\\evil.xlsx","evil.exe","x"):
        bad=list(DEFAULT);bad[4]=name
        assert check_as(WRITER,"A",SQL_WRITE,bad) is False
    pass_case("FOUR_UNSAFE_FILENAMES_DENIED")
    for status in ("confirmed","rejected",""):
        bad=list(DEFAULT);bad[7]=status
        assert check_as(WRITER,"A",SQL_WRITE,bad) is False
    pass_case("INVALID_INSERT_STATUSES_DENIED")
    assert check_as(WRITER,"A",SQL_WRITE,DEFAULT,True) is None
    pass_case("DB_VERIFIED_SESSION_CAN_INSERT_PENDING")
    repeated=list(DEFAULT);repeated[0]="7"*32
    assert check_as(WRITER,"A",SQL_WRITE,repeated) is False
    pass_case("PENDING_FILE_CONFLICT_DENIED")
    assert check_as(WRITER,"A","UPDATE jw_dev.import_previews SET status='confirmed' WHERE id=%s",(PID,)) is False
    pass_case("WRITER_STATUS_UPDATE_DENIED")
    assert check_as(WRITER,"A","SELECT normalized_json FROM jw_dev.import_previews WHERE id=%s",(PID,)) is False
    pass_case("WRITER_SEALED_DATA_READ_DENIED")
    assert check_as(REVIEWER,"A","SELECT secret FROM jw_dev.v201_approval_secrets") is False
    assert check_as(WRITER,"A","SELECT secret FROM jw_dev.v201_approval_secrets") is False
    pass_case("KEY_NEVER_READABLE_BY_WRITER_OR_REVIEWER")
    assert check_as(REVIEWER,"A","UPDATE jw_dev.import_previews SET status='confirmed' WHERE id=%s",(PID,)) is False
    pass_case("REVIEWER_DIRECT_UPDATE_DENIED")
    facts={"schema":"jw-import-approval-v195","preview_id":PID,"org_id":ORGA,
      "actor_id":ACTOR_A,"preview_digest":DIGEST,"approved":True,
      "company":"Customer A","quote_date":"2026-11-01","total_krw":176000}
    stmt=json.dumps(facts,sort_keys=True,separators=(",",":"),ensure_ascii=False)
    key=secrets.token_bytes(32)
    signature=hmac.new(key,stmt.encode(),hashlib.sha256).hexdigest()
    fn="SELECT jw_dev.v201_confirm_import(%s,%s,%s,%s,%s,%s,%s)"
    req=(PID,ORGA,ACTOR_A,DIGEST,stmt,signature,"8"*32)
    assert check_as(REVIEWER,"A",fn,req) is False
    pass_case("NO_KEY_MEANS_APPROVAL_BLOCKED")
    with psycopg.connect(fixture.DSN) as conn:
        # Synthetic temporary CI key; deliberately NEVER in migration or logs.
        conn.execute("INSERT INTO jw_dev.v201_approval_secrets(name,secret) VALUES('active',%s)",(key,))
    for n in range(20):
        altered=list(req)
        altered[5]=f"{n:064x}"
        assert check_as(REVIEWER,"A",fn,altered) is False
    pass_case("TWENTY_INVALID_HMAC_DENIED")
    assert check_as(REVIEWER,"B",fn,req) is False
    pass_case("REVIEWER_TENANT_B_DENIED")
    assert check_as(REVIEWER,"bogus",fn,req) is False
    pass_case("REVIEWER_UNKNOWN_SESSION_DENIED")
    altered=list(req);altered[1]=ORG_B
    assert check_as(REVIEWER,"A",fn,altered) is False
    pass_case("REVIEWER_FORGED_ORG_DENIED")
    altered=list(req);altered[3]="f"*64
    assert check_as(REVIEWER,"A",fn,altered) is False
    pass_case("REVIEWER_CHANGED_DIGEST_DENIED")
    assert check_as(REVIEWER,"A",fn,req,True)==("8"*32,)
    pass_case("HMAC_APPROVAL_ATOMICALLY_SUCCEEDS")
    assert root("""SELECT status FROM jw_dev.import_previews WHERE id=%s""",(PID,))==[("confirmed",)]
    assert root("""SELECT id,preview_id FROM jw_dev.v201_approval_receipts""")==[("8"*32,PID)]
    pass_case("APPROVAL_AND_AUDIT_ARE_ATOMIC")
    assert check_as(REVIEWER,"A",fn,req) is False
    pass_case("DUPLICATE_APPROVAL_DENIED")
    try:
        root("UPDATE jw_dev.v201_approval_receipts SET signature=%s WHERE id=%s",("0"*64,"8"*32))
    except psycopg.Error:
        pass
    else:
        raise AssertionError("AUDIT_MUTATION_PERMITTED")
    pass_case("RECEIPT_IMMUTABILITY_TRIGGER")
    try:
        root(DOWN.read_text())
    except psycopg.Error:
        pass
    else:
        raise AssertionError("DATA_BEARING_ROLLBACK_PERMITTED")
    pass_case("DATA_BEARING_ROLLBACK_BLOCKED")
    assert root("SELECT count(*) FROM jw_dev.v201_approval_receipts")==[(1,)]
    assert root("SELECT status FROM jw_dev.import_previews WHERE id=%s",(PID,))==[("confirmed",)]
    pass_case("FAILED_ROLLBACK_PRESERVES_BUSINESS_AND_AUDIT")
    assert root("""SELECT rolcanlogin,rolsuper,rolbypassrls
       FROM pg_roles WHERE rolname=%s""",(OWNER,))==[(False,False,False)]
    pass_case("SECURITY_DEFINER_OWNER_REMAINS_NONPRIVILEGED")
    print(f"PASS_V201_REAL_PG17_INACTIVE_DEV_MIGRATION {PASS_COUNT} scoped test groups, "
          "20 HMAC forgeries, no real DEV or customer changes",flush=True)

if __name__=="__main__":
    main()
