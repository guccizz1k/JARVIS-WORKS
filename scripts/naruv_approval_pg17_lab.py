"""Real PG17, fixed disposable CI service only. No configurable remote DSN."""
import concurrent.futures
import os
from pathlib import Path
import threading
import time
import unittest

import psycopg

from app.erp_migration_review import prepare_header_review
from app.erp_migration_preflight import make_target_snapshot, prepare_row_preflight

SCHEMA="naruv_approval_lab"
ROOT_DSN="postgresql://postgres:naruv-ci-root-fixture@127.0.0.1:5432/naruv_approval_ci"
SQL=Path(__file__).resolve().parents[1]/"db/review/naruv_approval_pg17_lab.sql"
SOURCE="erp-source-1"
ENTITY="item"
H=("sku","item_name")

def root():
    if os.environ.get("NARUV_APPROVAL_PG_ALLOW")!="ONLY_DISPOSABLE_CI" or os.environ.get("GITHUB_ACTIONS")!="true":
        raise RuntimeError("DISPOSABLE_CI_REQUIRED")
    conn=psycopg.connect(ROOT_DSN,connect_timeout=5)
    with conn.cursor() as cur:
        cur.execute("SELECT current_database(),current_setting('server_version_num')::int,inet_server_addr()::text,session_user")
        db,ver,addr,user=cur.fetchone()
        if db!="naruv_approval_ci" or not 170000<=ver<180000 or user!="postgres":
            conn.close()
            raise RuntimeError("WRONG_PG_ENVIRONMENT")
        cur.execute("SELECT pg_catalog.to_regnamespace('naruv_approval_lab')")
        # Existing schema is expected only after explicit bootstrap by this run.
    conn.rollback()
    return conn

def actor(org):
    suffix={"org-a":"a","org-b":"b"}[org]
    if os.environ.get("NARUV_APPROVAL_PG_ALLOW")!="ONLY_DISPOSABLE_CI" or os.environ.get("GITHUB_ACTIONS")!="true":
        raise RuntimeError("DISPOSABLE_CI_REQUIRED")
    return psycopg.connect(f"postgresql://naruv_lab_{suffix}:naruv-ci-{suffix}-fixture@127.0.0.1:5432/naruv_approval_ci",
                           connect_timeout=5,options="-c statement_timeout=5000 -c lock_timeout=4000")

def fixture(org="org-a",code="001",revision="rev-1"):
    review=prepare_header_review(org,SOURCE,ENTITY,H)
    target=make_target_snapshot(org,SOURCE,ENTITY,revision,())
    p=prepare_row_preflight(review,organization_id=org,source_id=SOURCE,entity=ENTITY,
                            headers=H,rows=((code,"품목"),),target=target)
    return p,target

def issue(c,p,id="approval-1",ttl=60,confirmed=True):
    return c.execute("SELECT naruv_approval_lab.issue(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
          (p.organization_id,id,p.source_id,p.entity,p.binding_sha256,p.rows_sha256,p.target_snapshot_sha256,confirmed,ttl)).fetchone()[0]

def reserve(c,p,id="approval-1",rid="reservation-1"):
    return c.execute("SELECT naruv_approval_lab.reserve(%s,%s,%s,%s,%s,%s,%s,%s)",
          (p.organization_id,id,rid,p.source_id,p.entity,p.binding_sha256,p.rows_sha256,p.target_snapshot_sha256)).fetchone()[0]

def inspect(c,org,id="approval-1"):
    return c.execute("SELECT * FROM naruv_approval_lab.inspect(%s,%s)",(org,id)).fetchone()

class PostgresApprovalLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with root() as c:
            # Abort instead of deleting any existing schema or roles.
            if c.execute("SELECT to_regnamespace('naruv_approval_lab')").fetchone()[0] is not None:
                raise RuntimeError("LAB_SCHEMA_ALREADY_EXISTS")
            c.execute(SQL.read_text(encoding="utf-8"))

    def setUp(self):
        self.p,self.t=fixture()
        self.pb,self.tb=fixture("org-b")
        with root() as c:
            c.execute("DELETE FROM naruv_approval_lab.approvals")
            c.execute("DELETE FROM naruv_approval_lab.targets")
            c.execute("UPDATE naruv_approval_lab.actors SET active=true,can_approve=true,can_reserve=true,permission_revision='perm-1',last_epoch=0")
            for t in (self.t,self.tb):
                c.execute("INSERT INTO naruv_approval_lab.targets VALUES(%s,%s,%s,%s)",
                          (t.organization_id,t.source_id,t.entity,t.snapshot_sha256))

    def reject(self,reason,fn):
        with self.assertRaisesRegex(psycopg.Error,reason):
            fn()

    def test_commit_reconnect_and_replay(self):
        with actor("org-a") as c:self.assertEqual(issue(c,self.p),"APPROVED")
        with actor("org-a") as c:self.assertEqual(issue(c,self.p),"ALREADY_APPROVED")
        with actor("org-a") as c:self.assertEqual(reserve(c,self.p),"RESERVED")
        with actor("org-a") as c:self.assertEqual(inspect(c,"org-a"),("RESERVED","reservation-1",False))
        with actor("org-a") as c:
            self.reject("APPROVAL_TERMINAL",lambda:reserve(c,self.p))
            c.rollback()

    def test_rollback_and_abandoned_connection(self):
        c=actor("org-a")
        self.assertEqual(issue(c,self.p),"APPROVED")
        c.close() # implicit rollback, no committed approval
        with actor("org-a") as c:self.assertIsNone(inspect(c,"org-a"))
        with actor("org-a") as c:issue(c,self.p)
        c=actor("org-a")
        self.assertEqual(reserve(c,self.p),"RESERVED")
        c.rollback()
        c.close()
        with actor("org-a") as c:self.assertEqual(inspect(c,"org-a"),("APPROVED",None,False))
        with actor("org-a") as c:self.assertEqual(reserve(c,self.p),"RESERVED")

    def test_scope_and_database_privileges(self):
        with actor("org-a") as c:issue(c,self.p)
        with actor("org-b") as c:
            self.assertIsNone(inspect(c,"org-b"))
            self.reject("APPROVAL_SCOPE",lambda:inspect(c,"org-a"))
            c.rollback()
            self.reject("permission denied",lambda:c.execute("SELECT * FROM naruv_approval_lab.approvals"))
            c.rollback()
            self.reject("permission denied",lambda:c.execute("UPDATE naruv_approval_lab.approvals SET status='REVOKED'"))
            c.rollback()
            self.reject("permission denied",lambda:c.execute("SELECT naruv_approval_lab.lock_actor('approve')"))
            c.rollback()
            self.reject("permission denied",lambda:c.execute("SET ROLE naruv_lab_owner"))
            c.rollback()
            self.assertEqual(issue(c,self.pb),"APPROVED")
            self.assertEqual(reserve(c,self.pb),"RESERVED")
        with actor("org-a") as c:self.assertEqual(inspect(c,"org-a"),("APPROVED",None,False))

    def test_rls_and_owner_role_catalog(self):
        with root() as c:
            rows=c.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE relnamespace='naruv_approval_lab'::regnamespace AND relkind='r'").fetchall()
            self.assertEqual(rows,[(True,True)]*3)
            roles=c.execute("SELECT rolsuper,rolbypassrls,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname IN ('naruv_lab_owner','naruv_lab_a','naruv_lab_b')").fetchall()
            self.assertEqual(roles,[(False,False,False,False)]*3)

    def test_changed_authority_and_target(self):
        with actor("org-a") as c:issue(c,self.p)
        with root() as c:c.execute("UPDATE naruv_approval_lab.actors SET permission_revision='perm-2' WHERE organization_id='org-a'")
        with actor("org-a") as c:
            self.reject("APPROVAL_ACTOR_CHANGED",lambda:reserve(c,self.p))
            c.rollback()
        with root() as c:
            c.execute("UPDATE naruv_approval_lab.actors SET permission_revision='perm-1',can_reserve=false WHERE organization_id='org-a'")
        with actor("org-a") as c:
            self.reject("APPROVAL_PERMISSION_DENIED",lambda:reserve(c,self.p))
            c.rollback()
        with root() as c:
            c.execute("UPDATE naruv_approval_lab.actors SET can_reserve=true WHERE organization_id='org-a'")
            c.execute("UPDATE naruv_approval_lab.targets SET snapshot_sha256=%s WHERE organization_id='org-a'",("f"*64,))
        with actor("org-a") as c:
            self.reject("APPROVAL_TARGET_CHANGED",lambda:reserve(c,self.p))
            c.rollback()

    def test_binding_and_duplicate_content(self):
        with actor("org-a") as c:issue(c,self.p)
        other,_=fixture(code="002")
        with actor("org-a") as c:
            self.reject("APPROVAL_CONTENT_ALREADY_REGISTERED",lambda:issue(c,self.p,id="different"))
            c.rollback()
            self.reject("APPROVAL_ID_CONFLICT",lambda:issue(c,other))
            c.rollback()
            self.reject("APPROVAL_BINDING_CHANGED",lambda:reserve(c,other))
            c.rollback()
            self.assertEqual(reserve(c,self.p),"RESERVED")

    def test_ttl_clock_and_confirmation(self):
        with actor("org-a") as c:
            self.reject("APPROVAL_EXPLICIT_CONFIRMATION_REQUIRED",lambda:issue(c,self.p,confirmed=False))
            c.rollback()
            self.reject("APPROVAL_TTL",lambda:issue(c,self.p,ttl=901))
            c.rollback()
            self.assertEqual(issue(c,self.p,ttl=1),"APPROVED")
        time.sleep(1.1)
        with actor("org-a") as c:
            self.reject("APPROVAL_EXPIRED",lambda:reserve(c,self.p))
            c.rollback()
        with root() as c:c.execute("UPDATE naruv_approval_lab.actors SET last_epoch=extract(epoch FROM clock_timestamp())::bigint+3600 WHERE organization_id='org-a'")
        with actor("org-a") as c:
            self.reject("APPROVAL_CLOCK_ROLLBACK",lambda:inspect(c,"org-a"))
            c.rollback()

    def test_concurrent_claims_distinct_connections(self):
        with actor("org-a") as c:issue(c,self.p)
        barrier=threading.Barrier(8)
        def claim(i):
            with actor("org-a") as c:
                barrier.wait(timeout=10)
                try:return reserve(c,self.p,rid=f"reservation-{i}")
                except psycopg.Error as exc:
                    c.rollback()
                    return exc.diag.message_primary
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            outcomes=list(pool.map(claim,range(8)))
        self.assertEqual(outcomes.count("RESERVED"),1)
        self.assertEqual(outcomes.count("APPROVAL_TERMINAL"),7)
        with actor("org-a") as c:self.assertFalse(inspect(c,"org-a")[2])

    def test_revoke_reserve_race(self):
        with actor("org-a") as c:issue(c,self.p)
        barrier=threading.Barrier(2)
        def action(revoke):
            with actor("org-a") as c:
                barrier.wait(timeout=10)
                try:
                    if revoke:return c.execute("SELECT naruv_approval_lab.revoke(%s,%s)",("org-a","approval-1")).fetchone()[0]
                    return reserve(c,self.p)
                except psycopg.Error as exc:
                    c.rollback()
                    return exc.diag.message_primary
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(action,(False,True)))
        self.assertEqual(results.count("APPROVAL_TERMINAL"),1)
        self.assertEqual(sum(r in ("RESERVED","REVOKED") for r in results),1)

    def test_unique_reservation_and_import_flag_constraint(self):
        with actor("org-a") as c:
            issue(c,self.p);reserve(c,self.p)
        other,_=fixture(code="002")
        with actor("org-a") as c:issue(c,other,id="approval-2")
        with actor("org-a") as c:
            self.reject("APPROVAL_RESERVATION_ID_CONFLICT",lambda:reserve(c,other,id="approval-2"))
            c.rollback()
        with root() as c:
            self.reject("check constraint",lambda:c.execute("UPDATE naruv_approval_lab.approvals SET row_import_authorized=true"))
            c.rollback()

if __name__=="__main__":
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(PostgresApprovalLabTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun!=10 or result.skipped or result.expectedFailures or result.unexpectedSuccesses:
        raise SystemExit(1)
    print("NARUV_APPROVAL_PG17_LAB_PASS 10 tests; real commits, rollback, reconnect, tenant scope, concurrent claims; no row import")
