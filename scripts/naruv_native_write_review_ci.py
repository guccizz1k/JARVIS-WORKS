"""Native auth, separate stage credential, actual PG17 commit and receipt tests.

Uses synthetic records and emulated HTTPS origin, never a deployed TLS endpoint.
"""
import concurrent.futures
import hashlib
import io
import os
from pathlib import Path
import secrets
import threading
import unittest

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
from fastapi.testclient import TestClient
from openpyxl import Workbook
from app import naruv_native_file_preview as preview
from app import naruv_native_write_review as mod
from scripts import ci_v90_postgres_browser as fixture
from scripts.naruv_native_file_preview_ci import NativePreview

ROOT=Path(__file__).resolve().parents[1]
RAW=b"sku,item_name,unit\n001,Widget,EA\n"
PREFIX=preview.PREFIX

class NativeWrite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("JW_ENV")!="review":
            raise RuntimeError("CI_ONLY")
        NativePreview.setUpClass()
        with psycopg.connect(fixture.root_dsn,autocommit=True) as c:
            c.execute("CREATE TABLE jw_dev.staff_disabled(user_id text PRIMARY KEY REFERENCES jw_dev.users(id))")
            identity=(ROOT/"db/review/jw_dev_v84_stage_identity.sql").read_text()
            marker="CREATE FUNCTION jw_dev.stage_identity_v84()"
            if identity.count(marker)!=1:
                raise RuntimeError("IDENTITY_SOURCE_CHANGED")
            c.execute(identity.replace(marker,"CREATE OR REPLACE FUNCTION jw_dev.stage_identity_v84()"))
        password=secrets.token_urlsafe(36)
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("SELECT set_config('naruv.native_write_ci','DISPOSABLE_ONLY',true)")
            c.execute((ROOT/"db/review/naruv_native_write_review_ci.sql").read_text())
            c.execute(sql.SQL("CREATE ROLE naruv_ci_ingest LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB PASSWORD {}").format(sql.Literal(password)))
            c.execute("GRANT naruv_native_stage TO naruv_ci_ingest WITH INHERIT FALSE, SET TRUE")
        cls.ingest_dsn=make_conninfo(fixture.root_dsn,user="naruv_ci_ingest",password=password)
        mod._ingest_connect=lambda:psycopg.connect(cls.ingest_dsn,connect_timeout=5)
        os.environ["NARUV_NATIVE_WRITE_REVIEW"]="ISOLATED_SYNTHETIC_ONLY"
        cls.app=NativePreview.app
        if not mod.register_native_write_review(cls.app):
            raise RuntimeError("WRITE_REVIEW_DISABLED")

    def setUp(self):
        os.environ["NARUV_NATIVE_WRITE_REVIEW"]="ISOLATED_SYNTHETIC_ONLY"
        os.environ["JW_ENV"]="dev"
        with psycopg.connect(fixture.root_dsn) as c:
            tables="naruv_native_review.receipts,naruv_native_review.records,naruv_native_review.approvals,naruv_native_review.stages"
            if getattr(self,"bridge_active",False):
                tables+=",naruv_customer_bridge.crosswalk"
            if getattr(self,"inventory_active",False):
                tables+=",naruv_inventory.movements,naruv_inventory.balances,naruv_inventory.items"
            if getattr(self,"trade_active",False):
                tables+=",naruv_trade.events,naruv_trade.documents"
            if getattr(self,"finance_active",False):
                tables+=",naruv_finance.events,naruv_finance.bills"
            c.execute("TRUNCATE "+tables)
            c.execute("DELETE FROM jw_dev.staff_disabled")
            c.execute("DELETE FROM jw_dev.sessions WHERE id='A2'")
            c.execute("UPDATE jw_dev.users SET role='admin' WHERE id IN ('ci-ua','ci-ub','ci-uc')")
            c.execute("UPDATE jw_dev.sessions SET expires_at=(now()+interval '2 hours')::text")
            c.execute("""UPDATE jw_dev.naruv_review_sources SET revision=CASE WHEN org_id='ci-b' THEN 'rev-b' ELSE 'rev-a' END,
             existing_ids=CASE WHEN source_id='source-a' AND entity='item' THEN ARRAY['EXISTING-A']
              WHEN source_id='source-b' AND entity='item' THEN ARRAY['EXISTING-B'] ELSE ARRAY[]::text[] END""")
    def req(self,path,who="A",raw=b"",fmt=None,d=None,extra=None):
        with TestClient(self.app,base_url="https://testserver") as c:
            if who is not None:c.cookies.set("__Host-jw_session",fixture.TOKENS[who])
            h={"origin":"https://testserver","x-csrf-token":fixture.CSRF[who or "A"]}
            if fmt:h["content-type"]=preview.FORMATS[fmt]
            if d:
                h.update({"x-naruv-stage-digest":d["stage_sha256"],"x-naruv-canonical-digest":d["canonical_rows_sha256"],
                          "x-naruv-target-digest":d["target_snapshot_sha256"]})
            if extra:h.update(extra)
            return c.post(PREFIX+path,headers=h,content=raw)
    def check(self,r,code):
        self.assertEqual(r.status_code,code,r.text)
        return r.json()
    def review(self,raw=RAW,source="source-a",entity="item",fmt="csv",who="A"):
        return self.check(self.req(f"/sources/{source}/{entity}/{fmt}/preview",who,raw,fmt),200)
    def stage(self,sid="stage-1",raw=RAW,source="source-a",entity="item",fmt="csv",who="A",d=None):
        if d is None:d=self.review(raw,source,entity,fmt,who)
        r=self.req(f"/sources/{source}/{entity}/{fmt}/stages/{sid}",who,raw,fmt,d)
        self.check(r,200)
        return d
    def approve(self,d,sid="stage-1",who="A"):
        return self.req(f"/stages/{sid}/approve",who,d=d,extra={"x-naruv-confirm":"yes"})
    def commit(self,d,sid="stage-1",rid="request-1",who="A"):
        return self.req(f"/stages/{sid}/commit/{rid}",who,d=d)
    def counts(self):
        with psycopg.connect(fixture.root_dsn) as c:
            return c.execute("SELECT (SELECT count(*) FROM naruv_native_review.records),(SELECT count(*) FROM naruv_native_review.receipts)").fetchone()
    def test_csv_full_flow_and_exact_retry(self):
        d=self.stage()
        self.assertEqual(self.check(self.approve(d),200)["status"],"APPROVED")
        first=self.check(self.commit(d),200)
        self.assertEqual(first["status"],"REVIEW_COMMITTED")
        self.assertEqual(first["canonical_rows_sha256"],d["canonical_rows_sha256"])
        self.assertEqual(first["target_snapshot_sha256"],d["target_snapshot_sha256"])
        self.assertFalse(first["row_import_authorized"])
        self.assertEqual(self.check(self.commit(d),200),first)
        self.assertEqual(self.check(self.req("/stages/stage-1/receipt/request-1"),200),first)
        self.check(self.commit(d,rid="different"),409)
        self.assertEqual(self.counts(),(1,1))
        with psycopg.connect(fixture.root_dsn) as c:
            self.assertEqual(c.execute("SELECT data FROM naruv_native_review.records").fetchone()[0],{"source_item_id":"001","name":"Widget","unit":"EA"})
            self.assertEqual(c.execute("SELECT existing_ids FROM jw_dev.naruv_review_sources WHERE source_id='source-a' AND entity='item'").fetchone()[0],["001","EXISTING-A"])
    def test_xlsx_customer_optional(self):
        w=Workbook();w.active.append(["customer_id","customer_name","business_number"])
        w.active.append(["C001","Sample","012-34-56789"]);f=io.BytesIO();w.save(f);w.close()
        d=self.stage(raw=f.getvalue(),entity="customer",fmt="xlsx")
        self.check(self.approve(d),200);self.check(self.commit(d),200)
        with psycopg.connect(fixture.root_dsn) as c:
            self.assertEqual(c.execute("SELECT data FROM naruv_native_review.records").fetchone()[0]["business_number"],"012-34-56789")
    def test_stage_and_approval_retry(self):
        d=self.stage()
        r=self.req("/sources/source-a/item/csv/stages/stage-1","A",RAW,"csv",d)
        self.assertEqual(self.check(r,200)["status"],"ALREADY_STAGED")
        self.check(self.approve(d),200)
        with psycopg.connect(fixture.root_dsn) as c:
            before=c.execute("SELECT expires_at FROM naruv_native_review.approvals").fetchone()
        self.assertEqual(self.check(self.approve(d),200)["status"],"ALREADY_APPROVED")
        with psycopg.connect(fixture.root_dsn) as c:
            self.assertEqual(c.execute("SELECT expires_at FROM naruv_native_review.approvals").fetchone(),before)
    def test_changed_raw_digest_and_scope(self):
        d=self.review()
        self.check(self.req("/sources/source-a/item/csv/stages/stage-1","A",RAW.replace(b"Widget",b"Other"),"csv",d),409)
        self.check(self.req("/sources/source-a/item/csv/stages/stage-1","A",RAW,"csv",d,{"x-naruv-canonical-digest":"f"*64}),409)
        self.check(self.req("/sources/source-a/item/csv/stages/stage-1","A",RAW,"csv",d,{"x-naruv-target-digest":"f"*64}),409)
        self.check(self.req("/sources/source-a/item/csv/stages/stage-1","B",RAW,"csv",d),404)
        self.assertEqual(self.counts(),(0,0))
    def test_explicit_confirmation_and_binding(self):
        d=self.stage()
        self.check(self.commit(d),409)
        self.check(self.req("/stages/stage-1/approve",d=d),422)
        self.check(self.req("/stages/stage-1/approve",d=d,extra={"x-naruv-confirm":"yes","x-naruv-canonical-digest":"e"*64}),409)
        self.check(self.approve(d),200)
        self.check(self.req("/stages/stage-1/commit/request-1",d=d,extra={"x-naruv-target-digest":"e"*64}),409)
        self.assertEqual(self.counts(),(0,0))
    def test_tenant_isolation(self):
        d=self.stage()
        self.check(self.approve(d,who="B"),404)
        self.check(self.commit(d,who="B"),404)
        self.check(self.req("/stages/stage-1/receipt/request-1","B"),404)
        self.assertEqual(self.counts(),(0,0))
    def test_revoked_approval(self):
        d=self.stage();self.check(self.approve(d),200)
        self.assertEqual(self.check(self.req("/stages/stage-1/revoke",d=d),200)["status"],"REVOKED")
        self.assertEqual(self.check(self.req("/stages/stage-1/revoke",d=d),200)["status"],"ALREADY_REVOKED")
        self.check(self.commit(d),409);self.check(self.approve(d),409)
        self.assertEqual(self.counts(),(0,0))
    def test_role_and_disabled_session(self):
        d=self.stage();self.check(self.approve(d),200)
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("UPDATE jw_dev.users SET role='member' WHERE id='ci-ua'")
        self.check(self.commit(d),403)
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("UPDATE jw_dev.users SET role='admin' WHERE id='ci-ua'")
            c.execute("INSERT INTO jw_dev.staff_disabled VALUES('ci-ua')")
        self.check(self.commit(d),401)
        self.assertEqual(self.counts(),(0,0))
    def test_session_rotation_blocks_write_but_allows_receipt(self):
        d=self.stage();self.check(self.approve(d),200)
        token=secrets.token_urlsafe(48);csrf=secrets.token_urlsafe(24)
        fixture.TOKENS["A2"]=token;fixture.CSRF["A2"]=csrf
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("INSERT INTO jw_dev.sessions VALUES('A2',%s,'ci-ua',(now()+interval '2 hours')::text,%s,now()::text)",(hashlib.sha256(token.encode()).hexdigest(),csrf))
        self.check(self.commit(d,who="A2"),409)
        receipt=self.check(self.commit(d),200)
        self.assertEqual(self.check(self.req("/stages/stage-1/receipt/request-1","A2"),200),receipt)
    def test_expired_approval(self):
        d=self.stage();self.check(self.approve(d),200)
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("UPDATE naruv_native_review.approvals SET approved_at=now()-interval '2 minutes',expires_at=now()-interval '1 minute'")
        self.check(self.commit(d),409);self.assertEqual(self.counts(),(0,0))
    def test_concurrent_same_reservation(self):
        d=self.stage();self.check(self.approve(d),200)
        b=threading.Barrier(5)
        def run(i):
            b.wait(timeout=10)
            return self.commit(d)
        with concurrent.futures.ThreadPoolExecutor(5) as pool:outcomes=list(pool.map(run,range(5)))
        receipts=[self.check(x,200) for x in outcomes]
        self.assertTrue(all(x==receipts[0] for x in receipts))
        self.assertEqual(self.counts(),(1,1))
    def test_concurrent_different_reservation(self):
        d=self.stage();self.check(self.approve(d),200)
        b=threading.Barrier(5)
        def run(i):
            b.wait(timeout=10)
            return self.commit(d,rid=f"race-{i}")
        with concurrent.futures.ThreadPoolExecutor(5) as pool:outcomes=list(pool.map(run,range(5)))
        self.assertEqual(sorted(x.status_code for x in outcomes),[200,409,409,409,409])
        self.assertEqual(self.counts(),(1,1))
    def test_stale_after_other_commit(self):
        d=self.stage();q=self.stage("stage-2",RAW.replace(b"001",b"002"))
        self.check(self.approve(d),200);self.check(self.approve(q,"stage-2"),200)
        self.check(self.commit(d),200);self.check(self.commit(q,"stage-2","request-2"),409)
        self.assertEqual(self.counts(),(1,1))
    def test_mid_batch_rollback(self):
        d=self.stage(raw=b"sku,item_name\n001,First\n002,Second\n")
        self.check(self.approve(d),200)
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("""CREATE FUNCTION naruv_native_review.inject_failure() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN IF NEW.source_record_id='002' THEN RAISE EXCEPTION 'SYNTHETIC_FAILURE'; END IF; RETURN NEW; END $$""")
            c.execute("CREATE TRIGGER inject_failure BEFORE INSERT ON naruv_native_review.records FOR EACH ROW EXECUTE FUNCTION naruv_native_review.inject_failure()")
        try:
            self.check(self.commit(d),503)
            self.assertEqual(self.counts(),(0,0))
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertEqual(c.execute("SELECT status FROM naruv_native_review.approvals").fetchone()[0],"APPROVED")
                self.assertEqual(c.execute("SELECT revision FROM jw_dev.naruv_review_sources WHERE source_id='source-a' AND entity='item'").fetchone()[0],"rev-a")
        finally:
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("DROP TRIGGER inject_failure ON naruv_native_review.records")
                c.execute("DROP FUNCTION naruv_native_review.inject_failure()")
        self.check(self.commit(d),200);self.assertEqual(self.counts(),(2,1))
    def test_privilege_split_and_immutable_staging(self):
        d=self.stage()
        with psycopg.connect(fixture.root_dsn) as c:
            self.assertEqual(c.execute("SELECT count(*) FROM pg_class WHERE relnamespace='naruv_native_review'::regnamespace AND relkind='r' AND relrowsecurity AND relforcerowsecurity").fetchone()[0],4)
            with self.assertRaisesRegex(psycopg.Error,"NARUV_IMMUTABLE"):
                c.execute("UPDATE naruv_native_review.stages SET rows_canonical=rows_canonical")
            c.rollback()
        for dsn,role in [(fixture.TRADE_DSN,"jw_app_dev"),(self.ingest_dsn,"naruv_native_stage")]:
            with psycopg.connect(dsn) as c:
                c.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(role)))
                row=c.execute("""SELECT has_table_privilege(current_user,'naruv_native_review.stages','SELECT'),
                  has_function_privilege(current_user,'naruv_native_review.store_stage(text,text,text,text,text,integer,text,text,text,text,text,text[],text,text)','EXECUTE'),
                  has_function_privilege(current_user,'naruv_native_review.commit_stage(text,text,text,text,text,text)','EXECUTE')""").fetchone()
                self.assertEqual(row,(False,role=="naruv_native_stage",role=="jw_app_dev"))
        self.assertEqual(self.counts(),(0,0))
    def test_overlapping_roles_fail_in_http_and_database(self):
        d=self.stage();self.check(self.approve(d),200)
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("GRANT naruv_native_stage TO jw_ci_trade WITH INHERIT FALSE, SET TRUE")
        try:
            self.check(self.commit(d),503)
            with psycopg.connect(fixture.TRADE_DSN) as c:
                c.execute("SET LOCAL ROLE jw_app_dev")
                c.execute("SELECT set_config('jw.session_hash',%s,true)",(hashlib.sha256(fixture.TOKENS["A"].encode()).hexdigest(),))
                with self.assertRaisesRegex(psycopg.Error,"NARUV_PERMISSION_DENIED"):
                    c.execute("SELECT naruv_native_review.commit_stage(%s,%s,%s,%s,%s,%s)",
                        ("stage-1",d["stage_sha256"],d["canonical_rows_sha256"],d["target_snapshot_sha256"],"request-1",fixture.CSRF["A"]))
                c.rollback()
        finally:
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("REVOKE naruv_native_stage FROM jw_ci_trade")
        q=self.review(RAW.replace(b"001",b"002"))
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("GRANT jw_app_dev TO naruv_ci_ingest WITH INHERIT FALSE, SET TRUE")
        try:
            self.check(self.req("/sources/source-a/item/csv/stages/stage-2","A",RAW.replace(b"001",b"002"),"csv",q),503)
            with psycopg.connect(self.ingest_dsn) as c:
                c.execute("SET LOCAL ROLE naruv_native_stage")
                c.execute("SELECT set_config('jw.session_hash',%s,true)",(hashlib.sha256(fixture.TOKENS["A"].encode()).hexdigest(),))
                with self.assertRaisesRegex(psycopg.Error,"NARUV_PERMISSION_DENIED"):
                    c.execute("SELECT * FROM naruv_native_review.read_source(%s,%s,%s)",("source-a","item",fixture.CSRF["A"]))
                c.rollback()
        finally:
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("REVOKE jw_app_dev FROM naruv_ci_ingest")
        self.assertEqual(self.counts(),(0,0))
        self.check(self.commit(d),200)
    def test_database_independently_rejects_forged_stage_digests(self):
        import json
        d=self.review()
        correct=json.dumps(d["rows"],ensure_ascii=False,sort_keys=True,separators=(",",":"))
        with psycopg.connect(self.ingest_dsn) as c:
            c.execute("SET LOCAL ROLE naruv_native_stage")
            c.execute("SELECT set_config('jw.session_hash',%s,true)",(hashlib.sha256(fixture.TOKENS["A"].encode()).hexdigest(),))
            q="SELECT naruv_native_review.store_stage(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            def args(rows,snapshot):
                return ("forged","source-a","item","csv",d["raw_sha256"],d["byte_count"],d["stage_sha256"],
                    d["canonical_rows_sha256"],"a"*64,snapshot,"rev-a",["EXISTING-A"],rows,fixture.CSRF["A"])
            for rows,snapshot,error in [(correct.replace("Widget","Other"),d["target_snapshot_sha256"],"NARUV_STAGE_INPUT"),
                                       (correct,"f"*64,"NARUV_TARGET_CHANGED")]:
                with self.assertRaisesRegex(psycopg.Error,error):
                    with c.transaction():c.execute(q,args(rows,snapshot))
        with psycopg.connect(fixture.root_dsn) as c:
            self.assertEqual(c.execute("SELECT count(*) FROM naruv_native_review.stages").fetchone()[0],0)
    def test_permission_generation_never_resurrects_approval(self):
        d=self.stage();self.check(self.approve(d),200)
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("UPDATE jw_dev.users SET role='member' WHERE id='ci-ua'")
            c.execute("UPDATE jw_dev.users SET role='admin' WHERE id='ci-ua'")
        self.check(self.commit(d),409)
        self.assertEqual(self.counts(),(0,0))
        q=self.stage("stage-2")
        self.check(self.approve(q,"stage-2"),200)
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("INSERT INTO jw_dev.staff_disabled VALUES('ci-ua')")
            c.execute("DELETE FROM jw_dev.staff_disabled WHERE user_id='ci-ua'")
        self.check(self.commit(q,"stage-2"),409)
        self.assertEqual(self.counts(),(0,0))
        r=self.stage("stage-3");self.check(self.approve(r,"stage-3"),200)
        self.check(self.commit(r,"stage-3"),200)
    def test_session_generation_never_resurrects_approval(self):
        d=self.stage();self.check(self.approve(d),200)
        with psycopg.connect(fixture.root_dsn) as c:
            expiry=c.execute("SELECT expires_at FROM jw_dev.sessions WHERE id='A'").fetchone()[0]
            c.execute("UPDATE jw_dev.sessions SET expires_at=(now()-interval '1 hour')::text WHERE id='A'")
            c.execute("UPDATE jw_dev.sessions SET expires_at=%s WHERE id='A'",(expiry,))
        self.check(self.commit(d),409)
        self.assertEqual(self.counts(),(0,0))
    def _direct_commit(self,c,d):
        c.execute("SET LOCAL ROLE jw_app_dev")
        c.execute("SELECT set_config('jw.session_hash',%s,true)",(hashlib.sha256(fixture.TOKENS["A"].encode()).hexdigest(),))
        return c.execute("SELECT naruv_native_review.commit_stage(%s,%s,%s,%s,%s,%s)",
            ("stage-1",d["stage_sha256"],d["canonical_rows_sha256"],d["target_snapshot_sha256"],"request-1",fixture.CSRF["A"])).fetchone()[0]
    def _wait_blocked(self,pid,blocker):
        import time
        deadline=time.monotonic()+5
        with psycopg.connect(fixture.root_dsn,autocommit=True) as c:
            while time.monotonic()<deadline:
                if blocker in c.execute("SELECT pg_blocking_pids(%s)",(pid,)).fetchone()[0]:
                    return
                time.sleep(.02)
        self.fail("Expected database lock wait was not observed")
    def test_revocation_wins_and_waiting_commit_is_denied(self):
        import queue
        d=self.stage();self.check(self.approve(d),200)
        pids=queue.Queue()
        def attempt():
            try:
                with psycopg.connect(fixture.TRADE_DSN,options="-c statement_timeout=12000") as c:
                    pids.put(c.info.backend_pid)
                    self._direct_commit(c,d)
            except psycopg.Error as e:
                return e.sqlstate,e.diag.message_primary
            return ("UNEXPECTED_SUCCESS","")
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            with psycopg.connect(fixture.root_dsn) as root:
                root.execute("UPDATE jw_dev.users SET role='member' WHERE id='ci-ua'")
                fut=pool.submit(attempt)
                self._wait_blocked(pids.get(timeout=5),root.info.backend_pid)
            self.assertEqual(fut.result(timeout=10),("42501","NARUV_PERMISSION_DENIED"))
        self.assertEqual(self.counts(),(0,0))
    def test_commit_wins_and_revocation_waits(self):
        import queue
        d=self.stage();self.check(self.approve(d),200)
        pids=queue.Queue()
        def revoke():
            with psycopg.connect(fixture.root_dsn,options="-c statement_timeout=12000") as c:
                pids.put(c.info.backend_pid)
                c.execute("INSERT INTO jw_dev.staff_disabled VALUES('ci-ua')")
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            with psycopg.connect(fixture.TRADE_DSN) as c:
                self.assertEqual(self._direct_commit(c,d)["status"],"REVIEW_COMMITTED")
                fut=pool.submit(revoke)
                self._wait_blocked(pids.get(timeout=5),c.info.backend_pid)
            fut.result(timeout=10)
        self.assertEqual(self.counts(),(1,1))
        self.check(self.commit(d),401)
    def test_repeatable_read_rejected(self):
        d=self.stage();self.check(self.approve(d),200)
        with psycopg.connect(fixture.TRADE_DSN) as c:
            c.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            with self.assertRaisesRegex(psycopg.Error,"NARUV_AUTH_FENCE_UNSAFE"):
                self._direct_commit(c,d)
            c.rollback()
        self.assertEqual(self.counts(),(0,0))
    def test_tenant_quota_cross_source_and_retry(self):
        d=self.stage()
        with psycopg.connect(fixture.root_dsn) as c:
            # Deliberately seed synthetic immutable rows for quota-boundary testing.
            c.execute("""INSERT INTO naruv_native_review.stages
              SELECT (jsonb_populate_record(NULL::naruv_native_review.stages,
                  to_jsonb(s)||jsonb_build_object('stage_id','quota-'||g))).*
              FROM naruv_native_review.stages s CROSS JOIN generate_series(1,127) g
              WHERE s.stage_id='stage-1' AND s.org_id='ci-a'""")
        retry=self.req("/sources/source-a/item/csv/stages/stage-1","A",RAW,"csv",d)
        self.assertEqual(self.check(retry,200)["status"],"ALREADY_STAGED")
        raw=b"customer_id,customer_name\nC001,Sample\n"
        q=self.review(raw,entity="customer")
        r=self.req("/sources/source-a/customer/csv/stages/extra","A",raw,"csv",q)
        self.assertEqual(self.check(r,422)["detail"],"NARUV_CAPACITY")
        self.stage("other-tenant",source="source-b",who="B")
        with psycopg.connect(fixture.root_dsn) as c:
            self.assertEqual(c.execute("SELECT count(*) FROM naruv_native_review.stages WHERE org_id='ci-a'").fetchone()[0],128)
        self.assertEqual(self.counts(),(0,0))
    def test_tenant_byte_quota(self):
        d=self.stage()
        with psycopg.connect(fixture.root_dsn) as c:
            # Catalog-constrained synthetic payloads, not parser acceptance evidence.
            c.execute("""WITH payload AS (
              SELECT jsonb_build_array(jsonb_build_object('fixture',repeat('x',1048576)))::text AS v
            ) INSERT INTO naruv_native_review.stages
              SELECT (jsonb_populate_record(NULL::naruv_native_review.stages,
                  to_jsonb(s)||jsonb_build_object('stage_id','bytes-'||g,'rows_canonical',p.v,
                  'canonical_sha256',encode(sha256(convert_to(p.v,'UTF8')),'hex')))).*
              FROM naruv_native_review.stages s CROSS JOIN payload p CROSS JOIN generate_series(1,16) g
              WHERE s.stage_id='stage-1' AND s.org_id='ci-a'""")
        r=self.req("/sources/source-a/item/csv/stages/extra","A",RAW,"csv",d)
        self.assertEqual(self.check(r,422)["detail"],"NARUV_CAPACITY")
        self.stage("other-tenant",source="source-b",who="B")
    def test_future_approval_denied(self):
        d=self.stage();self.check(self.approve(d),200)
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("UPDATE naruv_native_review.approvals SET approved_at=now()+interval '1 minute',expires_at=now()+interval '10 minutes'")
        self.check(self.commit(d),409)
        self.assertEqual(self.counts(),(0,0))
    def test_rolled_back_revocation_does_not_invalidate(self):
        d=self.stage();self.check(self.approve(d),200)
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("UPDATE jw_dev.users SET role='member' WHERE id='ci-ua'")
            c.rollback()
        self.check(self.commit(d),200)
        self.assertEqual(self.counts(),(1,1))
    def test_actor_lock_does_not_block_other_tenant(self):
        d=self.stage("stage-b",source="source-b",who="B")
        self.check(self.approve(d,"stage-b","B"),200)
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("UPDATE jw_dev.users SET role='member' WHERE id='ci-ua'")
            self.check(self.commit(d,"stage-b","request-b","B"),200)
            c.rollback()
        self.assertEqual(self.counts(),(1,1))
    def test_transport_and_default_off(self):
        d=self.stage()
        self.check(self.req("/stages/stage-1/approve",d=d,raw=b"unexpected",extra={"x-naruv-confirm":"yes"}),413)
        self.check(self.req("/stages/stage-1/approve",d=d,extra={"x-naruv-confirm":"yes","origin":"https://other.test"}),403)
        os.environ["JW_ENV"]="production"
        self.check(self.approve(d),404)
        os.environ["JW_ENV"]="dev";os.environ.pop("NARUV_NATIVE_WRITE_REVIEW",None)
        self.check(self.approve(d),404)
        self.assertEqual(self.counts(),(0,0))
if __name__=="__main__":
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(NativeWrite)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun!=28 or result.skipped or result.expectedFailures or result.unexpectedSuccesses:
        raise SystemExit(1)
    print("NARUV_NATIVE_WRITE_REVIEW_PASS: 28 isolated PG17 HTTP and direct transaction cases; no production ERP import.")
    from scripts.naruv_customer_bridge_ci import run_bridge
    run_bridge(NativeWrite)
    from scripts.naruv_inventory_ci import run_inventory
    run_inventory(NativeWrite)
    from scripts.naruv_trade_ci import run_trade
    run_trade(NativeWrite)
    from scripts.naruv_finance_ci import run_finance
    run_finance(NativeWrite)
