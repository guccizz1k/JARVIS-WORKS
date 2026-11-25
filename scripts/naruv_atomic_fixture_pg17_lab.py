"""Actual disposable PG17 atomic synthetic item writes; no remote DSN."""
import concurrent.futures
from pathlib import Path
import threading
import unittest
import psycopg
from psycopg.types.json import Jsonb

from scripts.naruv_approval_pg17_lab import root, actor, issue, inspect, SQL, SOURCE, ENTITY, H
from app.erp_migration_review import prepare_header_review
from app.erp_migration_preflight import make_target_snapshot, prepare_row_preflight

EXT=Path(__file__).resolve().parents[1]/"db/review/naruv_atomic_fixture_pg17_lab.sql"

def commit_fixture(c,org="org-a",aid="approval-1",rid="request-1"):
    return c.execute("SELECT naruv_approval_lab.commit_fixture(%s,%s,%s)",(org,aid,rid)).fetchone()[0]

def receipt(c,org="org-a",aid="approval-1",rid="request-1"):
    return c.execute("SELECT * FROM naruv_approval_lab.inspect_fixture(%s,%s,%s)",(org,aid,rid)).fetchone()

class AtomicFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with root() as c:
            if c.execute("SELECT to_regnamespace('naruv_approval_lab')").fetchone()[0] is not None:
                raise RuntimeError("LAB_SCHEMA_ALREADY_EXISTS")
            c.execute(SQL.read_text(encoding="utf-8"))
            c.execute(EXT.read_text(encoding="utf-8"))

    def setUp(self):
        self.targets={}
        with root() as c:
            for table in ("fixture_receipts","fixture_stage","fixture_items","approvals","targets"):
                # Fixed fixture-only names, never arbitrary SQL from user.
                c.execute("DELETE FROM naruv_approval_lab."+table)
            c.execute("UPDATE naruv_approval_lab.actors SET active=true,can_approve=true,can_reserve=true,permission_revision='perm-1',last_epoch=0")
            for org in ("org-a","org-b"):
                t=make_target_snapshot(org,SOURCE,ENTITY,"rev-1",())
                self.targets[org]=t
                c.execute("INSERT INTO naruv_approval_lab.targets VALUES(%s,%s,%s,%s)",
                          (org,SOURCE,ENTITY,t.snapshot_sha256))

    def stage(self,org="org-a",aid="approval-1",rows=(("001","품목 A"),("002","품목 B"))):
        # Trusted root fixture stages exactly the rows checked by existing Python preflight.
        target=self.targets[org]
        review=prepare_header_review(org,SOURCE,ENTITY,H)
        p=prepare_row_preflight(review,organization_id=org,source_id=SOURCE,entity=ENTITY,
                                headers=H,rows=rows,target=target)
        next_target=make_target_snapshot(org,SOURCE,ENTITY,"next-"+aid,
                          (*target.existing_source_ids,*(row[0] for row in rows)))
        with actor(org) as c:self.assertEqual(issue(c,p,id=aid),"APPROVED")
        with root() as c:
            c.execute("""INSERT INTO naruv_approval_lab.fixture_stage
                (organization_id,approval_id,source_id,entity,preflight_sha256,rows_sha256,
                snapshot_sha256,next_snapshot_sha256,expected_ids,fixture_rows)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (org,aid,SOURCE,ENTITY,p.binding_sha256,p.rows_sha256,p.target_snapshot_sha256,
                 next_target.snapshot_sha256,list(target.existing_source_ids),
                 Jsonb([{"source_item_id":r[0],"name":r[1]} for r in rows])))
        return next_target

    def state(self,org="org-a"):
        with root() as c:
            ids=c.execute("SELECT source_item_id FROM naruv_approval_lab.fixture_items WHERE organization_id=%s ORDER BY source_item_id",(org,)).fetchall()
            n=c.execute("SELECT count(*) FROM naruv_approval_lab.fixture_receipts WHERE organization_id=%s",(org,)).fetchone()[0]
            h=c.execute("SELECT snapshot_sha256 FROM naruv_approval_lab.targets WHERE organization_id=%s",(org,)).fetchone()[0]
            return tuple(row[0] for row in ids),n,h

    def rejected(self,org,reason,fn):
        with actor(org) as c:
            with self.assertRaisesRegex(psycopg.Error,reason):fn(c)
            c.rollback()

    def assert_unwritten(self,org="org-a",aid="approval-1"):
        self.assertEqual(self.state(org),((),0,self.targets[org].snapshot_sha256))
        with actor(org) as c:
            self.assertEqual(inspect(c,org,id=aid),("APPROVED",None,False))

    def test_commit_and_receipt_after_reconnect(self):
        target=self.stage()
        with actor("org-a") as c:self.assertEqual(commit_fixture(c),"FIXTURE_COMMITTED")
        self.assertEqual(self.state(),(("001","002"),1,target.snapshot_sha256))
        with actor("org-a") as c:
            self.assertEqual(receipt(c),("FIXTURE_COMMITTED",2,False))
            self.assertIsNone(receipt(c,rid="wrong"))
        self.rejected("org-a","APPROVAL_TARGET_CHANGED",commit_fixture)
        self.assertEqual(self.state(),(("001","002"),1,target.snapshot_sha256))

    def test_abandon_before_commit(self):
        self.stage()
        c=actor("org-a")
        try:self.assertEqual(commit_fixture(c),"FIXTURE_COMMITTED")
        finally:c.close()
        self.assert_unwritten()
        with actor("org-a") as c:self.assertIsNone(receipt(c))

    def test_explicit_rollback_after_all_writes(self):
        self.stage()
        with actor("org-a") as c:
            commit_fixture(c)
            c.rollback()
        self.assert_unwritten()

    def test_fault_after_first_row_rolls_back_everything(self):
        self.stage(rows=(("001","ok"),("fault-2","fail")))
        # A test-only trigger fails on the second row; first INSERT has executed.
        with root() as c:
            c.execute("""CREATE FUNCTION naruv_approval_lab.fixture_test_fault() RETURNS trigger
            LANGUAGE plpgsql SET search_path=pg_catalog AS $$
            BEGIN IF NEW.source_item_id='fault-2' THEN RAISE EXCEPTION 'LAB_INJECTED_FAILURE'; END IF; RETURN NEW; END $$;
            CREATE TRIGGER fixture_test_fault BEFORE INSERT ON naruv_approval_lab.fixture_items
             FOR EACH ROW EXECUTE FUNCTION naruv_approval_lab.fixture_test_fault()""")
        try:
            self.rejected("org-a","LAB_INJECTED_FAILURE",commit_fixture)
            self.assert_unwritten()
        finally:
            with root() as c:
                c.execute("DROP TRIGGER fixture_test_fault ON naruv_approval_lab.fixture_items; DROP FUNCTION naruv_approval_lab.fixture_test_fault()")

    def test_target_fencing_two_approved_batches(self):
        target=self.stage()
        self.stage(aid="approval-2",rows=(("002","overlap"),("003","new")))
        with actor("org-a") as c:commit_fixture(c)
        self.rejected("org-a","APPROVAL_TARGET_CHANGED",lambda c:commit_fixture(c,aid="approval-2",rid="request-2"))
        self.assertEqual(self.state(),(("001","002"),1,target.snapshot_sha256))

    def test_unexpected_existing_ids_detected(self):
        self.stage()
        with root() as c:
            c.execute("INSERT INTO naruv_approval_lab.fixture_items(organization_id,source_id,entity,source_item_id,name) VALUES(%s,%s,%s,%s,%s)",
                      ("org-a",SOURCE,ENTITY,"unexpected","old"))
        self.rejected("org-a","FIXTURE_TARGET_IDS_CHANGED",commit_fixture)
        self.assertEqual(self.state(),(("unexpected",),0,self.targets["org-a"].snapshot_sha256))

    def test_untrusted_role_cannot_stage_write_or_cross_tenant(self):
        self.stage()
        for query in ("SELECT * FROM naruv_approval_lab.fixture_stage",
                      "DELETE FROM naruv_approval_lab.fixture_items",
                      "DELETE FROM naruv_approval_lab.fixture_receipts"):
            self.rejected("org-a","permission denied",lambda c,q=query:c.execute(q))
        self.rejected("org-b","FIXTURE_SCOPE",commit_fixture)
        self.rejected("org-b","FIXTURE_SCOPE",receipt)
        self.assert_unwritten()
        target=self.stage("org-b")
        with actor("org-b") as c:commit_fixture(c,"org-b")
        self.assertEqual(self.state("org-b"),(("001","002"),1,target.snapshot_sha256))
        self.assert_unwritten()

    def test_tampered_binding_and_revoked_authority(self):
        self.stage()
        with root() as c:c.execute("UPDATE naruv_approval_lab.fixture_stage SET preflight_sha256=%s",("f"*64,))
        self.rejected("org-a","FIXTURE_BINDING_CHANGED",commit_fixture)
        self.assert_unwritten()
        with root() as c:
            c.execute("""UPDATE naruv_approval_lab.fixture_stage s SET preflight_sha256=a.preflight_sha256
             FROM naruv_approval_lab.approvals a WHERE s.organization_id=a.organization_id AND s.approval_id=a.approval_id""")
            c.execute("UPDATE naruv_approval_lab.actors SET can_reserve=false WHERE organization_id='org-a'")
        self.rejected("org-a","APPROVAL_PERMISSION_DENIED",commit_fixture)
        self.assertEqual(self.state(),((),0,self.targets["org-a"].snapshot_sha256))

    def test_concurrent_commit_single_winner(self):
        target=self.stage()
        barrier=threading.Barrier(8)
        def run(i):
            with actor("org-a") as c:
                barrier.wait(timeout=10)
                try:return commit_fixture(c,rid=f"request-{i}")
                except psycopg.Error as exc:
                    c.rollback()
                    return exc.diag.message_primary
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(run,range(8)))
        self.assertEqual(results.count("FIXTURE_COMMITTED"),1)
        self.assertEqual(results.count("APPROVAL_TARGET_CHANGED"),7)
        self.assertEqual(self.state(),(("001","002"),1,target.snapshot_sha256))

    def test_natural_key_constraint_and_force_rls(self):
        self.stage()
        with actor("org-a") as c:commit_fixture(c)
        with root() as c:
            c.execute("INSERT INTO naruv_approval_lab.fixture_items(organization_id,source_id,entity,source_item_id,name) VALUES(%s,%s,%s,%s,%s)",
                      ("org-a",SOURCE,ENTITY,"ABC","name"))
        with root() as c:
            with self.assertRaises(psycopg.errors.UniqueViolation):
                c.execute("INSERT INTO naruv_approval_lab.fixture_items(organization_id,source_id,entity,source_item_id,name) VALUES(%s,%s,%s,%s,%s)",
                          ("org-a",SOURCE,ENTITY,"abc","other"))
            c.rollback()
            flags=c.execute("""SELECT relrowsecurity,relforcerowsecurity FROM pg_class
                WHERE relnamespace='naruv_approval_lab'::regnamespace AND relkind='r'""").fetchall()
            self.assertEqual(flags,[(True,True)]*6)

if __name__=="__main__":
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(AtomicFixtureTests))
    if not result.wasSuccessful() or result.testsRun!=10 or result.skipped or result.expectedFailures or result.unexpectedSuccesses:
        raise SystemExit(1)
    print("NARUV_ATOMIC_FIXTURE_PG17_PASS 10 tests; synthetic items only; no production import authority")
