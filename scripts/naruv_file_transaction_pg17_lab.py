"""Run on a fresh disposable PG17 service using existing approved lab guards."""
from pathlib import Path
import unittest
import concurrent.futures
import threading
import io
import os
import psycopg
from openpyxl import Workbook
from app.erp_migration_file_stage import prepare_file_stage
from app.erp_migration_file_transaction import stage_reviewed_file
from app.erp_migration_preflight import make_target_snapshot
from scripts.naruv_approval_pg17_lab import root,actor,SQL

EXT=Path(__file__).resolve().parents[1]/'db/review/naruv_file_transaction_pg17_lab.sql'
S='erp-source-1'
class FileTransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with root() as c:
            if c.execute("SELECT to_regnamespace('naruv_approval_lab')").fetchone()[0] is not None:
                raise RuntimeError('LAB_SCHEMA_ALREADY_EXISTS')
            expected=os.environ.get('NARUV_FILE_TX_SERVER_ADDR')
            if not expected or c.execute('SELECT host(inet_server_addr())').fetchone()[0]!=expected:
                raise RuntimeError('TX_SERVICE_ADDR')
            c.execute("SELECT set_config('naruv.file_tx_server_addr',%s,true)",(expected,))
            c.execute(SQL.read_text());c.execute(EXT.read_text())
    def setUp(self):
        with root() as c:
            c.execute('TRUNCATE naruv_approval_lab.file_receipts,naruv_approval_lab.file_bindings,naruv_approval_lab.file_stages,naruv_approval_lab.file_records,naruv_approval_lab.file_revisions,naruv_approval_lab.approvals,naruv_approval_lab.targets')
            c.execute("UPDATE naruv_approval_lab.actors SET active=true,can_approve=true,can_reserve=true,permission_revision='perm-1',last_epoch=0")
            for org in ('org-a','org-b'):
                for entity in ('item','customer'):
                    t=make_target_snapshot(org,S,entity,'rev-0',())
                    c.execute('INSERT INTO naruv_approval_lab.targets VALUES(%s,%s,%s,%s)',(org,S,entity,t.snapshot_sha256))
                    c.execute('INSERT INTO naruv_approval_lab.file_revisions VALUES(%s,%s,%s,0)',(org,S,entity))
    def stage(self,*,org='org-a',sid='stage-1',fmt='csv',code='001'):
        if fmt=='csv':raw=f'sku,item_name,unit\n{code},품목,EA\n'.encode()
        else:
            w=Workbook();w.active.append(['sku','item_name','unit']);w.active.append([code,'품목','EA']);f=io.BytesIO();w.save(f);raw=f.getvalue();w.close()
        t=make_target_snapshot(org,S,'item','rev-0',())
        prev=prepare_file_stage(raw,format=fmt,organization_id=org,source_id=S,entity='item',target=t)
        with root() as c:return stage_reviewed_file(c,raw,file_format=fmt,organization_id=org,source_id=S,entity='item',stage_id=sid,previously_reviewed=prev)
    def approve(self,p,org='org-a',confirmed=True):
        with actor(org) as c:return c.execute('SELECT naruv_approval_lab.approve_file(%s,%s,%s,%s,60)',(p.organization_id,p.stage_id,p.stage_sha256,confirmed)).fetchone()[0]
    def commit(self,p,rid='reservation-1',org='org-a'):
        with actor(org) as c:return c.execute('SELECT naruv_approval_lab.commit_file(%s,%s,%s)',(p.organization_id,p.stage_id,rid)).fetchone()[0]
    def test_csv_xlsx_commit_and_receipt(self):
        for fmt,org in [('csv','org-a'),('xlsx','org-b')]:
            p=self.stage(fmt=fmt,org=org);self.assertEqual(self.approve(p,org),'APPROVED');self.assertEqual(self.commit(p,org=org),'FILE_COMMITTED')
            with actor(org) as c:
                self.assertEqual(c.execute('SELECT * FROM naruv_approval_lab.inspect_file(%s,%s,%s)',(org,p.stage_id,'reservation-1')).fetchone(),('FILE_COMMITTED',1,p.stage_sha256,False))
            with root() as c:
                self.assertEqual(c.execute('SELECT data FROM naruv_approval_lab.file_records WHERE organization_id=%s',(org,)).fetchone()[0]['unit'],'EA')
    def test_unapproved_and_wrong_org(self):
        p=self.stage()
        with self.assertRaisesRegex(psycopg.Error,'TX_BINDING_CHANGED'):self.commit(p)
        with self.assertRaisesRegex(psycopg.Error,'TX_SCOPE'):self.approve(p,'org-b')
        with self.assertRaisesRegex(psycopg.Error,'APPROVAL_EXPLICIT_CONFIRMATION_REQUIRED'):self.approve(p,confirmed=False)
    def test_revoked_permission(self):
        p=self.stage();self.approve(p)
        with root() as c:c.execute("UPDATE naruv_approval_lab.actors SET permission_revision='perm-2' WHERE organization_id='org-a'")
        with self.assertRaisesRegex(psycopg.Error,'APPROVAL_ACTOR_CHANGED'):self.commit(p)
    def test_stage_immutable_and_direct_bypass(self):
        p=self.stage()
        with self.assertRaisesRegex(psycopg.Error,'TX_STAGE_IMMUTABLE'):
            with root() as c:c.execute("UPDATE naruv_approval_lab.file_stages SET rows_json=rows_json")
        with self.assertRaisesRegex(psycopg.Error,'permission denied'):
            with actor('org-a') as c:c.execute('SELECT naruv_approval_lab.issue(%s,%s,%s,%s,%s,%s,%s,true,60)',(p.organization_id,p.stage_id,p.source_id,p.entity,p.preflight_sha256,p.rows_sha256,p.snapshot_sha256))
    def test_concurrent_commit(self):
        p=self.stage();self.approve(p);barrier=threading.Barrier(5)
        def f(i):
            barrier.wait(10)
            try:return self.commit(p,f'r-{i}')
            except psycopg.Error as e:return e.diag.message_primary
        with concurrent.futures.ThreadPoolExecutor(5) as pool:outcomes=list(pool.map(f,range(5)))
        self.assertEqual(outcomes.count('FILE_COMMITTED'),1)
        self.assertEqual(outcomes.count('APPROVAL_TARGET_CHANGED'),4)
        with root() as c:self.assertEqual(c.execute('SELECT count(*) FROM naruv_approval_lab.file_records').fetchone()[0],1)
    def test_rollback_after_write(self):
        p=self.stage();self.approve(p)
        c=actor('org-a')
        try:
            self.assertEqual(c.execute('SELECT naruv_approval_lab.commit_file(%s,%s,%s)',('org-a',p.stage_id,'r-1')).fetchone()[0],'FILE_COMMITTED');c.rollback()
        finally:c.close()
        with root() as c:
            self.assertEqual(c.execute('SELECT count(*) FROM naruv_approval_lab.file_records').fetchone()[0],0)
            self.assertEqual(c.execute('SELECT count(*) FROM naruv_approval_lab.file_receipts').fetchone()[0],0)
        self.assertEqual(self.commit(p),'FILE_COMMITTED')
    def test_customer_optional_field(self):
        org='org-a';raw='customer_id,customer_name,business_number\nC001,테스트,012-34-56789\n'.encode()
        t=make_target_snapshot(org,S,'customer','rev-0',())
        prev=prepare_file_stage(raw,format='csv',organization_id=org,source_id=S,entity='customer',target=t)
        with root() as c:p=stage_reviewed_file(c,raw,file_format='csv',organization_id=org,source_id=S,entity='customer',stage_id='customer-1',previously_reviewed=prev)
        self.approve(p);self.assertEqual(self.commit(p),'FILE_COMMITTED')
        with root() as c:self.assertEqual(c.execute("SELECT data FROM naruv_approval_lab.file_records WHERE entity='customer'").fetchone()[0]['business_number'],'012-34-56789')
    def test_stale_target_after_other_commit(self):
        p=self.stage();q=self.stage(sid='stage-2',code='002');self.approve(p);self.approve(q);self.commit(p)
        with self.assertRaisesRegex(psycopg.Error,'APPROVAL_TARGET_CHANGED'):self.commit(q,rid='r-2')
        with root() as c:self.assertEqual(c.execute('SELECT count(*) FROM naruv_approval_lab.file_records').fetchone()[0],1)
    def test_mid_batch_error_rolls_back_all(self):
        org='org-a';raw='sku,item_name,unit\n001,품목,EA\n002,품목,EA\n'.encode()
        t=make_target_snapshot(org,S,'item','rev-0',())
        prev=prepare_file_stage(raw,format='csv',organization_id=org,source_id=S,entity='item',target=t)
        with root() as c:p=stage_reviewed_file(c,raw,file_format='csv',organization_id=org,source_id=S,entity='item',stage_id='batch',previously_reviewed=prev)
        self.approve(p)
        with root() as c:
            c.execute("CREATE FUNCTION naruv_approval_lab.inject_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.source_record_id='002' THEN RAISE EXCEPTION 'SYNTHETIC_SECOND_ROW_FAILURE'; END IF; RETURN NEW; END $$")
            c.execute('CREATE TRIGGER inject_failure BEFORE INSERT ON naruv_approval_lab.file_records FOR EACH ROW EXECUTE FUNCTION naruv_approval_lab.inject_failure()')
        try:
            with self.assertRaisesRegex(psycopg.Error,'SYNTHETIC_SECOND_ROW_FAILURE'):self.commit(p)
            with root() as c:
                self.assertEqual(c.execute('SELECT count(*) FROM naruv_approval_lab.file_records').fetchone()[0],0)
                self.assertEqual(c.execute('SELECT count(*) FROM naruv_approval_lab.file_receipts').fetchone()[0],0)
                self.assertEqual(c.execute("SELECT status FROM naruv_approval_lab.approvals WHERE approval_id='batch'").fetchone()[0],'APPROVED')
                self.assertEqual(c.execute("SELECT revision FROM naruv_approval_lab.file_revisions WHERE organization_id='org-a' AND entity='item'").fetchone()[0],0)
        finally:
            with root() as c:
                c.execute('DROP TRIGGER inject_failure ON naruv_approval_lab.file_records')
                c.execute('DROP FUNCTION naruv_approval_lab.inject_failure()')
        self.assertEqual(self.commit(p),'FILE_COMMITTED')
if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(FileTransactionTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun!=9 or result.skipped or result.expectedFailures or result.unexpectedSuccesses:raise SystemExit(1)
