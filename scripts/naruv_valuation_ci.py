"""Actual PG17 valuation / quantity and material cost integrity."""
import concurrent.futures
import os
from pathlib import Path
import threading
import unittest
import psycopg
from fastapi import FastAPI
from app import naruv_valuation_review as valuation
from scripts import ci_v90_postgres_browser as fixture
ROOT=Path(__file__).resolve().parents[1]
RAW=b"sku,item_name,unit\n0001,Widget,EA\n0002,Bolt,EA\n0003,Assembly,EA\n"

def run_valuation(base):
    class Valuation(base):
        valuation_active=True
        @classmethod
        def setUpClass(cls):
            if os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("JW_ENV")!="dev":raise RuntimeError("CI_ONLY")
            cls.app=base.app;cls.ingest_dsn=base.ingest_dsn
            # Clear the previous synthetic test's rows before installing the valuation fence.
            base("test_prod_strict_input_and_role_revocation").setUp()
            os.environ.update(NARUV_PRODUCTION_REVIEW="ISOLATED_SYNTHETIC_ONLY",NARUV_VALUATION_REVIEW="ISOLATED_SYNTHETIC_ONLY")
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("SELECT set_config('naruv.valuation_ci','DISPOSABLE_ONLY',true)")
                c.execute((ROOT/"db/review/naruv_valuation_ci.sql").read_text())
            if not valuation.register_valuation(cls.app):raise RuntimeError("COST_DISABLED")
            from app import naruv_draft_review as drafts
            from scripts.naruv_draft_ci import seed,seed_confirmation_proofs
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("SELECT set_config('naruv.draft_ci','DISPOSABLE_ONLY',true)")
                c.execute((ROOT/"db/review/naruv_draft_ci.sql").read_text())
                seed(c)
            os.environ[drafts.FLAG]="ISOLATED_SYNTHETIC_ONLY"
            if not drafts.register_drafts(cls.app):raise RuntimeError("DRAFT_DISABLED")
            from app import naruv_hr_review as hr
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("SELECT set_config('naruv.hr_ci','DISPOSABLE_ONLY',true)")
                c.execute((ROOT/"db/review/naruv_hr_ci.sql").read_text())
                seed_confirmation_proofs(c)
            os.environ[hr.FLAG]="ISOLATED_SYNTHETIC_ONLY"
            if not hr.register_hr(cls.app):raise RuntimeError("HR_DISABLED")
        def setUp(self):
            super().setUp()
            os.environ["NARUV_VALUATION_REVIEW"]="ISOLATED_SYNTHETIC_ONLY"
        def seed_cost(self,who="A"):
            src="source-a" if who=="A" else "source-b"
            d=self.stage("stage-1",RAW,src,"item","csv",who)
            self.check(self.approve(d,"stage-1",who),200);self.check(self.commit(d,"stage-1","import-1",who),200)
        def receive(self,rid,item,qty,price,who="A",wh="W1",code=200,extra=None,raw=None):
            return self.check(self.call(f"/valuation/items/{item}/receive/{rid}",{"source_id":"source-a" if who=="A" else "source-b",
                "warehouse_id":wh,"quantity":qty,"unit_cost":price},who,extra,raw),code)
        def value(self,item="0001",who="A",wh="W1",code=200):
            src="source-a" if who=="A" else "source-b"
            r=self.check(self.call(f"/valuation/sources/{src}/items/{item}/stock/{wh}",who=who),code)
            if code!=200:return r
            self.assertIs(type(r["value_krw"]),str)
            return r["quantity"],int(r["value_krw"])
        def buy(self,doc,rid,item,qty,price,who="A",code=200):
            self.trade("open",rid+"-o",{"kind":"purchase","counterparty_id":"ci-customer-a" if who=="A" else "ci-customer-b",
                "source_id":"source-a" if who=="A" else "source-b","item_id":item,"warehouse_id":"W1","quantity":qty,"unit_price":price,"vat_mode":"taxable"},doc=doc,who=who)
            return self.trade("fulfill",rid+"-f",{"quantity":qty},doc=doc,who=who,code=code)
        def cost_counts(self):
            with psycopg.connect(fixture.root_dsn) as c:
                return c.execute("""SELECT (SELECT count(*) FROM naruv_inventory.movements),
                 (SELECT count(*) FROM naruv_valuation.entries),(SELECT coalesce(sum(value_krw),0) FROM naruv_valuation.balances)""").fetchone()
        def cost_entries(self,kind):
            with psycopg.connect(fixture.root_dsn) as c:
                return [int(x[0]) for x in c.execute("SELECT amount_krw FROM naruv_valuation.entries WHERE kind=%s ORDER BY amount_krw",(kind,)).fetchall()]
        def ready_cost_prod(self):
            self.seed_cost();self.receive("init-1","0001",10,101);self.receive("init-2","0002",10,51)
            self.define();self.open_job()
        def test_cost_purchase_moving_average_and_final_drain(self):
            self.seed_cost();self.buy("p1","r1","0001",3,100);self.buy("p2","r2","0001",2,201)
            self.assertEqual(self.value(),(5,702))
            self.manual("issue","0001","W1",None,2)
            self.assertEqual(self.value(),(3,421))
            self.manual("last","0001","W1",None,3)
            self.assertEqual(self.value(),(0,0))
            self.assertEqual(self.cost_entries("adjustment_issue"),[281,421])
            self.assertEqual(self.cost_counts(),(4,4,0))
        def test_cost_transfer_conserves_value_and_retry(self):
            self.seed_cost();self.receive("r1","0001",3,101);self.receive("r2","0001",1,102)
            r=self.manual("transfer","0001","W1","W2",2)
            self.assertEqual(self.value(),(2,202));self.assertEqual(self.value(wh="W2"),(2,203))
            self.assertEqual(self.manual("transfer","0001","W1","W2",2),r)
            self.assertEqual(self.cost_counts(),(3,3,405))
        def test_cost_production_material_and_output_conservation(self):
            self.ready_cost_prod();self.complete()
            self.assertEqual([self.value(i) for i in ("0001","0002","0003")],[(8,808),(9,459),(1,253)])
            self.complete(2,"c2")
            self.assertEqual([self.value(i) for i in ("0001","0002","0003")],[(4,404),(7,357),(3,759)])
            self.assertEqual(self.cost_entries("output"),[253,506])
            self.assertEqual(self.cost_counts(),(8,8,1520))
        def test_cost_sale_cost_and_billing_independent(self):
            self.ready_cost_prod();self.complete(3)
            q=self.quote(names=("Assembly",),qty=2)
            self.trade("open","sale-o",{"kind":"sale","quote_id":q["quote_id"],"source_id":"source-a","item_id":"0003","warehouse_id":"W1"},doc="sale")
            self.trade("fulfill","sale-f",{"quantity":2},doc="sale")
            self.assertEqual(self.value("0003"),(1,253));self.assertEqual(self.cost_entries("sale"),[506])
            bill=self.fin("bill","sale-b",{"doc_id":"sale","fulfillment_id":"sale-f"},bill="sale-b")
            self.assertEqual(bill["subtotal"],210);self.assertEqual(self.acct("sale-b")["ar"],231)
            self.assertEqual(self.cost_counts()[2],1014)
        def test_cost_opening_retry_zero_and_unpriced_denial(self):
            self.seed_cost();self.manual("unpriced","0001",None,"W1",2,code=422)
            r=self.receive("r1","0001",3,101)
            self.assertEqual(r["cost_krw"],"303")
            self.assertEqual(self.receive("r1","0001",3,101),r)
            self.receive("r1","0001",3,102,code=409)
            self.receive("free","0002",1,0);self.assertEqual(self.value("0002"),(1,0))
            self.manual("zero-issue","0002","W1",None,1)
            self.assertEqual(self.value("0002"),(0,0));self.assertEqual(self.cost_counts(),(3,3,303))
        def test_cost_output_failure_rolls_back_quantity_and_value(self):
            self.ready_cost_prod()
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("""CREATE FUNCTION naruv_valuation.fail_output() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN IF NEW.kind='output' THEN RAISE EXCEPTION 'SYNTHETIC_COST_FAILURE'; END IF; RETURN NEW; END $$""")
                c.execute("CREATE TRIGGER cost_fail BEFORE INSERT ON naruv_valuation.entries FOR EACH ROW EXECUTE FUNCTION naruv_valuation.fail_output()")
            try:
                self.complete(code=503);self.assertEqual(self.stocks(),[10,10,0])
                self.assertEqual(self.cost_counts(),(2,2,1520));self.assertEqual(self.inspect_job()["completed"],0)
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    c.execute("DROP TRIGGER cost_fail ON naruv_valuation.entries")
                    c.execute("DROP FUNCTION naruv_valuation.fail_output()")
            self.complete();self.assertEqual(self.value("0003"),(1,253))
        def test_cost_unposted_movement_rejected_at_commit(self):
            self.seed_cost()
            with psycopg.connect(fixture.root_dsn) as c:c.execute("ALTER TABLE naruv_trade.events DISABLE TRIGGER valuation_trade")
            try:
                self.buy("p1","r1","0001",3,100,code=503)
                self.assertEqual(self.value(),(0,0));self.assertEqual(self.cost_counts(),(0,0,0))
            finally:
                with psycopg.connect(fixture.root_dsn) as c:c.execute("ALTER TABLE naruv_trade.events ENABLE TRIGGER valuation_trade")
            self.trade("fulfill","r1-f",{"quantity":3},doc="p1")
            self.assertEqual(self.value(),(3,300))
        def test_cost_concurrent_issue_and_tenant_scope(self):
            self.seed_cost();self.receive("r1","0001",5,100);bar=threading.Barrier(2)
            def go(i):
                bar.wait(timeout=10)
                return self.call(f"/inventory/sources/source-a/items/0001/movements/issue-{i}",{"from_warehouse":"W1","to_warehouse":None,"quantity":4})
            with concurrent.futures.ThreadPoolExecutor(2) as pool:rs=list(pool.map(go,range(2)))
            self.assertEqual(sorted(r.status_code for r in rs),[200,409]);self.assertEqual(self.value(),(1,100))
            self.value(who="B",code=404)
            self.seed_cost("B");self.receive("r1","0001",2,200,"B")
            self.assertEqual(self.value(who="B"),(2,400));self.assertEqual(self.value(),(1,100))
        def test_cost_permissions_immutable_and_default_off(self):
            self.seed_cost();r=self.receive("r1","0001",3,101)
            self.manual(r["request_id"],"0001",None,"W1",3,code=422)
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertEqual(c.execute("SELECT count(*) FROM pg_class WHERE relnamespace='naruv_valuation'::regnamespace AND relkind='r' AND relrowsecurity AND relforcerowsecurity").fetchone()[0],3)
                for role in ("jw_app_dev","naruv_native_stage"):
                    self.assertEqual(c.execute("""SELECT has_table_privilege(%s,'naruv_valuation.balances','UPDATE'),
                     has_function_privilege(%s,'naruv_valuation.apply(text,text,text,text,numeric)','EXECUTE'),
                     has_function_privilege(%s,'naruv_valuation.receive(text,text,jsonb,boolean,text)','EXECUTE')""",(role,role,role)).fetchone(),(False,False,role=="jw_app_dev"))
                with self.assertRaisesRegex(psycopg.Error,"NARUV_IMMUTABLE"):c.execute("UPDATE naruv_valuation.entries SET amount_krw=0")
                c.rollback()
            os.environ.pop("NARUV_VALUATION_REVIEW",None)
            self.assertFalse(valuation.register_valuation(FastAPI()));self.value(code=404)
        def test_cost_large_exact_integer_and_strict_input(self):
            self.seed_cost()
            for price in (-1,True,1.5,1000000001):self.receive("bad","0001",1,price,code=422)
            self.receive("bad","0001",1,1,extra={"x-naruv-confirm":"no"},code=422)
            self.receive("bad","0001",1,1,raw=b'{"unit_cost":1,"unit_cost":2}',code=422)
            self.receive("huge","0001",1000000000,1000000000)
            self.assertEqual(self.value(),(1000000000,1000000000000000000))
            self.manual("huge-issue","0001","W1",None,999999999)
            self.assertEqual(self.value(),(1,1000000000))
        def reconcile(self,bill,who="A",code=200):
            return self.check(self.call(f"/valuation/bills/{bill}/reconcile",who=who),code)
        def test_cost_reconcile_purchase_and_payment(self):
            self.seed_cost();self.buy("p1","r1","0001",3,101)
            self.fin("bill","bill-r",{"doc_id":"p1","fulfillment_id":"r1-f"},bill="bill")
            before=self.cost_counts()
            r=self.reconcile("bill")
            self.assertEqual((r["net_krw"],r["inventory_cost_krw"],r["purchase_clearing_difference_krw"],r["sales_margin_krw"]),("303","303","0",None))
            self.assertEqual(r["outstanding_krw"],"333")
            self.fin("pay","pay-r",{"amount":100,"reference":"p-ref"},bill="bill")
            self.assertEqual(self.reconcile("bill")["outstanding_krw"],"233")
            self.fin("reverse","rev-r",{"payment_request_id":"pay-r"},bill="bill")
            self.assertEqual(self.reconcile("bill"),r)
            self.assertEqual(self.cost_counts(),before)
        def test_cost_reconcile_sale_negative_margin(self):
            self.ready_cost_prod();self.complete(3)
            q=self.quote(names=("Assembly",),qty=2)
            self.trade("open","sale-o",{"kind":"sale","quote_id":q["quote_id"],"source_id":"source-a","item_id":"0003","warehouse_id":"W1"},doc="sale")
            self.trade("fulfill","sale-f",{"quantity":2},doc="sale")
            self.fin("bill","sale-b",{"doc_id":"sale","fulfillment_id":"sale-f"},bill="sale-b")
            r=self.reconcile("sale-b")
            self.assertEqual((r["net_krw"],r["inventory_cost_krw"],r["sales_margin_krw"]),("210","506","-296"))
            self.assertIsNone(r["purchase_clearing_difference_krw"])
            self.assertFalse(r["statutory_posted"])
        def test_cost_reconcile_tenant_and_default_off(self):
            self.seed_cost();self.buy("p1","r1","0001",1,100)
            self.fin("bill","bill-r",{"doc_id":"p1","fulfillment_id":"r1-f"},bill="bill")
            self.reconcile("bill",who="B",code=404)
            self.reconcile("missing",code=404)
            self.reconcile("bill")
            os.environ.pop("NARUV_VALUATION_REVIEW",None)
            self.reconcile("bill",code=404)
        def test_cost_reconcile_inconsistent_cost_fails_closed(self):
            self.seed_cost();self.buy("p1","r1","0001",3,100)
            self.fin("bill","bill-r",{"doc_id":"p1","fulfillment_id":"r1-f"},bill="bill")
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("ALTER TABLE naruv_valuation.entries DISABLE TRIGGER cost_entries_immutable")
                c.execute("UPDATE naruv_valuation.entries SET amount_krw=299 WHERE kind='purchase'")
                c.execute("ALTER TABLE naruv_valuation.entries ENABLE TRIGGER cost_entries_immutable")
            try:
                self.reconcile("bill",code=503)
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    c.execute("ALTER TABLE naruv_valuation.entries DISABLE TRIGGER cost_entries_immutable")
                    c.execute("UPDATE naruv_valuation.entries SET amount_krw=300 WHERE kind='purchase'")
                    c.execute("ALTER TABLE naruv_valuation.entries ENABLE TRIGGER cost_entries_immutable")
            self.assertEqual(self.reconcile("bill")["purchase_clearing_difference_krw"],"0")
        def posting(self):
            with psycopg.connect(fixture.root_dsn) as c:
                return sorted((d or "",cr or "",int(a)) for d,cr,a in c.execute(
                    "SELECT debit_account,credit_account,amount_krw FROM naruv_valuation.cost_journals").fetchall())
        def test_cost_journal_purchase_sale_and_clearing(self):
            self.seed_cost();self.buy("p1","r1","0003",3,101)
            self.fin("bill","bill-r",{"doc_id":"p1","fulfillment_id":"r1-f"},bill="bill")
            self.assertTrue(self.reconcile("bill")["cost_journal_posted"])
            q=self.quote(names=("Assembly",),qty=2)
            self.trade("open","sale-o",{"kind":"sale","quote_id":q["quote_id"],"source_id":"source-a","item_id":"0003","warehouse_id":"W1"},doc="sale")
            self.trade("fulfill","sale-f",{"quantity":2},doc="sale")
            self.fin("bill","sale-b",{"doc_id":"sale","fulfillment_id":"sale-f"},bill="sale-b")
            self.assertEqual(self.posting(),[("COGS","INVENTORY",202),("INVENTORY","PURCHASE_CLEARING",303)])
            self.assertEqual(self.reconcile("sale-b")["sales_margin_krw"],"8")
            self.assertEqual(self.value("0003"),(1,101))
        def test_cost_journal_production_transfer_and_zero(self):
            self.ready_cost_prod();self.complete()
            self.manual("move","0003","W1","W2",1)
            self.receive("free","0001",1,0)
            self.assertEqual(self.posting(),sorted([("INVENTORY","OPENING_EQUITY",1010),("INVENTORY","OPENING_EQUITY",510),
                ("WIP","INVENTORY",202),("WIP","INVENTORY",51),("INVENTORY","WIP",253),("","",0),("","",0)]))
        def test_cost_journal_closed_period_and_retry(self):
            self.seed_cost();r=self.receive("opening","0001",3,100);self.close()
            self.assertEqual(self.receive("opening","0001",3,100),r)
            self.receive("new","0001",1,100,code=409)
            self.manual("issue","0001","W1",None,1,code=409)
            self.assertEqual(self.value(),(3,300))
            self.assertEqual(self.posting(),[("INVENTORY","OPENING_EQUITY",300)])
            self.seed_cost("B");self.receive("opening","0001",1,5,"B")
            self.assertEqual(self.value(who="B"),(1,5))
        def test_cost_journal_close_race(self):
            self.seed_cost();bar=threading.Barrier(2)
            def go(i):
                bar.wait(timeout=10)
                if i==0:return self.call(f"/accounting/periods/{self.month}/close")
                return self.call("/valuation/items/0001/receive/race",{"source_id":"source-a","warehouse_id":"W1","quantity":1,"unit_cost":100})
            with concurrent.futures.ThreadPoolExecutor(2) as pool:rs=list(pool.map(go,range(2)))
            self.assertEqual(rs[0].status_code,200);self.assertIn(rs[1].status_code,(200,409))
            self.assertEqual(self.value(),(1,100) if rs[1].status_code==200 else (0,0))
            self.receive("late","0001",1,100,code=409)
        def test_cost_journal_missing_rollback(self):
            self.seed_cost()
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("ALTER TABLE naruv_valuation.entries DISABLE TRIGGER cost_journal_post")
            try:
                self.receive("opening","0001",3,100,code=503)
                self.assertEqual(self.cost_counts(),(0,0,0));self.assertEqual(self.posting(),[])
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    c.execute("ALTER TABLE naruv_valuation.entries ENABLE TRIGGER cost_journal_post")
            self.receive("opening","0001",3,100)
            self.assertEqual(self.posting(),[("INVENTORY","OPENING_EQUITY",300)])
        def test_cost_journal_cancel_preserves_fulfilled(self):
            self.seed_cost()
            self.trade("open","open-p",{"kind":"purchase","counterparty_id":"ci-customer-a","source_id":"source-a",
                "item_id":"0001","warehouse_id":"W1","quantity":5,"unit_price":100,"vat_mode":"taxable"},doc="p1")
            self.trade("fulfill","receipt",{"quantity":2},doc="p1")
            self.fin("bill","bill-r",{"doc_id":"p1","fulfillment_id":"receipt"},bill="bill")
            before=self.reconcile("bill");posting=self.posting()
            self.trade("cancel","cancel-p",{},doc="p1")
            self.assertEqual(self.reconcile("bill"),before);self.assertEqual(self.posting(),posting)
            self.assertEqual(self.value(),(2,200))
            self.trade("fulfill","late",{"quantity":1},doc="p1",code=409)
        def test_cost_journal_direct_access_denied(self):
            self.seed_cost();self.receive("r1","0001",1,5)
            with psycopg.connect(fixture.root_dsn) as c:
                for role in ("jw_app_dev","naruv_native_stage"):
                    for privilege in ("SELECT","INSERT","UPDATE","DELETE"):
                        self.assertFalse(c.execute("SELECT has_table_privilege(%s,'naruv_valuation.cost_journals',%s)",(role,privilege)).fetchone()[0])
                with self.assertRaisesRegex(psycopg.Error,"NARUV_IMMUTABLE"):
                    c.execute("UPDATE naruv_valuation.cost_journals SET amount_krw=1")
                c.rollback()
        def return_bill(self,bill="bill",rid="return",who="A",code=200,extra=None):
            return self.check(self.call(f"/valuation/bills/{bill}/return/{rid}",who=who,extra=extra),code)
        def billed_purchase(self):
            self.seed_cost();self.buy("p1","r1","0001",3,101)
            return self.fin("bill","bill-r",{"doc_id":"p1","fulfillment_id":"r1-f"},bill="bill")
        def test_cost_return_purchase_credit_and_retry(self):
            self.billed_purchase()
            r=self.return_bill()
            self.assertEqual((r["credited"],r["outstanding"],r["returned_cost_krw"]),(333,0,"303"))
            self.assertEqual(self.return_bill(),r)
            self.return_bill(rid="duplicate",code=409)
            self.assertEqual(self.value(),(0,0))
            self.assertEqual(self.reconcile("bill")["net_krw"],"0")
            self.assertEqual(self.acct("bill")["ap"],0)
            self.assertEqual(self.inspect("bill")["state"],"CREDITED")
            self.fin("pay","later",{"amount":1,"reference":"ref"},bill="bill",code=409)
        def test_cost_return_sale_restores_original_cost(self):
            self.ready_cost_prod();self.complete(3)
            q=self.quote(names=("Assembly",),qty=2)
            self.trade("open","sale-o",{"kind":"sale","quote_id":q["quote_id"],"source_id":"source-a","item_id":"0003","warehouse_id":"W1"},doc="sale")
            self.trade("fulfill","sale-f",{"quantity":2},doc="sale")
            self.fin("bill","sale-b",{"doc_id":"sale","fulfillment_id":"sale-f"},bill="sale-b")
            r=self.return_bill("sale-b")
            self.assertEqual((r["credited"],r["returned_cost_krw"]),(231,"506"))
            self.assertEqual(self.value("0003"),(3,759))
            self.assertEqual(self.reconcile("sale-b")["sales_margin_krw"],"0")
            self.assertEqual(self.acct("sale-b")["ar"],0)
        def test_cost_return_paid_tenant_and_confirm(self):
            self.billed_purchase()
            self.return_bill(who="B",code=404)
            self.return_bill(extra={"x-naruv-confirm":"no"},code=422)
            self.fin("pay","pay",{"amount":1,"reference":"ref"},bill="bill")
            self.return_bill(code=409)
            self.assertEqual(self.value(),(3,303))
        def test_cost_return_purchase_changed_average_rollback(self):
            self.billed_purchase();self.receive("other","0001",3,201)
            before=self.cost_counts()
            self.return_bill(code=409)
            self.assertEqual(self.value(),(6,906))
            self.assertEqual(self.cost_counts(),before)
            self.assertEqual(self.acct("bill")["ap"],333)
        def test_cost_return_closed_and_race(self):
            self.billed_purchase();bar=threading.Barrier(2)
            def go(i):
                bar.wait(timeout=10)
                if i==0:return self.call(f"/accounting/periods/{self.month}/close")
                return self.call("/valuation/bills/bill/return/return")
            with concurrent.futures.ThreadPoolExecutor(2) as pool:rs=list(pool.map(go,range(2)))
            self.assertEqual(rs[0].status_code,200);self.assertIn(rs[1].status_code,(200,409))
            self.assertEqual(self.value(),(0,0) if rs[1].status_code==200 else (3,303))
            self.return_bill(rid="late",code=409)
        def test_cost_return_credit_failure_rollback(self):
            self.billed_purchase()
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("""CREATE FUNCTION naruv_finance.fail_credit() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN IF NEW.action='credit' THEN RAISE EXCEPTION 'SYNTHETIC_CREDIT_FAILURE'; END IF; RETURN NEW; END $$""")
                c.execute("CREATE TRIGGER fail_credit BEFORE INSERT ON naruv_finance.events FOR EACH ROW EXECUTE FUNCTION naruv_finance.fail_credit()")
            try:
                self.return_bill(code=503);self.assertEqual(self.value(),(3,303))
                self.assertEqual(self.acct("bill")["ap"],333)
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    c.execute("DROP TRIGGER fail_credit ON naruv_finance.events")
                    c.execute("DROP FUNCTION naruv_finance.fail_credit()")
            self.return_bill()
        def audit_ledger(self,who="A",code=200):
            return self.check(self.call("/valuation/audit",who=who),code)
        def test_cost_audit_integrated_tenant_returns(self):
            self.billed_purchase()
            self.assertEqual(self.audit_ledger()["inventory_krw"],"303")
            self.return_bill()
            a=self.audit_ledger();self.assertEqual((a["inventory_krw"],a["journal_inventory_krw"],a["wip_krw"],a["bill_count"]),("0","0","0",1))
            self.seed_cost("B");self.receive("other","0001",2,25,"B")
            self.assertEqual(self.audit_ledger("B")["inventory_krw"],"50")
            self.assertEqual(self.audit_ledger(),a)
        def test_cost_audit_detects_balance_tampering(self):
            self.billed_purchase()
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("UPDATE naruv_valuation.balances SET value_krw=value_krw+1 WHERE org_id='ci-a'")
            try:self.audit_ledger(code=503)
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    c.execute("UPDATE naruv_valuation.balances SET value_krw=value_krw-1 WHERE org_id='ci-a'")
            self.assertEqual(self.audit_ledger()["status"],"RECONCILED")
        def test_cost_audit_production_transfer(self):
            self.ready_cost_prod();self.complete(3);self.manual("transfer","0003","W1","W2",1)
            a=self.audit_ledger()
            self.assertEqual((a["inventory_krw"],a["journal_inventory_krw"],a["wip_krw"]),("1520","1520","0"))
        def test_cost_return_payment_race_and_reconnect(self):
            self.billed_purchase();bar=threading.Barrier(2)
            def go(i):
                bar.wait(timeout=10)
                if i==0:return self.call("/valuation/bills/bill/return/return")
                return self.call("/finance/bills/bill/commands/pay/pay",{"amount":1,"reference":"race"})
            with concurrent.futures.ThreadPoolExecutor(2) as pool:rs=list(pool.map(go,range(2)))
            self.assertEqual(sorted(r.status_code for r in rs),[200,409])
            if rs[0].status_code==200:
                self.assertEqual(self.return_bill()["state"],"CREDITED");self.assertEqual(self.value(),(0,0))
            else:
                self.assertEqual(self.inspect("bill")["paid"],1);self.assertEqual(self.value(),(3,303))
            self.assertEqual(self.audit_ledger()["status"],"RECONCILED")
        def test_cost_audit_detects_cross_warehouse_value_shift(self):
            self.seed_cost();self.receive("opening","0001",4,100)
            self.manual("transfer","0001","W1","W2",2)
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("UPDATE naruv_valuation.balances SET value_krw=value_krw+CASE WHEN warehouse_id='W1' THEN 1 ELSE -1 END WHERE org_id='ci-a'")
            try:self.audit_ledger(code=503)
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    c.execute("UPDATE naruv_valuation.balances SET value_krw=value_krw-CASE WHEN warehouse_id='W1' THEN 1 ELSE -1 END WHERE org_id='ci-a'")
            self.assertEqual(self.audit_ledger()["inventory_krw"],"400")
        def partial_return(self,rid,qty,bill="bill",code=200,who="A"):
            return self.check(self.call(f"/valuation/bills/{bill}/return/{rid}/quantity/{qty}",who=who),code)
        def test_cost_partial_purchase_rounding_and_retry(self):
            self.billed_purchase()
            r=self.partial_return("p1",1)
            self.assertEqual((r["credited"],r["outstanding"],r["returned_cost_krw"]),(111,222,"101"))
            self.assertEqual(self.partial_return("p1",1),r)
            self.partial_return("p1",2,code=409)
            self.partial_return("p2",1);r=self.partial_return("p3",1)
            self.assertEqual((r["credited"],r["state"]),(333,"CREDITED"))
            self.assertEqual(self.value(),(0,0));self.assertEqual(self.acct("bill")["ap"],0)
            self.partial_return("over",1,code=409);self.assertEqual(self.audit_ledger()["status"],"RECONCILED")
        def test_cost_partial_paid_credit_ceiling(self):
            self.billed_purchase();self.fin("pay","pay",{"amount":100,"reference":"ref"},bill="bill")
            self.partial_return("too-many",3,code=409)
            self.partial_return("p1",1);self.partial_return("p2",1)
            self.assertEqual(self.inspect("bill")["outstanding"],11)
            self.fin("pay","over",{"amount":12,"reference":"ref2"},bill="bill",code=409)
            self.fin("pay","rest",{"amount":11,"reference":"ref2"},bill="bill")
            self.assertEqual(self.inspect("bill")["state"],"SETTLED")
            self.partial_return("refund-required",1,code=409)
            self.assertEqual(self.audit_ledger()["status"],"RECONCILED")
        def test_cost_partial_sale_exact_original_cost(self):
            self.ready_cost_prod();self.complete(3)
            q=self.quote(names=("Assembly",),qty=2)
            self.trade("open","sale-o",{"kind":"sale","quote_id":q["quote_id"],"source_id":"source-a","item_id":"0003","warehouse_id":"W1"},doc="sale")
            self.trade("fulfill","sale-f",{"quantity":2},doc="sale")
            self.fin("bill","sale-b",{"doc_id":"sale","fulfillment_id":"sale-f"},bill="sale-b")
            r=self.partial_return("r1",1,"sale-b")
            self.assertEqual((r["credited"],r["returned_cost_krw"]),(116,"253"))
            self.assertEqual(self.reconcile("sale-b")["sales_margin_krw"],"-148")
            self.partial_return("r2",1,"sale-b")
            self.assertEqual(self.value("0003"),(3,759));self.assertEqual(self.acct("sale-b")["ar"],0)
        def test_cost_partial_concurrent_and_invalid(self):
            self.billed_purchase();self.partial_return("bad",0,code=422)
            self.partial_return("bad","1.5",code=422);self.partial_return("bad",1,code=404,who="B")
            bar=threading.Barrier(2)
            def go(i):
                bar.wait(timeout=10)
                return self.call(f"/valuation/bills/bill/return/r-{i}/quantity/2")
            with concurrent.futures.ThreadPoolExecutor(2) as pool:rs=list(pool.map(go,range(2)))
            self.assertEqual(sorted(r.status_code for r in rs),[200,409])
            self.assertEqual(self.value(),(1,101));self.assertEqual(self.audit_ledger()["status"],"RECONCILED")
        def adjusted_return(self,rid,qty,ref=None,bill="bill",who="A",code=200):
            return self.check(self.call(f"/valuation/bills/{bill}/return/{rid}/quantity/{qty}/adjusted",
                {} if ref is None else {"refund_reference":ref},who=who),code)
        def test_cost_adjusted_paid_purchase_refund(self):
            self.billed_purchase();self.fin("pay","pay",{"amount":333,"reference":"p-ref"},bill="bill")
            self.adjusted_return("r",3,code=409)
            r=self.adjusted_return("r",3,"refund-ref")
            self.assertEqual((r["refund_recorded_krw"],r["paid"],r["state"]),("333",0,"CREDITED"))
            self.assertFalse(r["external_transfer_executed"])
            self.assertEqual(self.adjusted_return("r",3,"refund-ref"),r)
            self.adjusted_return("r",3,"different",code=409)
            self.assertEqual(self.value(),(0,0));self.assertEqual(self.acct("bill")["ap"],0)
            self.assertEqual(self.audit_ledger()["status"],"RECONCILED")
        def test_cost_adjusted_purchase_variance_both_signs(self):
            self.billed_purchase();self.receive("other","0001",3,201)
            r=self.adjusted_return("r",3)
            self.assertEqual((r["returned_cost_krw"],r["purchase_cost_variance_krw"]),("453","-150"))
            self.assertEqual(self.value(),(3,453));self.assertEqual(self.reconcile("bill")["purchase_clearing_difference_krw"],"0")
            self.buy("p2","r2","0001",3,201)
            self.fin("bill","bill-r2",{"doc_id":"p2","fulfillment_id":"r2-f"},bill="bill2")
            r=self.adjusted_return("r2",3,bill="bill2")
            self.assertEqual((r["returned_cost_krw"],r["purchase_cost_variance_krw"]),("528","75"))
            self.assertEqual(self.value(),(3,528));self.assertEqual(self.audit_ledger()["status"],"RECONCILED")
        def test_cost_adjusted_sale_refund_partial(self):
            self.ready_cost_prod();self.complete(3)
            q=self.quote(names=("Assembly",),qty=2)
            self.trade("open","sale-o",{"kind":"sale","quote_id":q["quote_id"],"source_id":"source-a","item_id":"0003","warehouse_id":"W1"},doc="sale")
            self.trade("fulfill","sale-f",{"quantity":2},doc="sale")
            self.fin("bill","sale-b",{"doc_id":"sale","fulfillment_id":"sale-f"},bill="sale-b")
            self.fin("pay","sale-pay",{"amount":200,"reference":"sale-pay"},bill="sale-b")
            r=self.adjusted_return("r",1,"sale-refund",bill="sale-b")
            self.assertEqual((r["refund_recorded_krw"],r["paid"],r["outstanding"]),("85",115,0))
            self.assertEqual(self.reconcile("sale-b")["sales_margin_krw"],"-148")
            self.fin("reverse","unsafe",{"payment_request_id":"sale-pay"},bill="sale-b",code=409)
            self.assertEqual(self.audit_ledger()["status"],"RECONCILED")
        def test_cost_adjusted_duplicate_reference_and_rollback(self):
            self.billed_purchase();self.fin("pay","pay",{"amount":333,"reference":"same"},bill="bill")
            self.adjusted_return("r",3,"same",code=409)
            self.adjusted_return("r",3,"other",who="B",code=404)
            self.assertEqual(self.value(),(3,303));self.assertEqual(self.inspect("bill")["paid"],333)
            self.close();self.adjusted_return("r",3,"other",code=409)
            self.assertEqual(self.value(),(3,303));self.assertEqual(self.audit_ledger()["status"],"RECONCILED")
        def test_cost_integrated_independent_restore(self):
            from scripts.naruv_erp_restore_ci import prove_restore
            self.billed_purchase();self.receive("other","0001",3,201)
            self.fin("pay","paid",{"amount":333,"reference":"paid-ref"},bill="bill")
            self.adjusted_return("r",3,"refund-ref")
            self.seed_cost("B");self.receive("opening","0001",1,25,"B")
            self.assertEqual(self.audit_ledger()["inventory_krw"],"453")
            self.assertEqual(self.audit_ledger("B")["inventory_krw"],"25")
            proof=prove_restore(fixture.root_dsn)
            self.assertGreater(proof["tables"],10)
            self.assertEqual(proof["distinct_clusters"],True)
            self.assertEqual(self.audit_ledger()["inventory_krw"],"453")
        def test_cost_adjusted_audit_detects_balanced_wrong_account(self):
            self.billed_purchase();self.receive("other","0001",3,201)
            self.fin("pay","paid",{"amount":333,"reference":"paid-ref"},bill="bill")
            self.adjusted_return("r",3,"refund-ref")
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("ALTER TABLE naruv_accounting.lines DISABLE TRIGGER lines_immutable")
                c.execute("UPDATE naruv_accounting.lines SET account='CASH_CLEARING' WHERE account='PURCHASE_COST_VARIANCE'")
                c.execute("ALTER TABLE naruv_accounting.lines ENABLE TRIGGER lines_immutable")
            try:self.audit_ledger(code=503)
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    c.execute("ALTER TABLE naruv_accounting.lines DISABLE TRIGGER lines_immutable")
                    c.execute("UPDATE naruv_accounting.lines SET account='PURCHASE_COST_VARIANCE' WHERE event_id='r' AND line_no=5")
                    c.execute("ALTER TABLE naruv_accounting.lines ENABLE TRIGGER lines_immutable")
            self.assertEqual(self.audit_ledger()["status"],"RECONCILED")
        def test_cost_overview_actual_tenant_totals(self):
            self.billed_purchase()
            self.fin("pay","paid",{"amount":100,"reference":"paid-ref"},bill="bill")
            self.partial_return("partial",1)
            a=self.check(self.call("/valuation/overview"),200)
            self.assertEqual((a["inventory_krw"],a["payable_krw"],a["purchase_paid_krw"]),("202","122","100"))
            self.assertEqual((a["sales_bill_count"],a["purchase_bill_count"],a["item_count"]),(0,1,3))
            self.seed_cost("B");self.receive("other","0001",2,25,"B")
            b=self.check(self.call("/valuation/overview",who="B"),200)
            self.assertEqual((b["inventory_krw"],b["payable_krw"],b["purchase_bill_count"]),("50","0",0))
            self.assertEqual(self.check(self.call("/valuation/overview"),200),a)
        def test_cost_overview_default_off_and_fail_closed(self):
            self.billed_purchase()
            self.check(self.call("/valuation/overview",extra={"origin":"https://evil.test"}),403)
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("UPDATE naruv_valuation.balances SET value_krw=value_krw+1 WHERE org_id='ci-a'")
            try:self.check(self.call("/valuation/overview"),503)
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    c.execute("UPDATE naruv_valuation.balances SET value_krw=value_krw-1 WHERE org_id='ci-a'")
            self.check(self.call("/valuation/overview"),200)
            os.environ.pop("NARUV_VALUATION_REVIEW",None)
            self.check(self.call("/valuation/overview"),404)
        def test_cost_integrated_router_purchase_refund_and_overview(self):
            from app import naruv_integrated_review as integrated
            from unittest.mock import patch
            with patch.dict(os.environ,{integrated.FLAG:integrated.ACK}):
                self.app=FastAPI()
                self.assertTrue(integrated.register_integrated_review(self.app))
                self.billed_purchase();self.receive("other","0001",3,201)
                self.fin("pay","paid",{"amount":333,"reference":"paid-ref"},bill="bill")
                result=self.adjusted_return("r",3,"refund-ref")
                self.assertEqual((result["refund_recorded_krw"],result["purchase_cost_variance_krw"]),("333","-150"))
                self.assertEqual(self.adjusted_return("r",3,"refund-ref"),result)
                a=self.check(self.call("/valuation/overview"),200)
                self.assertEqual((a["inventory_krw"],a["payable_krw"],a["purchase_paid_krw"]),("453","0","0"))
                self.seed_cost("B");self.receive("other","0001",2,25,"B")
                b=self.check(self.call("/valuation/overview",who="B"),200)
                self.assertEqual((b["inventory_krw"],b["purchase_bill_count"]),("50",0))
                self.reconcile("bill",who="B",code=404)
                self.assertEqual(self.check(self.call("/valuation/overview"),200),a)
        def test_cost_integrated_router_runtime_shutdown(self):
            from app import naruv_integrated_review as integrated
            from unittest.mock import patch
            with patch.dict(os.environ,{integrated.FLAG:integrated.ACK}):
                self.app=FastAPI()
                self.assertTrue(integrated.register_integrated_review(self.app))
                self.billed_purchase()
                before=self.value()
                with patch.dict(os.environ,{integrated.FLAG:""}):
                    self.check(self.call("/valuation/overview"),404)
                    self.adjusted_return("blocked",1,code=404)
                self.assertEqual(self.value(),before)
                self.check(self.call("/valuation/overview",extra={"origin":"https://evil.test"}),403)
                self.check(self.call("/valuation/overview"),200)
        def test_cost_draft_server_owned_sources(self):
            a=self.check(self.call("/drafts/documents/shared"),200)
            b=self.check(self.call("/drafts/documents/shared",who="B"),200)
            self.assertNotEqual(a["source_sha256"],b["source_sha256"])
            self.assertNotEqual(a["source_binding_sha256"],b["source_binding_sha256"])
            self.assertFalse(a["posting_authorized"]);self.assertFalse(a["persisted"])
            self.assertEqual(self.check(self.call("/drafts/payroll/worker-1/2026-11"),200)["gross_krw"],114000)
            self.assertEqual(self.check(self.call("/drafts/payroll/worker-1/2026-11",who="B"),200)["gross_krw"],171000)
            self.check(self.call("/drafts/payroll/worker-1/2026-11",{"hourly_krw":1}),413)
            self.check(self.call("/drafts/documents/shared",{"registered_sha256":"x"}),413)
        def test_cost_draft_auth_and_scope(self):
            self.check(self.call("/drafts/documents/shared",extra={"origin":"https://evil.test"}),403)
            self.check(self.call("/drafts/documents/shared",extra={"x-csrf-token":"wrong"}),403)
            self.check(self.call("/drafts/documents/missing"),404)
            self.check(self.call("/drafts/payroll/worker-1/2026-13"),422)
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("UPDATE jw_dev.users SET role='member' WHERE id='ci-ua'")
            try:self.check(self.call("/drafts/payroll/worker-1/2026-11"),403)
            finally:
                with psycopg.connect(fixture.root_dsn) as c:c.execute("UPDATE jw_dev.users SET role='admin' WHERE id='ci-ua'")
        def test_cost_draft_changed_source_and_unconfirmed_pay(self):
            with psycopg.connect(fixture.root_dsn) as c:
                before=c.execute("SELECT org_id,worker_id,period,confirmed FROM naruv_draft.pay_periods ORDER BY 1,2,3").fetchall()
                self.assertEqual(c.execute("UPDATE naruv_draft.documents SET original_sha256=repeat('0',64) WHERE org_id='ci-a' AND document_id='shared'").rowcount,1)
                self.assertEqual(c.execute("UPDATE naruv_draft.pay_periods SET confirmed=false WHERE org_id='ci-a' AND worker_id='worker-1' AND period='2026-11' AND confirmed").rowcount,1)
            try:
                self.check(self.call("/drafts/documents/shared"),409)
                self.check(self.call("/drafts/payroll/worker-1/2026-11"),404)
                self.check(self.call("/drafts/documents/shared",who="B"),200)
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    self.assertEqual(c.execute("UPDATE naruv_draft.documents SET original_sha256=encode(sha256(original_bytes),'hex') WHERE org_id='ci-a' AND document_id='shared'").rowcount,1)
                    self.assertEqual(c.execute("UPDATE naruv_draft.pay_periods SET confirmed=true WHERE org_id='ci-a' AND worker_id='worker-1' AND period='2026-11' AND NOT confirmed").rowcount,1)
                    self.assertEqual(c.execute("SELECT org_id,worker_id,period,confirmed FROM naruv_draft.pay_periods ORDER BY 1,2,3").fetchall(),before)
        def test_cost_draft_direct_access_and_disable(self):
            from unittest.mock import patch
            from app import naruv_draft_review as drafts
            with psycopg.connect(fixture.root_dsn) as c:
                for table in ("documents","staff","pay_periods","attendance"):
                    self.assertFalse(c.execute("SELECT has_table_privilege('jw_app_dev',%s,'SELECT')",("naruv_draft."+table,)).fetchone()[0])
                    self.assertTrue(c.execute("SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid=%s::regclass",("naruv_draft."+table,)).fetchone()[0])
            with patch.dict(os.environ,{drafts.FLAG:""}):
                self.check(self.call("/drafts/documents/shared"),404)
            self.check(self.call("/drafts/documents/shared"),200)
        def test_cost_full_router_erp_and_drafts_same_tenant(self):
            from app import naruv_integrated_review as integrated
            from unittest.mock import patch
            with patch.dict(os.environ,{integrated.FLAG:integrated.ACK,integrated.drafts.FLAG:integrated.ACK}):
                self.app=FastAPI()
                self.assertTrue(integrated.register_integrated_review(self.app,include_drafts=True))
                self.billed_purchase()
                before=self.check(self.call("/valuation/overview"),200)
                self.assertEqual(self.check(self.call("/drafts/payroll/worker-1/2026-11"),200)["gross_krw"],114000)
                self.assertEqual(self.check(self.call("/drafts/payroll/worker-1/2026-11",who="B"),200)["gross_krw"],171000)
                self.assertFalse(self.check(self.call("/drafts/documents/shared"),200)["posting_authorized"])
                self.assertEqual(self.check(self.call("/valuation/overview"),200),before)
                with patch.dict(os.environ,{integrated.FLAG:""}):
                    self.check(self.call("/drafts/documents/shared"),404)
                    self.check(self.call("/drafts/payroll/worker-1/2026-11"),404)
                self.assertEqual(self.check(self.call("/valuation/overview"),200),before)
        def test_cost_full_router_draft_gate_and_direct_sql_boundary(self):
            from app import naruv_integrated_review as integrated
            from unittest.mock import patch
            with patch.dict(os.environ,{integrated.FLAG:integrated.ACK,integrated.drafts.FLAG:integrated.ACK}):
                self.app=FastAPI()
                self.assertTrue(integrated.register_integrated_review(self.app,include_drafts=True))
                with patch.dict(os.environ,{integrated.drafts.FLAG:""}):
                    self.check(self.call("/valuation/overview"),404)
                    self.check(self.call("/drafts/documents/shared"),404)
                self.check(self.call("/drafts/documents/shared"),200)
                self.check(self.call("/drafts/payroll/worker-1/2026-11",extra={"origin":"https://evil.test"}),403)
                with psycopg.connect(fixture.root_dsn) as c:
                    for role in ("naruv_native_stage","public"):
                        for fn in ("naruv_draft.document_source(text,text)","naruv_draft.pay_source(text,text,text)"):
                            if role=="public":
                                self.assertFalse(c.execute("SELECT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE p.oid=%s::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE')",(fn,)).fetchone()[0])
                            else:
                                self.assertFalse(c.execute("SELECT has_function_privilege(%s,%s,'EXECUTE')",(role,fn)).fetchone()[0])
        def hr_admit(self,rid,day="2026-10-01",who="A",code=200,period="2026-10",worker="worker-1",a=480,b=60,extra=None):
            return self.check(self.call(f"/hr/workers/{worker}/periods/{period}/attendance/{rid}",{"date":day,"regular":a,"additional":b},who,extra),code)
        def test_cost_hr_attendance_exact_retry_and_tenant(self):
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertEqual(c.execute("SELECT org_id,period,confirmed FROM naruv_draft.pay_periods WHERE worker_id='worker-1' AND period IN ('2026-10','2026-11') ORDER BY 1,2").fetchall(),
                    [("ci-a","2026-10",False),("ci-a","2026-11",True),("ci-b","2026-10",False),("ci-b","2026-11",True)])
            first=self.hr_admit("hr-1")
            self.assertEqual(first,self.hr_admit("hr-1"))
            self.assertFalse(first["payment_authorized"])
            self.hr_admit("hr-1",a=481,code=409)
            self.hr_admit("hr-duplicate",code=409)
            self.assertEqual(self.hr_admit("hr-1",who="B",a=300)["regular"],300)
            self.check(self.call("/drafts/payroll/worker-1/2026-10"),404)
            self.assertEqual(self.check(self.call("/drafts/payroll/worker-1/2026-11"),200)["gross_krw"],114000)
        def test_cost_hr_confirmed_and_invalid(self):
            self.hr_admit("hr-closed",day="2026-11-26",period="2026-11",code=409)
            self.hr_admit("hr-bad-date",day="2026-10-32",code=422)
            self.hr_admit("hr-bad-minutes",a=1440,b=1,code=422)
            self.hr_admit("hr-no-worker",worker="missing",code=404)
            self.hr_admit("hr-no-confirm",extra={"x-naruv-confirm":"no"},code=422)
            self.hr_admit("hr-origin",extra={"origin":"https://evil.test"},code=403)
        def test_cost_hr_concurrent_idempotency(self):
            import concurrent.futures
            barrier=threading.Barrier(3)
            def submit(_):
                barrier.wait(timeout=10)
                return self.hr_admit("hr-parallel",day="2026-10-02")
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                results=list(pool.map(submit,range(3)))
            self.assertTrue(all(r==results[0] for r in results))
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertEqual(c.execute("SELECT count(*) FROM naruv_draft.attendance_receipts WHERE org_id='ci-a' AND request_id='hr-parallel'").fetchone()[0],1)
        def test_cost_hr_direct_privilege_and_gate(self):
            from app import naruv_hr_review as hr
            from unittest.mock import patch
            with psycopg.connect(fixture.root_dsn) as c:
                for role in ("jw_app_dev","naruv_native_stage"):
                    self.assertFalse(c.execute("SELECT has_table_privilege(%s,'naruv_draft.attendance_receipts','INSERT')",(role,)).fetchone()[0])
                self.assertFalse(c.execute("SELECT has_function_privilege('naruv_native_stage','naruv_draft.admit_attendance(text,text,text,text,int,int,boolean,text)','EXECUTE')").fetchone()[0])
            with patch.dict(os.environ,{hr.FLAG:""}):
                self.hr_admit("hr-disabled",code=404)
        def test_cost_hr_full_router_no_ledger_mutation(self):
            from app import naruv_integrated_review as integrated
            from unittest.mock import patch
            with patch.dict(os.environ,{integrated.FLAG:integrated.ACK,integrated.drafts.FLAG:integrated.ACK,integrated.hr.FLAG:integrated.ACK}):
                self.app=FastAPI()
                self.assertTrue(integrated.register_integrated_review(self.app,include_drafts=True,include_hr=True))
                self.billed_purchase()
                before=self.check(self.call("/valuation/overview"),200)
                first=self.hr_admit("hr-integrated",day="2026-10-03")
                self.assertEqual(first,self.hr_admit("hr-integrated",day="2026-10-03"))
                self.hr_admit("hr-integrated",day="2026-10-03",who="B",a=240)
                self.assertEqual(self.check(self.call("/valuation/overview"),200),before)
                self.check(self.call("/drafts/payroll/worker-1/2026-10"),404)
                with patch.dict(os.environ,{integrated.hr.FLAG:""}):
                    self.hr_admit("hr-blocked",day="2026-10-04",code=404)
                    self.check(self.call("/valuation/overview"),404)
                self.assertEqual(self.check(self.call("/valuation/overview"),200),before)
        def test_cost_hr_period_snapshot_confirm_and_retry(self):
            path="/hr/workers/worker-1/periods/2026-09"
            self.hr_admit("hr-sep-1",day="2026-09-01",period="2026-09",a=60,b=0)
            first=self.check(self.call(path+"/review"),200)
            self.assertFalse(first["confirmed"])
            self.assertEqual((first["days"],first["hourly_krw"],first["additional_bps"],first["policy_revision"]),([["2026-09-01",60,0]],12000,15000,"policy-1"))
            self.hr_admit("hr-sep-2",day="2026-09-02",period="2026-09",a=60,b=0)
            self.check(self.call(path+"/confirm/confirm-sep",{"review_sha256":first["review_sha256"]}),409)
            current=self.check(self.call(path+"/review"),200)
            self.assertNotEqual(current["review_sha256"],first["review_sha256"])
            body={"review_sha256":current["review_sha256"]}
            result=self.check(self.call(path+"/confirm/confirm-sep",body),200)
            self.assertTrue(result["confirmed"]);self.assertFalse(result["payment_authorized"])
            self.assertEqual(result,self.check(self.call(path+"/confirm/confirm-sep",body),200))
            self.check(self.call(path+"/confirm/other",body),409)
            self.hr_admit("hr-sep-closed",day="2026-09-03",period="2026-09",code=409)
            self.assertEqual(self.check(self.call("/drafts/payroll/worker-1/2026-09"),200)["gross_krw"],24000)
            self.check(self.call("/drafts/payroll/worker-1/2026-09",who="B"),404)
        def test_cost_hr_period_empty_and_cross_tenant(self):
            path="/hr/workers/worker-1/periods/2026-08"
            self.check(self.call(path+"/review"),422)
            self.hr_admit("hr-aug-a",day="2026-08-01",period="2026-08",a=60,b=0)
            self.hr_admit("hr-aug-b",day="2026-08-01",period="2026-08",who="B",a=60,b=0)
            a=self.check(self.call(path+"/review"),200);b=self.check(self.call(path+"/review",who="B"),200)
            self.assertNotEqual(a["review_sha256"],b["review_sha256"])
            body={"review_sha256":a["review_sha256"]}
            self.check(self.call(path+"/confirm/cross",body,who="B"),409)
            self.check(self.call(path+"/confirm/no-confirm",body,extra={"x-naruv-confirm":"no"}),422)
            self.check(self.call(path+"/confirm/wrong-origin",body,extra={"origin":"https://evil.test"}),403)
            self.assertFalse(self.check(self.call(path+"/review"),200)["confirmed"])
        def test_cost_hr_period_confirmation_privileges(self):
            with psycopg.connect(fixture.root_dsn) as c:
                for role in ("jw_app_dev","naruv_native_stage"):
                    self.assertFalse(c.execute("SELECT has_table_privilege(%s,'naruv_draft.period_confirmations','INSERT')",(role,)).fetchone()[0])
                self.assertFalse(c.execute("SELECT has_function_privilege('naruv_native_stage','naruv_draft.review_period(text,text,text,text,boolean,text)','EXECUTE')").fetchone()[0])
        def test_cost_hr_confirmed_snapshot_drift_blocks_payroll(self):
            path="/drafts/payroll/worker-1/2026-11"
            before=self.check(self.call(path),200)
            b=self.check(self.call(path,who="B"),200)
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertEqual(c.execute("UPDATE naruv_draft.pay_periods SET hourly_krw=hourly_krw+1 WHERE org_id='ci-a' AND worker_id='worker-1' AND period='2026-11'").rowcount,1)
            try:
                self.check(self.call(path),409)
                self.check(self.call("/hr/workers/worker-1/periods/2026-11/review"),409)
                self.assertEqual(self.check(self.call(path,who="B"),200),b)
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    self.assertEqual(c.execute("UPDATE naruv_draft.pay_periods SET hourly_krw=hourly_krw-1 WHERE org_id='ci-a' AND worker_id='worker-1' AND period='2026-11'").rowcount,1)
            self.assertEqual(self.check(self.call(path),200),before)
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertEqual(c.execute("UPDATE naruv_draft.attendance SET regular=regular+1 WHERE org_id='ci-a' AND worker_id='worker-1' AND period='2026-11' AND work_day='2026-11-25'").rowcount,1)
            try:self.check(self.call(path),409)
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    self.assertEqual(c.execute("UPDATE naruv_draft.attendance SET regular=regular-1 WHERE org_id='ci-a' AND worker_id='worker-1' AND period='2026-11' AND work_day='2026-11-25'").rowcount,1)
            self.assertEqual(self.check(self.call(path),200),before)
        def test_cost_hr_setup_end_to_end_new_worker(self):
            path="/hr/workers/new-worker"
            first=self.check(self.call(path+"/register/setup-new"),200)
            self.assertEqual(first,self.check(self.call(path+"/register/setup-new"),200))
            self.check(self.call(path+"/register/another"),409)
            self.check(self.call(path+"/inspect",who="B"),404)
            policy={"revision":"new-policy","hourly_krw":15000,"additional_bps":15000}
            pp=path+"/periods/2026-07"
            self.check(self.call(pp+"/create/setup-period",policy,who="B"),404)
            created=self.check(self.call(pp+"/create/setup-period",policy),200)
            self.assertEqual(created,self.check(self.call(pp+"/create/setup-period",policy),200))
            self.check(self.call(pp+"/create/setup-period",dict(policy,hourly_krw=15001)),409)
            self.check(self.call(pp+"/create/other-period",policy),409)
            self.assertEqual(self.check(self.call(path+"/inspect"),200)["periods"],[{"period":"2026-07","revision":"new-policy","confirmed":False}])
            self.hr_admit("new-att",day="2026-07-01",period="2026-07",worker="new-worker",a=60,b=0)
            review=self.check(self.call(pp+"/review"),200)
            self.check(self.call(pp+"/confirm/new-confirm",{"review_sha256":review["review_sha256"]}),200)
            self.assertEqual(self.check(self.call("/drafts/payroll/new-worker/2026-07"),200)["gross_krw"],15000)
            self.check(self.call(pp+"/create/overwrite",dict(policy,hourly_krw=1)),409)
            self.assertTrue(self.check(self.call(path+"/inspect"),200)["periods"][0]["confirmed"])
        def test_cost_hr_setup_invalid_scope_and_concurrent_retry(self):
            path="/hr/workers/setup-parallel"
            self.check(self.call(path+"/register/no-confirm",extra={"x-naruv-confirm":"no"}),422)
            self.check(self.call(path+"/register/bad-origin",extra={"origin":"https://evil.test"}),403)
            self.check(self.call(path+"/inspect"),404)
            barrier=threading.Barrier(3)
            def submit(_):
                barrier.wait(timeout=10)
                return self.check(self.call(path+"/register/setup-same"),200)
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                results=list(pool.map(submit,range(3)))
            self.assertTrue(all(r==results[0] for r in results))
            self.check(self.call("/hr/workers/other-worker/register/setup-same"),409)
            self.check(self.call(path+"/register/setup-same",who="B"),200)
            for period,rate in (("2026-13",100),("0000-01",100),("2026-07",True),("2026-07",0)):
                self.check(self.call(path+"/periods/"+period+"/create/bad-policy",{"revision":"r1","hourly_krw":rate,"additional_bps":15000}),422)
            self.assertEqual(self.check(self.call(path+"/inspect"),200)["periods"],[])
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertEqual(c.execute("SELECT count(*) FROM naruv_draft.setup_receipts WHERE org_id='ci-a' AND request_id='setup-same'").fetchone()[0],1)
        def test_cost_hr_setup_direct_grants(self):
            with psycopg.connect(fixture.root_dsn) as c:
                for role in ("jw_app_dev","naruv_native_stage"):
                    for table in ("staff","pay_periods","setup_receipts"):
                        for privilege in ("INSERT","UPDATE","DELETE"):
                            self.assertFalse(c.execute("SELECT has_table_privilege(%s,%s,%s)",(role,"naruv_draft."+table,privilege)).fetchone()[0])
                self.assertFalse(c.execute("SELECT has_function_privilege('naruv_native_stage','naruv_draft.setup_worker(text,text,text,text,bigint,int,boolean,text)','EXECUTE')").fetchone()[0])
        def test_cost_hr_lifecycle_archive_preserves_confirmed_pay(self):
            path="/hr/workers/archive-case";pp=path+"/periods/2026-06"
            self.check(self.call(path+"/register/archive-register"),200)
            policy={"revision":"archive-policy","hourly_krw":12000,"additional_bps":15000}
            self.check(self.call(pp+"/create/archive-period",policy),200)
            self.check(self.call(path+"/archive/archive-rid"),409)
            self.hr_admit("archive-att",day="2026-06-01",period="2026-06",worker="archive-case",a=60,b=0)
            self.check(self.call(path+"/archive/archive-rid"),409)
            review=self.check(self.call(pp+"/review"),200)
            self.check(self.call(pp+"/confirm/archive-confirm",{"review_sha256":review["review_sha256"]}),200)
            paypath="/drafts/payroll/archive-case/2026-06"
            before=self.check(self.call(paypath),200)
            self.check(self.call(path+"/archive/archive-rid",who="B"),404)
            result=self.check(self.call(path+"/archive/archive-rid"),200)
            self.assertFalse(result["active"])
            self.assertEqual(result,self.check(self.call(path+"/archive/archive-rid"),200))
            self.check(self.call(path+"/archive/different"),409)
            self.assertEqual(self.check(self.call(paypath),200),before)
            self.assertTrue(self.check(self.call(pp+"/review"),200)["confirmed"])
            self.check(self.call(path+"/periods/2026-05/create/after-archive",policy),404)
            self.hr_admit("after-archive",day="2026-06-02",period="2026-06",worker="archive-case",code=404)
            self.assertFalse(self.check(self.call(path+"/inspect"),200)["active"])
        def test_cost_hr_lifecycle_list_tenant_and_pagination(self):
            path="/hr/workers/list"
            for worker in ("list-a","list-z"):
                self.check(self.call("/hr/workers/"+worker+"/register/"+worker),200)
            self.check(self.call("/hr/workers/list-z/archive/list-retire"),200)
            found=[];cursor=None
            for _ in range(10):
                data={"limit":1}
                if cursor is not None:data["after"]=cursor
                r=self.check(self.call(path,data),200)
                found.extend(r["workers"]);cursor=r["next_after"]
                if cursor is None:break
            self.assertIsNone(cursor)
            self.assertEqual(len({r["worker_id"] for r in found}),len(found))
            self.assertIn({"worker_id":"list-a","active":True},found)
            self.assertIn({"worker_id":"list-z","active":False},found)
            b=self.check(self.call(path,{"limit":100},who="B"),200)
            self.assertNotIn("list-z",[x["worker_id"] for x in b["workers"]])
            for bad in ({"limit":0},{"limit":101},{"limit":True},{"after":123},{"tenant":"ci-b"}):
                self.check(self.call(path,bad),422)
        def test_cost_hr_lifecycle_direct_grants_and_drift(self):
            path="/hr/workers/archive-drift";pp=path+"/periods/2026-05"
            self.check(self.call(path+"/register/drift-register"),200)
            self.check(self.call(pp+"/create/drift-period",{"revision":"r1","hourly_krw":12000,"additional_bps":15000}),200)
            self.hr_admit("drift-att",day="2026-05-01",period="2026-05",worker="archive-drift",a=60,b=0)
            r=self.check(self.call(pp+"/review"),200)
            self.check(self.call(pp+"/confirm/drift-confirm",{"review_sha256":r["review_sha256"]}),200)
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertFalse(c.execute("SELECT has_table_privilege('jw_app_dev','naruv_draft.staff_archivals','INSERT')").fetchone()[0])
                self.assertFalse(c.execute("SELECT has_function_privilege('naruv_native_stage','naruv_draft.archive_worker(text,text,boolean,text)','EXECUTE')").fetchone()[0])
                self.assertEqual(c.execute("UPDATE naruv_draft.pay_periods SET hourly_krw=12001 WHERE org_id='ci-a' AND worker_id='archive-drift' AND period='2026-05'").rowcount,1)
            try:
                self.check(self.call(path+"/archive/drift-archive"),409)
                self.assertTrue(self.check(self.call(path+"/inspect"),200)["active"])
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    self.assertEqual(c.execute("UPDATE naruv_draft.pay_periods SET hourly_krw=12000 WHERE org_id='ci-a' AND worker_id='archive-drift' AND period='2026-05'").rowcount,1)
            self.check(self.call(path+"/archive/drift-archive"),200)
    names=[n for n in unittest.defaultTestLoader.getTestCaseNames(Valuation) if n.startswith("test_cost_")]
    if len(names)!=67:raise RuntimeError("COST_CASE_COUNT_CHANGED")
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Valuation(n) for n in names))
    if not result.wasSuccessful() or result.testsRun!=67 or result.skipped or result.expectedFailures or result.unexpectedSuccesses:raise SystemExit(1)
    print("NARUV_VALUATION_PASS: 67 isolated PG17 cost, reconciliation, posting, return and ledger audit cases; no statutory posting.")
