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
        def test_cost_integrated_production_trade_hr_and_manual_payroll_source(self):
            from app import naruv_integrated_review as integrated
            from app.naruv_kr_payroll_review import source_bound_review,DEDUCTIONS
            from unittest.mock import patch
            with patch.dict(os.environ,{integrated.FLAG:integrated.ACK,integrated.drafts.FLAG:integrated.ACK,integrated.hr.FLAG:integrated.ACK,
                    integrated.drafts.KR_FLAG:"DISPOSABLE_FIXTURE_ONLY"}):
                self.app=FastAPI()
                self.assertTrue(integrated.register_integrated_review(self.app,include_drafts=True,include_hr=True))
                # Register the original quote writer AFTER reserving the NARUV
                # namespace; the isolated composer deliberately rejects opaque
                # preexisting FastAPI router nodes. Preserve the real V92 gate.
                from app import pg_quote_api_v92 as v92
                self.assertTrue(v92.enabled())
                self.assertTrue(v92.register_v92_quote_api(self.app))
                self.assertIn("/api/pg-stage/v92/quotes",self.app.openapi()["paths"])
                self.ready_cost_prod();self.complete(3)
                q=self.quote(names=("Assembly",),qty=2)
                self.trade("open","combined-sale-o",{"kind":"sale","quote_id":q["quote_id"],"source_id":"source-a","item_id":"0003","warehouse_id":"W1"},doc="combined-sale")
                self.trade("fulfill","combined-sale-f",{"quantity":2},doc="combined-sale")
                self.fin("bill","combined-bill",{"doc_id":"combined-sale","fulfillment_id":"combined-sale-f"},bill="combined-bill")
                self.fin("pay","combined-pay",{"amount":100,"reference":"combined-ref"},bill="combined-bill")
                self.assertEqual(self.reconcile("combined-bill")["outstanding_krw"],"131")
                self.assertEqual(self.value("0003"),(1,253))
                baseline=self.audit_ledger();self.assertEqual(baseline["status"],"RECONCILED")
                overview=self.check(self.call("/valuation/overview"),200)
                worker="/hr/workers/combined-worker";period=worker+"/periods/2026-07"
                self.check(self.call(worker+"/register/combined-reg"),200)
                self.check(self.call(period+"/create/combined-policy",{"revision":"combined-v1","hourly_krw":12000,"additional_bps":15000}),200)
                self.hr_admit("combined-att",day="2026-07-01",period="2026-07",worker="combined-worker",a=480,b=60)
                reviewed=self.check(self.call(period+"/review"),200)
                self.check(self.call(period+"/confirm/combined-confirm",{"review_sha256":reviewed["review_sha256"]}),200)
                pay=self.check(self.call("/drafts/payroll/combined-worker/2026-07"),200)
                self.assertEqual(pay["gross_krw"],114000)
                confirmed=self.check(self.call(period+"/review"),200)
                self.assertTrue(confirmed["confirmed"])
                result=source_bound_review(tenant="ci-a",worker="combined-worker",period="2026-07",
                    policy_revision=confirmed["policy_revision"],hourly_krw=confirmed["hourly_krw"],
                    minutes_by_day=[{"date":d,"regular":a,"additional":b} for d,a,b in confirmed["days"]],
                    additional_bps=confirmed["additional_bps"],expected_draft_sha256=pay["draft_sha256"],
                    ordinary_hourly=12000,classification_sha256="a"*64,
                    classified_days=[{"date":"2026-07-01","regular":480,"overtime":60,"holiday_first8":0,"holiday_after8":0,"night":60}],
                    deductions={k:{"amount_krw":1000,"evidence_sha256":"b"*64,"assessment":"ASSESSED"} for k in DEDUCTIONS})
                self.assertEqual(result["deductions"]["net_estimate_krw"],114000)
                self.assertFalse(result["payment_authorized"]);self.assertFalse(result["statutory_validated"])
                krpath="/drafts/payroll/combined-worker/2026-07/kr-review"
                manual=dict(expected_draft_sha256=pay["draft_sha256"],ordinary_hourly=12000,
                    classification_sha256="a"*64,classified_days=[{"date":"2026-07-01","regular":480,
                    "overtime":60,"holiday_first8":0,"holiday_after8":0,"night":60}],
                    deductions={k:{"amount_krw":1000,"evidence_sha256":"b"*64,"assessment":"ASSESSED"} for k in DEDUCTIONS},
                    pension_assessed_base_krw=410000)
                response=self.check(self.call(krpath,manual),200)
                self.assertEqual(response["review"],result)
                self.assertEqual(response["pension_reference"]["employee_collection_reference_krw"],19470)
                self.assertEqual(response["pension_reference"]["status"],"AGENCY_AMOUNT_DIFFERENCE_REVIEW_REQUIRED")
                insurance=dict(health_base_krw=1000000,employment_base_krw=120000,assessment_sha256="c"*64)
                expanded=self.check(self.call(krpath,dict(manual,insurance_assessed_bases=insurance)),200)
                self.assertEqual(expanded["insurance_reference"]["candidates"]["health_10won"],35950)
                self.assertIn("HEALTH_REFERENCE_DIFFERENCE",expanded["insurance_reference"]["flags"])
                self.assertNotEqual(expanded["review_sha256"],response["review_sha256"])
                self.assertFalse(expanded["payment_authorized"])
                self.check(self.call(krpath,dict(manual,insurance_assessed_bases=dict(insurance,health_base_krw=True))),422)
                settlement={"year_end":dict(kind="MIDYEAR_TERMINATION",decided_national_krw=10000,
                    previous_national_krw=12000,special_payment_krw=0,assessment_sha256="d"*64)}
                holiday=dict(calendar_sha256="e"*64,days=[dict(date="2026-07-02",paid_minutes=360,
                    actual_minutes=0,kind="ASSESSED_PUBLIC_HOLIDAY",assessment_sha256="f"*64)])
                combined=self.check(self.call(krpath,dict(manual,settlement_components=settlement,paid_holiday_review=holiday)),200)
                self.assertEqual(combined["settlement_reference"]["components"]["year_end"]["refund_reference_krw"],2000)
                self.assertEqual(combined["paid_holiday_reference"]["estimate_krw"],72000)
                self.assertFalse(combined["payment_authorized"])
                severance=dict(eligible_confirmed=True,service_days=730,average_period_days=90,
                    included_wages_krw=9000000,ordinary_daily_krw=100000,excluded_days=30,
                    excluded_wages_krw=1800000,assessment_sha256="d"*64)
                sv=self.check(self.call(krpath,dict(manual,settlement_components={"severance":severance})),200)
                self.assertEqual(sv["settlement_reference"]["components"]["severance"]["estimate_krw"],7200000)
                self.check(self.call(krpath,dict(manual,settlement_components={"severance":dict(severance,excluded_days=90)})),409)
                part_time=dict(comparator_grant_days=15,contracted_week_minutes=1200,
                    contract_sha256="a"*64,grant_assessment_sha256="b"*64)
                pt=self.check(self.call(krpath,dict(manual,part_time_leave_review=part_time)),200)
                self.assertEqual(pt["part_time_leave_reference"]["grant_hours"],60)
                self.assertFalse(pt["statutory_validated"])
                self.assertFalse(pt["payment_authorized"])
                self.assertNotEqual(pt["review_sha256"],response["review_sha256"])
                self.check(self.call(krpath,dict(manual,part_time_leave_review=dict(part_time,contracted_week_minutes=899))),409)
                self.check(self.call(krpath,dict(manual,part_time_leave_review=dict(part_time,tenant="ci-b"))),422)
                pt_html=self.call(krpath,dict(manual,part_time_leave_review=part_time),extra={"accept":"text/html"})
                self.assertEqual(pt_html.status_code,200)
                self.assertIn("60 시간",pt_html.text)
                self.assertEqual(pt_html.headers["cache-control"],"no-store")
                self.check(self.call(krpath,dict(manual,part_time_leave_review=part_time),who="B"),404)
                print("NARUV_PART_TIME_LEAVE_API_PASS isolated assessed grant, HTML and tenant denial",flush=True)
                leave=dict(employment_start="2025-07-01",service_year=1,as_of="2026-07-01",
                    last_employed_on=None,attendance_sha256="b"*64,contract_sha256="c"*64,
                    scope="CONTINUOUS_FULLTIME_5PLUS_FIRST_OF_MONTH_HIRE",
                    months=[dict(start=f"2025-{m:02}-01",scheduled_days=20,credited_days=20 if m<11 else 10,evidence_sha256="a"*64) for m in range(7,13)]
                    +[dict(start=f"2026-{m:02}-01",scheduled_days=20,credited_days=10,evidence_sha256="a"*64) for m in range(1,7)])
                assessment=dict(attendance_sha256="b"*64,contract_sha256="c"*64,anniversary="2026-07-01",assessed_additional_days=4,assessment_sha256="d"*64)
                self.check(self.call(krpath,dict(manual,annual_leave_accrual_review=leave)),409)
                leave["first_year_low_attendance_assessment"]=assessment
                lr=self.check(self.call(krpath,dict(manual,annual_leave_accrual_review=leave)),200)
                self.assertEqual(lr["annual_leave_accrual_reference"]["earned_days_in_review"],8)
                self.assertFalse(lr["annual_leave_accrual_reference"]["historical_attendance_authenticity_verified"])
                self.assertFalse(lr["statutory_validated"]);self.assertFalse(lr["payment_authorized"])
                self.assertNotEqual(lr["review_sha256"],response["review_sha256"])
                self.check(self.call(krpath,dict(manual,annual_leave_accrual_review=dict(leave,as_of="2026-08-01"))),409)
                self.check(self.call(krpath,dict(manual,annual_leave_accrual_review=dict(leave,first_year_low_attendance_assessment=dict(assessment,assessed_additional_days=5)))),409)
                self.check(self.call(krpath,dict(manual,annual_leave_accrual_review=leave,part_time_leave_review=part_time)),422)
                self.check(self.call(krpath,dict(manual,annual_leave_accrual_review=leave),who="B"),404)
                lh=self.call(krpath,dict(manual,annual_leave_accrual_review=leave),extra={"accept":"text/html"})
                self.assertEqual(lh.status_code,200);self.assertIn("8 일",lh.text)
                self.assertEqual(lh.headers["cache-control"],"no-store")
                print("NARUV_ANNUAL_LEAVE_ACCRUAL_API_PASS manual evidence, period, scope, HTML and tenant denial",flush=True)
                annual=dict(kind="MIDYEAR_TERMINATION",scope="RESIDENT_WAGE_ONLY_NO_RELIEF_ASSESSED_OTHER_DEDUCTIONS_CREDITS",
                    annual_income_krw=200000000,exempt_income_krw=5000000,assessed_other_deductions_krw=7000000,
                    assessed_cap_addback_krw=0,assessed_other_credits_krw=0,previous_national_krw=44334000,
                    annual_source_sha256="a"*64,deduction_assessment_sha256="b"*64,credit_assessment_sha256="c"*64,assessment_sha256="d"*64)
                yr=self.check(self.call(krpath,dict(manual,settlement_components={"year_end_calculated":annual})),200)
                self.assertEqual(yr["settlement_reference"]["components"]["year_end_calculated"]["signed_difference_krw"],639000)
                self.assertFalse(yr["settlement_reference"]["annual_source_authenticity_verified"])
                self.assertFalse(yr["settlement_reference"]["settlement_included_in_monthly_gross"])
                self.assertEqual(yr["settlement_reference"]["confirmed_month_gross_estimate_krw"],yr["review"]["wage"]["gross_estimate_krw"])
                self.assertFalse(yr["statutory_validated"])
                self.assertFalse(yr["payment_authorized"])
                self.check(self.call(krpath,dict(manual,settlement_components={"year_end_calculated":dict(annual,scope="UNSUPPORTED")})),409)
                self.check(self.call(krpath,dict(manual,settlement_components={"year_end_calculated":annual}),who="B"),404)
                annual_html=self.call(krpath,dict(manual,settlement_components={"year_end_calculated":annual}),extra={"accept":"text/html"})
                self.assertEqual(annual_html.status_code,200)
                self.assertIn("639,000",annual_html.text)
                self.assertIn("수동 제출 · 월 급여에 미합산",annual_html.text)
                print("NARUV_ANNUAL_NATIONAL_TAX_API_PASS assessed ordinary calculation, HTML and tenant denial",flush=True)
                tw="/hr/workers/tax-worker";tp=tw+"/periods/2026-07"
                self.check(self.call(tw+"/register/tax-reg"),200)
                self.check(self.call(tp+"/create/tax-policy",{"revision":"tax-v1","hourly_krw":100000,"additional_bps":15000}),200)
                self.hr_admit("tax-att1",day="2026-07-01",period="2026-07",worker="tax-worker",a=480,b=0)
                self.hr_admit("tax-att2",day="2026-07-02",period="2026-07",worker="tax-worker",a=480,b=0)
                tr=self.check(self.call(tp+"/review"),200)
                self.check(self.call(tp+"/confirm/tax-confirm",{"review_sha256":tr["review_sha256"]}),200)
                td=self.check(self.call("/drafts/payroll/tax-worker/2026-07"),200)
                self.assertEqual(td["gross_krw"],1600000)
                taxpath="/drafts/payroll/tax-worker/2026-07/kr-review"
                taxargs=dict(withholding_date="2026-07-25",taxable_monthly_krw=1600000,
                    eligible_family_count=1,eligible_children_8_20=0,selection_percent=100,assessment_sha256="b"*64)
                tm=dict(manual,expected_draft_sha256=td["draft_sha256"],ordinary_hourly=100000,
                    classified_days=[dict(date=d,regular=480,overtime=0,holiday_first8=0,holiday_after8=0,night=0)
                        for d in ("2026-07-01","2026-07-02")],monthly_tax_review=taxargs)
                taxout=self.check(self.call(taxpath,tm),200)
                self.assertIn("monthly_tax_reference",taxout)
                self.assertFalse(taxout["payment_authorized"])
                self.check(self.call(taxpath,dict(tm,monthly_tax_review=dict(taxargs,taxable_monthly_krw=1600001))),409)
                self.check(self.call(taxpath,dict(tm,monthly_tax_review=dict(taxargs,assessment_sha256="a"*64))),409)
                self.check(self.call(taxpath,tm,who="B"),404)
                th=self.call(taxpath,tm,extra={"accept":"text/html"})
                self.assertEqual(th.status_code,200)
                self.assertIn("월 소득세 계산 참고액",th.text)
                print("NARUV_MONTHLY_TAX_API_PASS confirmed gross bound, evidence, HTML and tenant denial",flush=True)
                from datetime import date,timedelta
                weeks=[]
                for w in range(5):
                    monday=date(2026,6,29)+timedelta(days=7*w)
                    entries=[]
                    for j in range(7):
                        d=monday+timedelta(days=j)
                        worked=d.isoformat() in ("2026-07-01","2026-07-02") or d.month==6
                        state=("PRESENT" if worked else "APPROVED_FULL_DAY_ANNUAL_LEAVE" if d.isoformat()=="2026-07-03" else "ABSENT") if j<5 else ("WEEKLY_REST" if j==6 else "NON_WORK_DAY")
                        entries.append(dict(date=d.isoformat(),status=state,actual_minutes=480 if state=="PRESENT" else 0,evidence_sha256="a"*64))
                    weeks.append(dict(monday=monday.isoformat(),employed_full_week=True,days=entries))
                paid=dict(schedule_sha256="b"*64,attendance_sha256="c"*64,weeks=weeks,scope="HOURLY_MON_FRI_40H_SUNDAY_REST_ORDINARY_LEAVE_RATE")
                fixed={k:v for k,v in tm.items() if k!="monthly_tax_review"}
                fr=self.check(self.call(taxpath,dict(fixed,fixed_week_paid_review=paid)),200)
                self.assertEqual(fr["fixed_week_paid_reference"]["paid_days"]["weekly_rest_krw"],800000)
                self.assertEqual(fr["fixed_week_paid_reference"]["paid_days"]["annual_leave_krw"],800000)
                self.assertEqual(fr["fixed_week_paid_reference"]["gross_estimate_krw"],3200000)
                self.assertFalse(fr["fixed_week_paid_reference"]["classification_authenticity_verified"])
                self.assertFalse(fr["payment_authorized"])
                self.check(self.call(taxpath,dict(tm,fixed_week_paid_review=paid)),422)
                self.check(self.call(taxpath,dict(fixed,fixed_week_paid_review=paid),who="B"),404)
                # A confirmed ordinary-hours draft can still include a manual
                # night classification. Alternative gross must not discard it.
                night_days=[dict(r) for r in fixed["classified_days"]]
                night_days[0]["night"]=60
                night_fixed=dict(fixed,classified_days=night_days)
                self.check(self.call(taxpath,night_fixed),200)
                self.check(self.call(taxpath,dict(night_fixed,fixed_week_paid_review=paid)),409)
                import copy
                mismatch=copy.deepcopy(paid);mismatch["weeks"][0]["days"][2]["actual_minutes"]=479
                self.check(self.call(taxpath,dict(fixed,fixed_week_paid_review=mismatch)),409)
                fh=self.call(taxpath,dict(fixed,fixed_week_paid_review=paid),extra={"accept":"text/html"})
                self.assertEqual(fh.status_code,200);self.assertIn("3,200,000",fh.text)
                print("NARUV_FIXED_WEEK_PAID_API_PASS alternative gross, confirmed work match, HTML, tenant and conflict denial",flush=True)
                ptweeks=[]
                for w in range(4):
                    mon=date(2026,6,8)+timedelta(days=7*w);entries=[]
                    for j in range(7):
                        d=mon+timedelta(days=j)
                        state="PRESENT" if j in (2,3) else "WEEKLY_REST" if j==6 else "NON_WORK_DAY"
                        entries.append(dict(date=d.isoformat(),status=state,actual_minutes=480 if state=="PRESENT" else 0,evidence_sha256="a"*64))
                    ptweeks.append(dict(monday=mon.isoformat(),employed_full_week=True,days=entries))
                ptr=dict(sunday="2026-07-05",contracted_minutes=[0,0,480,480,0,0],comparator_minutes=[480]*5+[0],
                    weeks=ptweeks,contract_sha256="b"*64,attendance_sha256="c"*64,scope="FIXED_PART_TIME_4_COMPLETE_WEEKS_SUNDAY_REST")
                pr=self.check(self.call(taxpath,dict(fixed,part_time_rest_review=ptr)),200)
                self.assertEqual(pr["part_time_rest_reference"]["rest_pay_estimate_krw"],320000)
                self.assertFalse(pr["part_time_rest_reference"]["included_in_gross"])
                self.assertEqual(pr["part_time_rest_reference"]["confirmed_month_overlap_days"],5)
                self.assertEqual(pr["part_time_rest_reference"]["matched_confirmed_positive_work_days"],2)
                self.assertEqual(pr["part_time_rest_reference"]["manual_zero_work_status_days"],3)
                self.assertFalse(pr["part_time_rest_reference"]["zero_minutes_attendance_status_verified"])
                self.check(self.call(taxpath,dict(fixed,part_time_rest_review=ptr),who="B"),404)
                self.check(self.call(taxpath,dict(tm,part_time_rest_review=ptr)),422)
                bad=copy.deepcopy(ptr);bad["weeks"][-1]["days"][2]["actual_minutes"]=479
                self.check(self.call(taxpath,dict(fixed,part_time_rest_review=bad)),409)
                self.check(self.call(taxpath,dict(night_fixed,part_time_rest_review=ptr)),409)
                ph=self.call(taxpath,dict(fixed,part_time_rest_review=ptr),extra={"accept":"text/html"})
                self.assertEqual(ph.status_code,200);self.assertIn("320,000",ph.text)
                self.assertIn("실근로 확인 2일 / 0분 근태 분류 수동 제출 3일",ph.text)
                print("NARUV_PART_TIME_REST_API_PASS confirmed overlapping work, manual history, separate reference and tenant denial",flush=True)
                shift=dict(shift_sha256="e"*64,segments=[dict(start="2026-07-01T14:00+09:00",end="2026-07-01T23:00+09:00",evidence_sha256="f"*64)])
                shift_result=self.check(self.call(krpath,dict(manual,shift_review=shift)),200)
                self.assertEqual(shift_result["shift_reference"]["days"],[{"date":"2026-07-01","work_minutes":540,"night_minutes":60}])
                self.check(self.call(krpath,dict(manual,shift_review=dict(shift,segments=[dict(shift["segments"][0],end="2026-07-01T22:59+09:00")]))),409)
                html=self.call(krpath,dict(manual,settlement_components=settlement,paid_holiday_review=holiday),extra={"accept":"text/html"})
                self.assertEqual(html.status_code,200)
                self.assertIn("text/html",html.headers["content-type"])
                self.assertIn("72,000",html.text)
                self.assertIn("지급 및 운영 반영 금지",html.text)
                self.assertEqual(html.headers["cache-control"],"no-store")
                self.assertNotIn("<script",html.text)
                bad_holiday=dict(holiday,days=[dict(holiday["days"][0],actual_minutes=60)])
                self.check(self.call(krpath,dict(manual,paid_holiday_review=bad_holiday)),409)
                for k in ("evidence_authenticity_verified","persisted","payment_authorized","production_authorized","statutory_validated"):
                    self.assertIs(response[k],False)
                self.check(self.call(krpath,manual,who="B"),404)
                self.check(self.call(krpath,dict(manual,expected_draft_sha256="0"*64)),409)
                self.check(self.call(krpath,dict(manual,tenant="ci-b")),422)
                self.check(self.call(krpath,dict(manual,classified_days=[])),409)
                bad=dict(manual,deductions=dict(manual["deductions"],pension=dict(manual["deductions"]["pension"],amount_krw=True)))
                self.check(self.call(krpath,bad),422)
                self.check(self.call(krpath,manual,extra={"content-encoding":"gzip"}),415)
                with patch.dict(os.environ,{integrated.drafts.KR_FLAG:""}):
                    self.check(self.call(krpath,manual),404)
                print("NARUV_KR_CONFIRMED_ATTENDANCE_API_PASS manual reference only, cross-tenant and stale source denial",flush=True)
                self.check(self.call("/drafts/payroll/combined-worker/2026-07",who="B"),404)
                self.assertFalse(self.check(self.call("/drafts/documents/shared"),200)["posting_authorized"])
                # Bounded disposable benchmark; no production SLO claim.
                import time,math
                paths=["/valuation/overview", "/valuation/audit", "/drafts/payroll/combined-worker/2026-07", "/drafts/documents/shared"]*8
                def measured(path):
                    start=time.perf_counter()
                    r=self.call(path)
                    return r.status_code,(time.perf_counter()-start)*1000
                start=time.perf_counter()
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    results=list(pool.map(measured,paths))
                elapsed=time.perf_counter()-start
                self.assertEqual(len(results),32)
                self.assertTrue(all(code==200 for code,_ in results))
                samples=sorted(ms for _,ms in results)
                p95=samples[math.ceil(len(samples)*.95)-1]
                p99=samples[math.ceil(len(samples)*.99)-1]
                print(f"NARUV_ISOLATED_READ_METRICS n={len(samples)} concurrency=4 p95_ms={p95:.2f} p99_ms={p99:.2f} max_ms={samples[-1]:.2f} rps={len(samples)/elapsed:.2f}",flush=True)
                self.assertEqual(self.audit_ledger(),baseline)
                self.assertEqual(self.check(self.call("/valuation/overview"),200),overview)
        def test_cost_hosted_admission_real_catalog(self):
            import secrets
            from psycopg import sql
            from psycopg.conninfo import make_conninfo,conninfo_to_dict
            from app.naruv_hosted_qa_admission import (Config,PURPOSES,AdmissionBlocked,
                verify_catalog,_verify_role_catalog)
            opts=conninfo_to_dict(fixture.root_dsn)
            self.assertEqual((os.environ.get("GITHUB_ACTIONS"),os.environ.get("JW_PG_CI_ALLOW"),opts.get("host"),opts.get("dbname")),
                ("true","ONLY_EPHEMERAL_LOCAL_DATABASE","127.0.0.1","postgres"))
            users=[user for _,user,_ in PURPOSES.values()]
            owner="naruv_qa_boundary_owner"
            passwords={u:secrets.token_urlsafe(36) for u in users}
            marker=secrets.token_hex(32);source="a"*40
            dsns={p:make_conninfo(fixture.root_dsn,user=u,password=passwords[u],sslmode="disable")
                  for p,(_,u,_) in PURPOSES.items()}
            cfg=Config("127.0.0.1","postgres",source,marker,dsns)
            with psycopg.connect(fixture.root_dsn) as root:
                self.assertEqual(root.execute("SELECT count(*) FROM pg_roles WHERE rolname=ANY(%s)",(users+[owner],)).fetchone()[0],0)
                self.assertIsNone(root.execute("SELECT to_regnamespace('naruv_hosted_qa')").fetchone()[0])
                root.execute(sql.SQL("CREATE ROLE {} NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB").format(sql.Identifier(owner)))
                from app.naruv_hosted_qa_boundary import initialize_ci
                for _,u,r in PURPOSES.values():
                    root.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD {}").format(sql.Identifier(u),sql.Literal(passwords[u])))
                    root.execute(sql.SQL("GRANT {} TO {} WITH INHERIT FALSE, SET TRUE").format(sql.Identifier(r),sql.Identifier(u)))
                # All DDL shares the caller transaction. A deliberately
                # rolled-back savepoint must leave no schema or marker.
                class RollbackProbe(Exception):pass
                try:
                    with root.transaction(),root.cursor() as cur:
                        initialize_ci(cur,marker=marker,source_sha=source)
                        raise RollbackProbe()
                except RollbackProbe:pass
                self.assertIsNone(root.execute("SELECT to_regnamespace('naruv_hosted_qa')").fetchone()[0])
                with root.cursor() as cur:
                    initialize_ci(cur,marker=marker,source_sha=source)
                    with self.assertRaisesRegex(AdmissionBlocked,"BOUNDARY_EXISTS"):
                        initialize_ci(cur,marker=marker,source_sha="b"*40)
                self.assertEqual(root.execute("SELECT marker,source_sha FROM naruv_hosted_qa.boundary").fetchall(),[(marker,source)])
                with self.assertRaises(psycopg.errors.UniqueViolation):
                    with root.transaction():
                        root.execute("INSERT INTO naruv_hosted_qa.boundary(marker,source_sha) VALUES(%s,%s)",("c"*64,source))
                print("NARUV_BOUNDARY_INITIALIZER_PASS transactional rollback, duplicate refusal, singleton, exact source marker",flush=True)
            def check(purpose,expected=None):
                with psycopg.connect(dsns[purpose]) as db:
                    with db.transaction(),db.cursor() as cur:
                        cur.execute("SET TRANSACTION READ ONLY")
                        if expected is None:
                            _verify_role_catalog(cur,purpose=purpose,config=cfg)
                            # No TLS here: prove the actual hosted entry rejects
                            # this deliberately non-TLS connection.
                            with self.assertRaisesRegex(AdmissionBlocked,"HOSTED_QA_DB_TLS"):
                                verify_catalog(cur,purpose=purpose,config=cfg)
                        else:
                            with self.assertRaisesRegex(AdmissionBlocked,expected):
                                _verify_role_catalog(cur,purpose=purpose,config=cfg)
            try:
                for p in PURPOSES:check(p)
                with psycopg.connect(fixture.root_dsn) as root:
                    root.execute("GRANT SELECT(worker_id) ON naruv_draft.staff TO naruv_qa_business")
                try:check("business","HOSTED_QA_DIRECT_GRANT")
                finally:
                    with psycopg.connect(fixture.root_dsn) as root:
                        root.execute("REVOKE SELECT(worker_id) ON naruv_draft.staff FROM naruv_qa_business")
                with psycopg.connect(fixture.root_dsn) as root:
                    root.execute("GRANT UPDATE ON naruv_hosted_qa.boundary TO naruv_qa_auth")
                try:check("auth","HOSTED_QA_BOUNDARY_WRITABLE")
                finally:
                    with psycopg.connect(fixture.root_dsn) as root:
                        root.execute("REVOKE UPDATE ON naruv_hosted_qa.boundary FROM naruv_qa_auth")
                with psycopg.connect(fixture.root_dsn) as root:
                    root.execute("UPDATE naruv_hosted_qa.boundary SET source_sha=%s",("b"*40,))
                try:check("ingest","HOSTED_QA_BOUNDARY_MISMATCH")
                finally:
                    with psycopg.connect(fixture.root_dsn) as root:
                        root.execute("UPDATE naruv_hosted_qa.boundary SET source_sha=%s",(source,))
                for p in PURPOSES:check(p)
                from scripts.naruv_pg_tls_admission_ci import verified_pg_tls
                with verified_pg_tls(fixture.root_dsn) as (cert,untrusted):
                    for p in PURPOSES:
                        tls_dsn=make_conninfo(dsns[p],sslmode="verify-full",sslrootcert=str(cert),
                            gssencmode="disable",connect_timeout=3)
                        with psycopg.connect(tls_dsn) as db:
                            with db.transaction(),db.cursor() as cur:
                                cur.execute("SET TRANSACTION READ ONLY")
                                verify_catalog(cur,purpose=p,config=cfg)
                        for kwargs in ({"sslrootcert":str(untrusted)},
                            {"host":"wrong.example.invalid","hostaddr":"127.0.0.1"}):
                            bad_dsn=make_conninfo(tls_dsn,**kwargs)
                            with self.assertRaises(psycopg.OperationalError):
                                with psycopg.connect(bad_dsn):pass
                    print("NARUV_PG_TLS_ADMISSION_PASS three actual verified TLS roles, six wrong-root/hostname denials",flush=True)
                    from scripts.naruv_pg_auth_acceptance_ci import verify as verify_auth
                    verify_auth(cert,dsns)
                print("NARUV_HOSTED_REAL_PG_CATALOG_PASS three restricted roles, 3 non-TLS denials, column grant, marker grant and drift refusals",flush=True)
            finally:
                # Only fixture-owned resources created in this test.
                with psycopg.connect(fixture.root_dsn) as root:
                    root.execute("DROP SCHEMA naruv_hosted_qa CASCADE")
                    for u in users:
                        root.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(u)))
                        root.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(u)))
                    root.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(owner)))
                    self.assertEqual(root.execute("SELECT count(*) FROM pg_roles WHERE rolname=ANY(%s)",(users+[owner],)).fetchone()[0],0)
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
        def test_cost_hr_amendment_and_confirmed_lock(self):
            path="/hr/workers/amend-worker";pp=path+"/periods/2026-04"
            self.check(self.call(path+"/register/amend-register"),200)
            self.check(self.call(pp+"/create/amend-period",{"revision":"r1","hourly_krw":12000,"additional_bps":15000}),200)
            self.hr_admit("amend-att",worker="amend-worker",period="2026-04",day="2026-04-01",a=60,b=0)
            first=self.check(self.call(pp+"/review"),200)
            body={"review_sha256":first["review_sha256"],"kind":"attendance","date":"2026-04-01","regular":120,"additional":0}
            self.check(self.call(pp+"/amend/amend-a",body,who="B"),404)
            a=self.check(self.call(pp+"/amend/amend-a",body),200)
            self.assertEqual(a,self.check(self.call(pp+"/amend/amend-a",body),200))
            self.check(self.call(pp+"/amend/other-a",body),409)
            p={"review_sha256":a["review_sha256"],"kind":"policy","revision":"r2","hourly_krw":15000,"additional_bps":15000}
            b=self.check(self.call(pp+"/amend/amend-p",p),200)
            self.check(self.call(pp+"/confirm/stale-confirm",{"review_sha256":first["review_sha256"]}),409)
            self.check(self.call(pp+"/confirm/amend-confirm",{"review_sha256":b["review_sha256"]}),200)
            self.assertEqual(self.check(self.call("/drafts/payroll/amend-worker/2026-04"),200)["gross_krw"],30000)
            body["review_sha256"]=b["review_sha256"]
            self.check(self.call(pp+"/amend/closed-amend",body),409)
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertEqual(c.execute("SELECT count(*) FROM naruv_draft.period_amendments WHERE org_id='ci-a' AND worker_id='amend-worker'").fetchone()[0],2)
                self.assertFalse(c.execute("SELECT has_table_privilege('jw_app_dev','naruv_draft.period_amendments','UPDATE')").fetchone()[0])
        def test_cost_works_real_stage_composition(self):
            # Fresh process avoids mutating the legacy singleton used by any other test.
            import subprocess,sys,tempfile
            from tests.test_naruv_integrated_review import FLAGS
            with tempfile.TemporaryDirectory() as tmp:
                env=dict(os.environ,**FLAGS,NARUV_DRAFT_REVIEW="ISOLATED_SYNTHETIC_ONLY",NARUV_HR_REVIEW="ISOLATED_SYNTHETIC_ONLY",
                         NARUV_WORKS_STAGE="ISOLATED_SYNTHETIC_ONLY",JW_PG_QUOTE_V92="ISOLATED_DEV_QUOTE_V92",
                         JARVIS_DB_PATH=str(Path(tmp)/"isolated.db"),DEMO_SEED="0",
                         NARUV_TEST_TOKEN=fixture.TOKENS["A"],NARUV_TEST_CSRF=fixture.CSRF["A"],
                         NARUV_TEST_TRADE_DSN=fixture.TRADE_DSN)
                env.pop("JW_V112_PG_NOTIFY_ACK",None)
                script="""
import os
import psycopg
from psycopg.conninfo import conninfo_to_dict
from fastapi.testclient import TestClient
from app import main,pg_api_v84 as stage
from app.naruv_works_stage_entry import app
assert app is main.app
# The parent fixture replaces _connect with a real disposable nonprivileged PG17
# connection; explicitly reproduce ONLY that test seam in the fresh process.
# Real TLS remains a separate gate; production connection code is untouched.
assert os.environ.get('GITHUB_ACTIONS')=='true'
assert os.environ.get('JW_PG_CI_ALLOW')=='ONLY_EPHEMERAL_LOCAL_DATABASE'
dsn=os.environ.pop('NARUV_TEST_TRADE_DSN')
opts=conninfo_to_dict(dsn)
assert (opts.get('host'),opts.get('dbname'),opts.get('user'))==('127.0.0.1','postgres','jw_ci_trade')
stage._connect=lambda:psycopg.connect(dsn,connect_timeout=5)
c=TestClient(app,base_url='https://testserver')
try:
    paths=app.openapi()['paths']
    assert len([x for x in paths if x.startswith('/api/naruv-review/v1/')])==42
    assert '/api/pg-stage/v92/quotes' in paths and '/api/pg-stage/v85/login' in paths
    assert c.get('/api/health').status_code==200
    home=c.get('/')
    assert home.status_code==200 and home.headers.get('x-frame-options')=='DENY'
    c.cookies.set('__Host-jw_session',os.environ['NARUV_TEST_TOKEN'])
    h={'origin':'https://testserver','x-csrf-token':os.environ['NARUV_TEST_CSRF']}
    r=c.post('/api/naruv-review/v1/drafts/payroll/worker-1/2026-11',headers=h)
    assert r.status_code==200 and r.json()['gross_krw']==114000
    assert r.headers.get('cache-control')=='no-store' and r.headers.get('strict-transport-security')
    assert c.get('/api/pg-stage/v90/me').status_code==200
    assert c.post('/api/naruv-review/v1/drafts/payroll/worker-1/2026-11',headers=dict(h,origin='https://evil.test')).status_code==403
    # Exercise original V22.3 cookie forwarding with the actual SQLite
    # session resolver and PG17 session/role resolver, not fake identities.
    import hashlib,secrets
    from datetime import datetime,timedelta
    from app import naruv_v223_read_bridge as bridge,pg_cinema_cutover_front_v223 as cut
    from app import pg_v90_integrated_entry as v90
    from fastapi import FastAPI
    os.environ[bridge.FLAG]=bridge.ACK
    main.init_db()
    legacy_token=secrets.token_urlsafe(36)
    with main.conn() as db:
        db.execute("INSERT INTO organizations VALUES(?,?,?)",("ci-a","Synthetic A",main.now()))
        db.execute("INSERT INTO users VALUES(?,?,?,?,?,?,?)",("ci-ua","ci-a","synthetic@example.invalid",main.hash_password(secrets.token_urlsafe(24)),"Synthetic","admin",main.now()))
        db.execute("INSERT INTO sessions(token_hash,user_id,expires_at,csrf_token,id,created_at) VALUES(?,?,?,?,?,?)",
          (hashlib.sha256(legacy_token.encode()).hexdigest(),"ci-ua",(datetime.now(main.KST)+timedelta(hours=1)).isoformat(),secrets.token_urlsafe(32),"bridge-legacy",main.now()))
    def legacy_identity(request):
        r=main.current_user(request)
        return cut.Identity(r["org_id"],r["id"],r["role"])
    def pg_identity(request):
        with v90._pg_validated_cursor(v90._session_hash(request)) as (_,ident):
            return cut.Identity(ident[2],ident[1],ident[3])
    erp=FastAPI()
    assert bridge.integrated.register_integrated_review(erp,include_drafts=True,include_hr=True)
    front=cut.CutoverFront(main.app,main.app,legacy_identity,pg_identity,lambda:frozenset(("ci-a",)))
    import sqlite3
    fence_probes=[]
    @erp.middleware("http")
    async def verify_legacy_fence(request,call_next):
        if bridge.is_pilot_path(request.url.path) and bridge.pilot_enabled():
            # Independent connection simulates a concurrent session revocation.
            with sqlite3.connect(main.DB_PATH,timeout=0) as other:
                try:
                    other.execute("DELETE FROM sessions WHERE id='bridge-legacy'")
                except sqlite3.OperationalError as exc:
                    assert "locked" in str(exc).lower()
                    fence_probes.append(request.url.path)
                else:raise AssertionError("LEGACY_REVOCATION_FENCE_MISSING")
        return await call_next(request)
    with TestClient(bridge.ReadBridge(front,erp,pilot_db=main.DB_PATH),base_url='https://testserver') as dual:
        dual.cookies.set(cut.LEGACY_COOKIE,legacy_token)
        dual.cookies.set(cut.PG_COOKIE,os.environ['NARUV_TEST_TOKEN'])
        dh={'origin':'https://testserver','x-jw-pg-csrf':os.environ['NARUV_TEST_CSRF']}
        pay='/api/naruv-review/v1/drafts/payroll/worker-1/2026-11'
        r=dual.post(pay,headers=dh)
        assert r.status_code==200 and r.json()['gross_krw']==114000
        page=dual.get('/naruv-workspace')
        assert page.status_code==200 and '기업 업무 검토' in page.text
        assert dual.get('/naruv-workspace/app.js').status_code==200
        assert dual.get('/api/pg-stage/v90/me').json()['csrf_token']==os.environ['NARUV_TEST_CSRF']
        assert dual.post(pay,headers=dict(dh,origin='https://evil.test')).status_code==403
        assert dual.post('/api/naruv-review/v1/hr/workers/bridge-spoof/register/bridge-rid',headers=dh).status_code==403
        # Narrow CI-only write pilot: no changes to preexisting worker or ledger.
        worker='/api/naruv-review/v1/hr/workers/pilot-bridge'
        period=worker+'/periods/2026-03'
        reg=worker+'/register/pilot-register'
        wh=dict(dh,**{'x-naruv-confirm':'yes'})
        overview='/api/naruv-review/v1/valuation/overview'
        baseline=dual.post(overview,headers=dh).json()
        assert dual.post(reg,headers=wh).status_code==403
        os.environ[bridge.HR_PILOT_FLAG]=bridge.HR_PILOT_ACK
        try:
            assert dual.post(reg,headers=dh).status_code==422
            created=dual.post(reg,headers=wh)
            assert created.status_code==200
            assert dual.post(reg,headers=wh).json()==created.json()
            assert dual.post(reg.replace('pilot-bridge','worker-1'),headers=wh).status_code==403
            policy={'revision':'pilot-policy','hourly_krw':12000,'additional_bps':15000}
            assert dual.post(period+'/create/pilot-policy',headers=wh,json=policy).status_code==200
            attendance={'date':'2026-03-01','regular':60,'additional':60}
            assert dual.post(period+'/attendance/pilot-att',headers=wh,json=attendance).status_code==200
            review=dual.post(period+'/review',headers=dh)
            assert review.status_code==200
            digest=review.json()['review_sha256']
            assert dual.post(period+'/confirm/pilot-confirm',headers=wh,json={'review_sha256':'0'*64}).status_code==409
            confirmation=dual.post(period+'/confirm/pilot-confirm',headers=wh,json={'review_sha256':digest})
            assert confirmation.status_code==200 and confirmation.json()['payment_authorized'] is False
            assert dual.post(period+'/confirm/pilot-confirm',headers=wh,json={'review_sha256':digest}).json()==confirmation.json()
            result=dual.post('/api/naruv-review/v1/drafts/payroll/pilot-bridge/2026-03',headers=dh)
            assert result.status_code==200 and result.json()['gross_krw']==30000
            assert result.json()['statutory_validated'] is False
            assert dual.post(period+'/attendance/pilot-late',headers=wh,json={'date':'2026-03-02','regular':60,'additional':0}).status_code==409
            assert dual.post(worker+'/archive/pilot-archive',headers=wh).status_code==403
            # Explicit second fixture gate extends the existing narrow pilot,
            # not the default read-only workspace or real staff administration.
            os.environ[bridge.HR_LIFECYCLE_FLAG]=bridge.HR_PILOT_ACK
            try:
                second=worker+'/periods/2026-04'
                assert dual.post(second+'/create/pilot-second',headers=wh,json=policy).status_code==200
                assert dual.post(second+'/attendance/pilot-second-att',headers=wh,json={'date':'2026-04-01','regular':60,'additional':0}).status_code==200
                assert dual.post(worker+'/archive/pilot-open-archive',headers=wh).status_code==409
                before=dual.post(second+'/review',headers=dh).json()['review_sha256']
                amendment={'review_sha256':before,'kind':'attendance','date':'2026-04-01','regular':120,'additional':0}
                amended=dual.post(second+'/amend/pilot-amend',headers=wh,json=amendment)
                assert amended.status_code==200
                assert dual.post(second+'/amend/pilot-amend',headers=wh,json=amendment).json()==amended.json()
                assert dual.post(second+'/confirm/pilot-stale',headers=wh,json={'review_sha256':before}).status_code==409
                assert dual.post(second+'/confirm/pilot-second-confirm',headers=wh,json={'review_sha256':amended.json()['review_sha256']}).status_code==200
                pay2=dual.post('/api/naruv-review/v1/drafts/payroll/pilot-bridge/2026-04',headers=dh)
                assert pay2.status_code==200 and pay2.json()['gross_krw']==24000
                archived=dual.post(worker+'/archive/pilot-archive',headers=wh)
                assert archived.status_code==200
                assert dual.post(worker+'/archive/pilot-archive',headers=wh).json()==archived.json()
                refused=dual.post(worker+'/periods/2026-05/create/pilot-after-archive',headers=wh,json=policy)
                assert refused.status_code==404 and refused.json().get('detail')=='HR_NOT_FOUND', "ARCHIVED_WORKER_CONTRACT"
                after=dual.post(worker+'/inspect',headers=dh)
                assert after.status_code==200 and after.json()['active'] is False
                assert [p['period'] for p in after.json()['periods']]==['2026-03','2026-04']
                assert dual.post('/api/naruv-review/v1/drafts/payroll/pilot-bridge/2026-04',headers=dh).json()==pay2.json()
                if os.environ.get('NARUV_WORKSPACE_BROWSER')=='EPHEMERAL_ONLY':
                    from scripts.naruv_workspace_browser_ci import verify_browser
                    os.environ[bridge.HR_UI_FLAG]=bridge.HR_PILOT_ACK
                    try:verify_browser(bridge.ReadBridge(front,erp,pilot_db=main.DB_PATH),legacy_token,os.environ['NARUV_TEST_TOKEN'],hr_pilot=True)
                    finally:os.environ.pop(bridge.HR_UI_FLAG,None)
            finally:os.environ.pop(bridge.HR_LIFECYCLE_FLAG,None)
            assert dual.post(overview,headers=dh).json()==baseline
            assert reg in fence_probes and second+'/amend/pilot-amend' in fence_probes and worker+'/archive/pilot-archive' in fence_probes
            print("NARUV_HR_SQLITE_PG_FENCE_PASS",len(fence_probes),"actual independent SQLite write refusals")
        finally:os.environ.pop(bridge.HR_PILOT_FLAG,None)
        assert dual.post(worker+'/register/pilot-other',headers=wh).status_code==403
        with main.conn() as db:
            db.execute("DELETE FROM sessions WHERE id='bridge-legacy'")
        assert dual.post(pay,headers=dh).status_code==401
        assert dual.get('/naruv-workspace').status_code==401
    os.environ['NARUV_INTEGRATED_REVIEW']=''
    assert c.post('/api/naruv-review/v1/drafts/payroll/worker-1/2026-11',headers=h).status_code==404
    assert c.get('/api/health').status_code==200
finally:c.close()
"""
                browser_requested=env.get("NARUV_WORKSPACE_BROWSER")=="EPHEMERAL_ONLY"
                done=subprocess.run([sys.executable,"-c",script],cwd=ROOT,env=env,capture_output=True,text=True,timeout=180 if browser_requested else 60)
                # Never print child environment or arbitrary DB exceptions which may contain connection data.
                safe=done.stderr.replace(fixture.TRADE_DSN,"[CI_DSN]").replace(fixture.TOKENS["A"],"[CI_TOKEN]").replace(fixture.CSRF["A"],"[CI_CSRF]")
                self.assertEqual(done.returncode,0,"WORKS_STAGE_COMPOSITION_FAILED "+safe[-1500:])
                self.assertEqual(sum(line.startswith("NARUV_HR_SQLITE_PG_FENCE_PASS ") for line in done.stdout.splitlines()),1)
                print(next(line for line in done.stdout.splitlines() if line.startswith("NARUV_HR_SQLITE_PG_FENCE_PASS ")),flush=True)
                if browser_requested:
                    marker="NARUV_WORKSPACE_REAL_HTTPS_BROWSER_PASS desktop, mobile restriction, real PG reads, expired session, no JS errors"
                    self.assertEqual(done.stdout.splitlines().count(marker),1)
                    print(marker,flush=True)
                    hr_marker="NARUV_HR_PILOT_REAL_BROWSER_PASS confirmed writes, review, gross draft, archive, historical read"
                    self.assertEqual(done.stdout.splitlines().count(hr_marker),1)
                    print(hr_marker,flush=True)
                    network_marker="NARUV_REAL_HTTPS_READ_PASS 64 exact responses, 5 access denials, 4 unchanged post-load reads"
                    self.assertEqual(done.stdout.splitlines().count(network_marker),1)
                    network_metrics=[line for line in done.stdout.splitlines() if line.startswith("NARUV_REAL_HTTPS_READ_METRICS ")]
                    self.assertEqual(len(network_metrics),1)
                    print(network_metrics[0],flush=True)
                    print(network_marker,flush=True)
        def test_cost_document_manual_registration_and_isolation(self):
            import base64,json
            path="/drafts/documents/manual-doc";raw=b"%PDF-1.7 synthetic opaque fixture"
            obs=[{"field":"subtotal","value":100,"page":1},{"field":"vat","value":10,"page":1},{"field":"gross_amount","value":110,"page":1}]
            payload={"format":"pdf","original_base64":base64.b64encode(raw).decode(),"observations":obs}
            def submit(rid="doc-rid",who="A",data=None,code=200):
                return self.check(self.call(path+"/register/"+rid,who=who,raw=json.dumps(payload if data is None else data).encode()),code)
            r=submit();self.assertEqual(r,submit());self.assertFalse(r["content_verified"]);self.assertFalse(r["posting_authorized"])
            self.check(self.call(path,who="B"),404)
            self.assertEqual(self.check(self.call(path),200)["source_sha256"],r["source_sha256"])
            submit(rid="another",code=409)
            submit(data=dict(payload,original_base64=base64.b64encode(raw+b" changed").decode()),code=409)
            submit(who="B")
            self.assertEqual(self.check(self.call(path,who="B"),200)["source_sha256"],r["source_sha256"])
            self.assertNotEqual(self.check(self.call(path,who="B"),200)["review_sha256"],self.check(self.call(path),200)["review_sha256"])
            self.check(self.call(path+"/register/invalid",raw=json.dumps(dict(payload,original_base64="not base64")).encode()),422)
            with psycopg.connect(fixture.root_dsn) as c:
                saved=c.execute("SELECT observations FROM naruv_draft.documents WHERE org_id='ci-a' AND document_id='manual-doc'").fetchone()[0]
                self.assertEqual(c.execute("UPDATE naruv_draft.documents SET observations='[]'::jsonb WHERE org_id='ci-a' AND document_id='manual-doc'").rowcount,1)
            try:
                self.check(self.call(path),409)
                self.check(self.call(path,who="B"),200)
                submit(code=409)
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    self.assertEqual(c.execute("UPDATE naruv_draft.documents SET observations=%s::jsonb WHERE org_id='ci-a' AND document_id='manual-doc'",(json.dumps(saved),)).rowcount,1)
            self.check(self.call(path),200)
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertFalse(c.execute("SELECT has_table_privilege('jw_app_dev','naruv_draft.document_admissions','INSERT')").fetchone()[0])
                self.assertFalse(c.execute("SELECT has_function_privilege('naruv_native_stage','naruv_draft.admit_document(text,text,text,bytea,jsonb,boolean,text)','EXECUTE')").fetchone()[0])
        def test_cost_document_revision_history_and_stale_rejection(self):
            import base64,json
            path="/drafts/documents/revision-doc"
            obs=[{"field":"subtotal","value":100,"page":1},{"field":"vat","value":10,"page":1},{"field":"gross_amount","value":110,"page":1}]
            import io
            from openpyxl import Workbook
            wb=Workbook();wb.active.append(["synthetic",100]);stream=io.BytesIO();wb.save(stream);wb.close()
            original=stream.getvalue()
            self.assertEqual(original[:4],bytes.fromhex("504b0304"))
            payload={"format":"xlsx","original_base64":base64.b64encode(original).decode(),"observations":obs}
            escaped=b"PK"+bytes((92,))+b"x03"+bytes((92,))+b"x04fake"
            self.check(self.call(path+"/register/bad-signature",dict(payload,original_base64=base64.b64encode(escaped).decode())),422)
            self.check(self.call(path+"/register/wrong-format",dict(payload,format="pdf")),422)
            initial=self.check(self.call(path+"/register/rev-original",payload),200)
            before=self.check(self.call(path),200)
            changed=[dict(x,value=120) if x["field"]=="gross_amount" else x for x in obs]
            data={"previous_revision":before["revision"],"source_sha256":initial["source_sha256"],"observations":changed}
            self.check(self.call(path+"/revise/rev-first",data,who="B"),404)
            first=self.check(self.call(path+"/revise/rev-first",data),200)
            self.assertEqual(first,self.check(self.call(path+"/revise/rev-first",data),200))
            self.check(self.call(path+"/revise/stale",data),409)
            after=self.check(self.call(path),200)
            self.assertEqual(after["revision"],"rev-first")
            self.assertIn("AMOUNT_MISMATCH",after["issues"])
            self.assertEqual(after["source_sha256"],before["source_sha256"])
            self.assertNotEqual(after["source_binding_sha256"],before["source_binding_sha256"])
            current=dict(data,previous_revision="rev-first",observations=obs)
            self.check(self.call(path+"/revise/rev-second",current),200)
            self.assertEqual(first,self.check(self.call(path+"/revise/rev-first",data),200))
            final=self.check(self.call(path),200)
            self.assertEqual(final["review_sha256"],before["review_sha256"])
            self.assertNotEqual(final["source_binding_sha256"],before["source_binding_sha256"])
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertEqual(c.execute("SELECT original_bytes,observations FROM naruv_draft.documents WHERE org_id='ci-a' AND document_id='revision-doc'").fetchone(),(original,obs))
                self.assertEqual(c.execute("SELECT count(*) FROM naruv_draft.document_revisions WHERE org_id='ci-a' AND document_id='revision-doc'").fetchone()[0],2)
                self.assertFalse(c.execute("SELECT has_table_privilege('jw_app_dev','naruv_draft.document_revisions','UPDATE')").fetchone()[0])
    names=[n for n in unittest.defaultTestLoader.getTestCaseNames(Valuation) if n.startswith("test_cost_")]
    if len(names)!=73:raise RuntimeError("COST_CASE_COUNT_CHANGED")
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Valuation(n) for n in names))
    if not result.wasSuccessful() or result.testsRun!=73 or result.skipped or result.expectedFailures or result.unexpectedSuccesses:raise SystemExit(1)
    print("NARUV_VALUATION_PASS: 73 isolated PG17 cost, reconciliation, posting, return and ledger audit cases; no statutory posting.")
