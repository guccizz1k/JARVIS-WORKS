"""Restricted paid-rest statement draft; no legal or payment acceptance."""
import unittest
from tests.test_naruv_kr_payroll_review import FixedWeekPaidRestLeave,deductions
from app.naruv_kr_payroll_review import fixed_week_wage_statement_draft_2026 as statement,fixed_week_monthly_payroll_review_2026 as monthly,PayrollBlocked
from app.naruv_payroll_draft import draft_gross

class PaidStatement(unittest.TestCase):
    def fixture(self,rate=12001):
        a=FixedWeekPaidRestLeave().fixture()
        a["weeks"][1]["days"][1].update(status="APPROVED_FULL_DAY_ANNUAL_LEAVE",actual_minutes=0)
        a["weeks"][2]["days"][0]["actual_minutes"]=421
        rows=[dict(date=d["date"],regular=d["actual_minutes"],additional=0) for w in a["weeks"] for d in w["days"] if d["date"].startswith("2026-11-") and d["status"]=="PRESENT"]
        a.update(base_hourly=rate,ordinary_hourly=rate+1,policy_revision="r1",minutes_by_day=rows,additional_bps=15000,deductions=deductions())
        a["expected_draft_sha256"]=draft_gross(tenant="a",worker="w",period="2026-11",policy_revision="r1",hourly_krw=rate,minutes_by_day=rows,multiplier_bps={"regular":10000,"additional":15000})["draft_sha256"]
        a.update(payment_date="2026-12-01",completeness_assessment_sha256="a"*64,expected_monthly_review_sha256=monthly(**a)["review_sha256"])
        return a
    def test_breakdown_and_fraction(self):
        for rate in (12000,12001,12059):
            a=self.fixture(rate);r=statement(**a)
            self.assertEqual([x["kind"] for x in r["components"]],["work_base","weekly_paid_rest","approved_annual_leave"])
            self.assertEqual(r["components"][1]["minutes"],2400)
            self.assertEqual(r["components"][2]["minutes"],480)
            self.assertEqual(sum(x["amount_krw"] for x in r["components"]),r["gross_krw"])
            self.assertEqual(r["gross_krw"]-r["deductions_krw"],r["net_krw"])
            self.assertTrue(all(r[k] is False for k in ("completeness_verified","payment_date_verified","statutory_validated","payment_authorized","delivery_authorized","production_authorized")))
    def test_source_and_scope(self):
        a=self.fixture()
        for change in (dict(expected_monthly_review_sha256="0"*64),dict(completeness_assessment_sha256="bad"),dict(payment_date="2027-01-01"),dict(payment_date="2026-11-31"),dict(expected_draft_sha256="0"*64)):
            with self.assertRaises(PayrollBlocked):statement(**dict(a,**change))
    def test_assessment_binding(self):
        a=self.fixture()
        self.assertNotEqual(statement(**a)["review_sha256"],statement(**dict(a,completeness_assessment_sha256="b"*64))["review_sha256"])
if __name__=="__main__":
    unittest.main()
