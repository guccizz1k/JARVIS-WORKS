import unittest
from app.naruv_kr_payroll_review import wage_review,deduction_reconciliation,DEDUCTIONS
from app.naruv_payroll_draft import PayrollBlocked

def day(d="2026-11-02",r=480,o=0,h=0,x=0,n=0):
    return {"date":d,"regular":r,"overtime":o,"holiday_first8":h,"holiday_after8":x,"night":n}
def wage(**kw):
    v=dict(tenant="a",worker="w",period="2026-11",base_hourly=12000,ordinary_hourly=12000,
           classification_sha256="a"*64,days=[day()],scope="ADULT_HOURLY_5PLUS_MANUALLY_CLASSIFIED")
    v.update(kw);return wage_review(**v)
def deductions():
    return {k:{"amount_krw":1000,"evidence_sha256":"b"*64,"assessment":"ASSESSED"} for k in DEDUCTIONS}

class KRReview(unittest.TestCase):
    def test_regular(self):
        r=wage();self.assertEqual(r["gross_estimate_krw"],96000);self.assertFalse(r["statutory_validated"])
        self.assertFalse(r["payment_authorized"])
    def test_overlapping_night(self):
        self.assertEqual(wage(days=[day(o=60,n=60)])["gross_estimate_krw"],120000)
    def test_holiday_over8_night(self):
        self.assertEqual(wage(days=[day(r=0,h=480,x=60,n=60)])["gross_estimate_krw"],174000)
    def test_separate_ordinary_wage_and_fraction(self):
        r=wage(base_hourly=10320,ordinary_hourly=12000,days=[day(r=0,o=1)])
        self.assertEqual(r["gross_exact"],{"numerator":272,"denominator":1})
        r=wage(base_hourly=10321,ordinary_hourly=10321,days=[day(r=1)])
        self.assertEqual(r["gross_exact"],{"numerator":10321,"denominator":60})
    def test_minimum_base_screen_not_legal_conclusion(self):
        self.assertTrue(wage(base_hourly=10319)["base_hourly_below_2026_floor"])
        self.assertFalse(wage(base_hourly=10320)["base_hourly_below_2026_floor"])
        self.assertFalse(wage(base_hourly=10320)["statutory_validated"])
    def test_invalid_classification(self):
        for rows in ([day(r=481)],[day(r=1,h=1)],[day(r=0,h=479,x=1)],[day(r=0,n=1)],[day(r=True)],[day(),day()],[day(d="2026-11-31")]):
            with self.subTest(rows=rows),self.assertRaises(PayrollBlocked):wage(days=rows)
        for x in ({"scope":"UNSUPPORTED"},{"period":"2027-01"},{"classification_sha256":"x"},{"ordinary_hourly":1}):
            with self.assertRaises(PayrollBlocked):wage(**x)
    def test_scope_order_and_source_proof(self):
        rows=[day(),day(d="2026-11-03",r=60)]
        self.assertEqual(wage(days=rows),wage(days=rows[::-1]))
        for kw in ({"tenant":"b"},{"worker":"other"},{"classification_sha256":"b"*64}):
            self.assertNotEqual(wage(**kw)["review_sha256"],wage()["review_sha256"])
    def test_manual_deductions_no_payment(self):
        d=deductions();r=deduction_reconciliation(wage_result=wage(),deductions=d)
        self.assertEqual((r["deductions_krw"],r["net_estimate_krw"]),(6000,90000))
        self.assertFalse(r["payment_authorized"]);self.assertFalse(r["statutory_validated"])
        d["health"]["evidence_sha256"]="c"*64
        self.assertNotEqual(r["reconciliation_sha256"],deduction_reconciliation(wage_result=wage(),deductions=d)["reconciliation_sha256"])
    def test_deduction_invalid(self):
        for bad in ({},dict(deductions(),health={"amount_krw":100000,"evidence_sha256":"b"*64,"assessment":"ASSESSED"}),dict(deductions(),health={"amount_krw":1,"evidence_sha256":"b"*64,"assessment":"NOT_APPLICABLE"})):
            with self.assertRaises(PayrollBlocked):deduction_reconciliation(wage_result=wage(),deductions=bad)
