import unittest
from app.naruv_kr_payroll_review import wage_review,deduction_reconciliation,DEDUCTIONS,source_bound_review,pension_reference_2026
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


class SourceBoundKRReview(unittest.TestCase):
    def inputs(self):
        from app.naruv_payroll_draft import draft_gross
        src=dict(tenant="a",worker="w",period="2026-11",policy_revision="v1",hourly_krw=12000,
                 minutes_by_day=[{"date":"2026-11-02","regular":480,"additional":60}])
        expected=draft_gross(**src,multiplier_bps={"regular":10000,"additional":15000})["draft_sha256"]
        return dict(src,additional_bps=15000,expected_draft_sha256=expected,
                    ordinary_hourly=12000,classification_sha256="a"*64,
                    classified_days=[day(o=60,n=60)],deductions=deductions())
    def test_exact_source_and_manual_net(self):
        r=source_bound_review(**self.inputs())
        self.assertEqual(r["wage"]["gross_estimate_krw"],120000)
        self.assertEqual(r["deductions"]["net_estimate_krw"],114000)
        for k in ("statutory_validated","payment_authorized","production_authorized"):
            self.assertIs(r[k],False)
        self.assertTrue(r["requires_human_review"])
    def test_stale_source_and_cross_tenant(self):
        for changes in ({"tenant":"b"},{"worker":"other"},{"policy_revision":"v2"},
                        {"hourly_krw":13000},{"additional_bps":20000},{"expected_draft_sha256":"0"*64}):
            with self.subTest(changes=changes),self.assertRaisesRegex(PayrollBlocked,"KR_SOURCE_CHANGED"):
                source_bound_review(**dict(self.inputs(),**changes))
    def test_classification_cannot_invent_or_drop_minutes(self):
        for rows in ([day(o=59)],[day(o=61)],[day(r=479,o=61)],
                     [day(d="2026-11-03",o=60)],[day(o=60),day(d="2026-11-03",r=0)]):
            with self.subTest(rows=rows),self.assertRaisesRegex(PayrollBlocked,"KR_ATTENDANCE_MISMATCH"):
                source_bound_review(**dict(self.inputs(),classified_days=rows))
    def test_manual_deduction_binding_changes(self):
        kw=self.inputs();r=source_bound_review(**kw)
        kw["deductions"]["health"]["evidence_sha256"]="c"*64
        self.assertNotEqual(r["review_binding_sha256"],source_bound_review(**kw)["review_binding_sha256"])


class PensionReference2026(unittest.TestCase):
    def ref(self,**kw):
        return pension_reference_2026(**dict(dict(tenant="a",worker="w",period="2026-07",
            assessed_base_krw=1000000,assessment_sha256="b"*64),**kw))
    def test_official_example_and_scope(self):
        r=self.ref();self.assertEqual(r["employee_exact"],{"numerator":47500,"denominator":1})
        self.assertEqual(r["total_exact"],{"numerator":95000,"denominator":1})
        self.assertFalse(r["statutory_validated"]);self.assertFalse(r["payment_authorized"])
    def test_effective_month_and_bounds(self):
        for month,low,high in (("06",400000,6370000),("07",410000,6590000)):
            for base in (low,high):
                self.assertEqual(self.ref(period="2026-"+month,assessed_base_krw=base)["base_limits_krw"],[low,high])
            for base in (low-1000,high+1000,low+1,True):
                with self.assertRaisesRegex(PayrollBlocked,"KR_NPS_BASE"):
                    self.ref(period="2026-"+month,assessed_base_krw=base)
        self.assertEqual(self.ref(assessed_base_krw=411000)["employee_exact"],{"numerator":39045,"denominator":2})
    def test_invalid_period_and_binding(self):
        for period in ("2025-12","2027-01","2026-00","2026-13"):
            with self.assertRaisesRegex(PayrollBlocked,"KR_NPS_PERIOD"):self.ref(period=period)
        for kw in ({"worker":"other"},{"tenant":"b"},{"assessment_sha256":"c"*64},{"period":"2026-08"}):
            self.assertNotEqual(self.ref()["reference_sha256"],self.ref(**kw)["reference_sha256"])
        with self.assertRaisesRegex(PayrollBlocked,"KR_NPS_EVIDENCE"):self.ref(assessment_sha256="bad")


class InsuranceReference2026(unittest.TestCase):
    def ref(self,**kw):
        from app.naruv_kr_payroll_review import insurance_reference_2026
        return insurance_reference_2026(**dict(dict(tenant="a",worker="w",period="2026-11",
            health_base_krw=2000000,employment_base_krw=3000000,assessment_sha256="a"*64,
            scope="ORDINARY_FULL_MONTH_NO_RELIEF_ASSESSED_BASES"),**kw))
    def test_rates_and_independent_bases(self):
        r=self.ref()
        self.assertEqual(r["employee_exact"],{
            "health":{"numerator":71900,"denominator":1},
            "long_term_care":{"numerator":9448,"denominator":1},
            "employment_insurance":{"numerator":27000,"denominator":1}})
        self.assertEqual(r["employee_total_exact"],{"numerator":108348,"denominator":1})
        self.assertFalse(r["statutory_validated"]);self.assertFalse(r["payment_authorized"])
    def test_restricted_scope_and_binding(self):
        for kw in ({"period":"2027-01"},{"health_base_krw":999999},{"health_base_krw":10000001},
                   {"employment_base_krw":True},{"scope":"RELIEF"},{"assessment_sha256":"bad"}):
            with self.assertRaises(PayrollBlocked):self.ref(**kw)
        for kw in ({"tenant":"b"},{"worker":"other"},{"period":"2026-12"},
                   {"assessment_sha256":"b"*64},{"employment_base_krw":3000001}):
            self.assertNotEqual(self.ref()["reference_sha256"],self.ref(**kw)["reference_sha256"])
