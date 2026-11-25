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


class WithholdingReference2026(unittest.TestCase):
    def ref(self,**kw):
        from app.naruv_kr_payroll_review import withholding_reference_2026
        return withholding_reference_2026(**dict(dict(tenant="a",worker="w",period="2026-11",
            table_amount_krw=100000,selection_percent=100,assessment_sha256="a"*64,
            scope="ASSESSED_ORDINARY_MONTHLY_TABLE_NO_RELIEF"),**kw))
    def test_selection_and_local_share(self):
        for choice,national in ((80,80000),(100,100000),(120,120000)):
            r=self.ref(selection_percent=choice)
            self.assertEqual(r["national_exact"],{"numerator":national,"denominator":1})
            self.assertEqual(r["local_exact"],{"numerator":national//10,"denominator":1})
            self.assertFalse(r["statutory_validated"]);self.assertFalse(r["payment_authorized"])
        self.assertEqual(self.ref(table_amount_krw=1,selection_percent=80)["local_exact"],{"numerator":2,"denominator":25})
        self.assertEqual(self.ref(table_amount_krw=0)["total_exact"],{"numerator":0,"denominator":1})
    def test_scope_input_and_evidence(self):
        for kw in ({"period":"2027-01"},{"selection_percent":90},{"selection_percent":True},
                   {"table_amount_krw":-1},{"table_amount_krw":1.5},{"scope":"BONUS"},{"assessment_sha256":"bad"}):
            with self.assertRaises(PayrollBlocked):self.ref(**kw)
        for kw in ({"tenant":"b"},{"worker":"other"},{"period":"2026-12"},{"assessment_sha256":"b"*64},{"selection_percent":80}):
            self.assertNotEqual(self.ref()["reference_sha256"],self.ref(**kw)["reference_sha256"])


class OfficialTablePage14(unittest.TestCase):
    def ref(self,**kw):
        from app.naruv_kr_payroll_review import withholding_table_review_2026
        return withholding_table_review_2026(**dict(dict(tenant="a",worker="w",withholding_date="2026-11-26",
            taxable_monthly_krw=3140000,eligible_family_count=1,eligible_children_8_20=0,
            selection_percent=100,assessment_sha256="a"*64,scope="ASSESSED_ORDINARY_MONTHLY_TABLE_NO_RELIEF"),**kw))
    def test_official_source_anchors(self):
        for wage,family,expected in ((3140000,1,86330),(3159999,11,3200),
            (3160000,1,88040),(3280000,3,45070),(3500000,2,102220),(3659999,11,13450)):
            with self.subTest(wage=wage,family=family):
                r=self.ref(taxable_monthly_krw=wage,eligible_family_count=family)
                self.assertEqual(r["table_amount_krw"],expected)
                self.assertFalse(r["statutory_validated"]);self.assertFalse(r["payment_authorized"])
    def test_every_cell_and_both_band_edges(self):
        from app.naruv_kr_payroll_review import KR_TABLE_ROWS
        self.assertEqual(len(KR_TABLE_ROWS),26)
        for i,row in enumerate(KR_TABLE_ROWS):
            self.assertEqual(len(row),11)
            for j,expected in enumerate(row):
                for wage in (3140000+i*20000,3159999+i*20000):
                    with self.subTest(row=i,family=j,wage=wage):
                        self.assertEqual(self.ref(taxable_monthly_krw=wage,eligible_family_count=j+1)["table_amount_krw"],expected)
    def test_child_adjustment_and_scope(self):
        self.assertEqual(self.ref(eligible_family_count=2,eligible_children_8_20=1)["child_adjusted_krw"],48000)
        self.assertEqual(self.ref(eligible_family_count=3,eligible_children_8_20=2)["child_adjusted_krw"],0)
        self.assertEqual(self.ref(taxable_monthly_krw=3500000,eligible_family_count=4,eligible_children_8_20=3)["child_adjusted_krw"],0)
        for kw in ({"taxable_monthly_krw":769999},{"taxable_monthly_krw":10000000},
                   {"withholding_date":"2026-02-28"},{"withholding_date":"2026-11-31"},
                   {"eligible_family_count":129},{"eligible_children_8_20":1},{"selection_percent":90},
                   {"assessment_sha256":"bad"}):
            with self.assertRaises(PayrollBlocked):self.ref(**kw)
    def test_proof_binds_exact_input(self):
        a=self.ref()["review_sha256"]
        for kw in ({"tenant":"b"},{"worker":"other"},{"withholding_date":"2026-11-27"},
                   {"taxable_monthly_krw":3140001},{"selection_percent":80},{"assessment_sha256":"b"*64}):
            self.assertNotEqual(a,self.ref(**kw)["review_sha256"])


class OfficialTableExtendedPages(unittest.TestCase):
    ref=OfficialTablePage14.ref
    def test_extended_anchors(self):
        for wage,family,amount,lo,hi in ((2810000,1,57660,2810000,2820000),(2899999,10,1170,2890000,2900000),
              (2999999,11,0,2990000,3000000),(3000000,1,74350,3000000,3020000),(3139999,11,2770,3120000,3140000),
              (3660000,1,146780,3660000,3680000),(4179999,11,28540,4160000,4180000),
              (4180000,1,219990,4180000,4200000),(4699999,11,58930,4680000,4700000),
              (4700000,1,293390,4700000,4720000),(5000000,4,219100,5000000,5020000),
              (5219999,11,113650,5200000,5220000),(5220000,1,366320,5220000,5240000),
              (5600000,7,240250,5600000,5620000),(5739999,11,180730,5720000,5740000),
              (5740000,1,439250,5740000,5760000),(5840000,4,353350,5840000,5860000),
              (6259999,11,277400,6240000,6260000),(6260000,1,564870,6260000,6280000),
              (6640000,3,481320,6640000,6660000),(6779999,11,346040,6760000,6780000)):
            r=self.ref(taxable_monthly_krw=wage,eligible_family_count=family)
            self.assertEqual((r["table_amount_krw"],r["table_low_krw"],r["table_high_exclusive_krw"]),(amount,lo,hi))
    def test_extended_all_cells(self):
        from app.naruv_kr_payroll_review import KR_TABLE_LOWEST,KR_TABLE_LOWER,KR_TABLE_BEFORE,KR_TABLE_AFTER
        for rows,low,steps in ((KR_TABLE_LOWEST,770000,[5000]*146+[10000]*79),(KR_TABLE_LOWER,2290000,[10000]*52),(KR_TABLE_BEFORE,2810000,[10000]*19+[20000]*7),(KR_TABLE_AFTER,3660000,[20000]*317)):
            self.assertEqual(len(rows),len(steps))
            for row,step in zip(rows,steps,strict=True):
                for j,amount in enumerate(row):
                    for wage in (low,low+step-1):
                        with self.subTest(wage=wage,family=j+1):
                            self.assertEqual(self.ref(taxable_monthly_krw=wage,eligible_family_count=j+1)["table_amount_krw"],amount)
                low+=step

    def test_lower_official_independent_anchors(self):
        for wage,family,amount,lo,hi in (
            (2290000,1,28840,2290000,2300000),
            (2399999,7,0,2390000,2400000),
            (2400000,7,1030,2400000,2410000),
            (2549999,7,3870,2540000,2550000),
            (2550000,1,37310,2550000,2560000),
            (2570000,8,1130,2570000,2580000),
            (2730000,9,1150,2730000,2740000),
            (2809999,9,2630,2800000,2810000)):
            with self.subTest(wage=wage,family=family):
                r=self.ref(taxable_monthly_krw=wage,eligible_family_count=family)
                self.assertEqual((r["table_amount_krw"],r["table_low_krw"],r["table_high_exclusive_krw"]),(amount,lo,hi))

    def test_lowest_official_anchors(self):
        for wage,family,amount,lo,hi in (
          (770000,1,0,770000,775000),(1059999,1,0,1055000,1060000),
          (1060000,1,1040,1060000,1065000),(1340000,2,1060,1340000,1345000),
          (1499999,2,4260,1495000,1500000),(1500000,2,4420,1500000,1510000),
          (1720000,3,1040,1720000,1730000),(1770000,3,2030,1770000,1780000),
          (1890000,4,1040,1890000,1900000),(2060000,5,1040,2060000,2070000),
          (2230000,6,1040,2230000,2240000),(2289999,6,2030,2280000,2290000)):
            with self.subTest(wage=wage,family=family):
                r=self.ref(taxable_monthly_krw=wage,eligible_family_count=family)
                self.assertEqual((r["table_amount_krw"],r["table_low_krw"],r["table_high_exclusive_krw"]),(amount,lo,hi))

    def test_final_printed_bands(self):
        for wage,family,amount in ((6780000,1,682810),(7299999,11,414680),
          (7300000,1,800740),(7819999,11,486310),(7820000,3,730530),
          (8339999,11,596130),(8340000,1,1036740),(8859999,11,709680),
          (8860000,3,954040),(9379999,11,823240),(9380000,1,1299240),
          (9899999,11,936810),(9900000,1,1476690),(9999999,11,958650)):
            with self.subTest(wage=wage,family=family):
                self.assertEqual(self.ref(taxable_monthly_krw=wage,eligible_family_count=family)["table_amount_krw"],amount)


class HighWageAndNationalCollection(unittest.TestCase):
    def args(self,**changes):
        return dict(dict(tenant="a",worker="w",withholding_date="2026-11-26",
            taxable_monthly_krw=10000000,eligible_family_count=1,eligible_children_8_20=0,
            selection_percent=100,assessment_sha256="a"*64,
            scope="ASSESSED_ORDINARY_MONTHLY_TABLE_NO_RELIEF"),**changes)
    def test_exact_formula_boundaries(self):
        from app.naruv_kr_payroll_review import withholding_high_reference_2026
        from fractions import Fraction
        base=1507400
        for wage,extra in ((10000000,0),(10000001,Fraction(25000343,1000)),
            (14000000,1397000),(14000001,1397000+Fraction(3724,10000)),
            (28000000,6610600),(28000001,6610600+Fraction(392,1000)),
            (30000000,7394600),(30000001,7394600+Fraction(2,5)),
            (45000000,13394600),(45000001,13394600+Fraction(42,100)),
            (87000000,31034600),(87000001,31034600+Fraction(45,100))):
            r=withholding_high_reference_2026(**self.args(taxable_monthly_krw=wage))
            self.assertEqual(Fraction(**r["national_exact"]),base+extra)
            self.assertFalse(r["payment_authorized"])
        r=withholding_high_reference_2026(**self.args(eligible_family_count=2,eligible_children_8_20=1,selection_percent=80))
        self.assertEqual(Fraction(**r["national_exact"]),Fraction((1431570-20830)*80,100))
        for changes in (dict(taxable_monthly_krw=9999999),dict(taxable_monthly_krw=10**9+1),
                        dict(eligible_family_count=129),dict(withholding_date="2026-02-28")):
            with self.assertRaises(PayrollBlocked):withholding_high_reference_2026(**self.args(**changes))
    def test_collection_small_amount_and_ten_won(self):
        from app.naruv_kr_payroll_review import national_collection_review_2026
        for wage,percent,expected in ((1060000,80,0),(1060000,100,1040),
              (1065000,120,1330),(10000001,100,1532400),(14000000,100,2904400)):
            r=national_collection_review_2026(**self.args(taxable_monthly_krw=wage,selection_percent=percent))
            self.assertEqual(r["national_collection_krw"],expected)
            self.assertFalse(r["statutory_validated"])
            self.assertFalse(r["payment_authorized"])

    def test_family_above_eleven(self):
        from app.naruv_kr_payroll_review import withholding_high_reference_2026,withholding_table_review_2026
        self.assertEqual(withholding_table_review_2026(**self.args(taxable_monthly_krw=9900000,eligible_family_count=12))["table_amount_krw"],911180)
        self.assertEqual(withholding_high_reference_2026(**self.args(eligible_family_count=12))["national_exact"],{"numerator":930840,"denominator":1})
        self.assertEqual(withholding_table_review_2026(**self.args(taxable_monthly_krw=1060000,eligible_family_count=128))["table_amount_krw"],0)

    def test_same_snapshot_integrated_deduction_review(self):
        from app.naruv_kr_payroll_review import ordinary_monthly_deduction_review_2026,wage_review
        days=[dict(date=f"2026-11-{i:02d}",regular=480,overtime=0,holiday_first8=0,holiday_after8=0,night=0) for i in range(1,26)]
        wage_args=dict(tenant="a",worker="w",period="2026-11",base_hourly=15000,ordinary_hourly=15000,
            classification_sha256="b"*64,days=days)
        gross=wage_review(**wage_args,scope="ADULT_HOURLY_5PLUS_MANUALLY_CLASSIFIED")
        self.assertEqual(gross["gross_estimate_krw"],3000000)
        amounts={"income_tax":74350,"local_income_tax":7435,"pension":142500,"health":107850,
                 "long_term_care":14172,"employment_insurance":27000}
        deductions={k:dict(amount_krw=v,assessment="ASSESSED",evidence_sha256="c"*64) for k,v in amounts.items()}
        args=dict(wage_args,expected_wage_sha256=gross["review_sha256"],withholding_date="2026-11-26",
            taxable_monthly_krw=3000000,eligible_family_count=1,eligible_children_8_20=0,selection_percent=100,
            tax_assessment_sha256="d"*64,pension_base_krw=3000000,pension_assessment_sha256="e"*64,
            health_base_krw=3000000,employment_base_krw=3000000,insurance_assessment_sha256="f"*64,
            assessed_deductions=deductions)
        r=ordinary_monthly_deduction_review_2026(**args)
        self.assertEqual(r["status"],"REFERENCE_MATCH_ONLY")
        self.assertEqual(r["manual_reconciliation"]["net_estimate_krw"],2626693)
        self.assertFalse(r["payment_authorized"])
        changed=dict(deductions,pension=dict(deductions["pension"],amount_krw=142490))
        out=ordinary_monthly_deduction_review_2026(**dict(args,assessed_deductions=changed))
        self.assertEqual((out["status"],out["mismatches"]),("ASSESSMENT_DIFFERENCE_REVIEW_REQUIRED",["pension"]))
        for change in (dict(expected_wage_sha256="0"*64),dict(tenant="b"),dict(withholding_date="2026-12-01"),
                       dict(taxable_monthly_krw=3000001),dict(assessed_deductions={})):
            with self.assertRaises(PayrollBlocked):ordinary_monthly_deduction_review_2026(**dict(args,**change))



class IndependentSourceAudit(unittest.TestCase):
    def test_exact_cells_no_guessing(self):
        from scripts.naruv_tax_source_audit import cells,compare,expected_rows
        from pathlib import Path
        self.assertEqual(cells("1,040 - - - - - - - - - -"),(1040,)+(0,)*10)
        for malformed in ("1040 ----------","1,04 - - - - - - - - - -","1040 - -","1040 - - - - - - - - - - -"):
            with self.assertRaises(ValueError):cells(malformed)
        actual=({9900000:(9920000,(1476690,1401010,1181180,1151180,1121180,1091180,1061180,1031180,1001180,971180,941180))},
            (1507400,1431570,1200840,1170840,1140840,1110840,1080840,1050840,1020840,990840,960840))
        source=(Path(__file__).resolve().parents[1]/"app/naruv_kr_payroll_review.py").read_text("utf-8")
        rows,base=expected_rows(source)
        self.assertEqual(len(rows),646)
        self.assertEqual(compare(actual,({9900000:rows[9900000]},base)),[])
        bad=dict(rows);bad[9900000]=(9920000,(1476680,)+rows[9900000][1][1:])
        self.assertEqual(compare(actual,({9900000:bad[9900000]},base)),[(9900000,1,1476690,1476680)])
        with self.assertRaisesRegex(ValueError,"SOURCE_BAND_MISMATCH"):compare(actual,(rows,base))
    def test_incomplete_source_never_passes(self):
        from scripts.naruv_tax_source_audit import extract
        for bad in ("2026. 2. 27.", "2026. 2. 27.\f"+"empty\f"*26):
            with self.assertRaises(ValueError):extract(bad)
