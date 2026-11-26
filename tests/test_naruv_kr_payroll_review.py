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
        rounded=dict(deductions,local_income_tax=dict(deductions["local_income_tax"],amount_krw=7430))
        v2=ordinary_monthly_deduction_review_2026(**dict(args,assessed_deductions=rounded,collection_policy="ASSESSED_LOCAL_COLLECTION_V2"))
        self.assertEqual(v2["status"],"REFERENCE_MATCH_ONLY")
        self.assertEqual(v2["manual_reconciliation"]["net_estimate_krw"],2626698)
        self.assertEqual(v2["insurance_rounding_status"],"AGENCY_ASSESSMENT_REQUIRED")
        self.assertNotEqual(v2["review_sha256"],r["review_sha256"])
        changed_national=dict(rounded,income_tax=dict(rounded["income_tax"],amount_krw=70000),
            local_income_tax=dict(rounded["local_income_tax"],amount_krw=7000))
        out2=ordinary_monthly_deduction_review_2026(**dict(args,assessed_deductions=changed_national,collection_policy="ASSESSED_LOCAL_COLLECTION_V2"))
        self.assertEqual(out2["mismatches"],["income_tax"])
        with self.assertRaises(PayrollBlocked):ordinary_monthly_deduction_review_2026(**dict(args,collection_policy="UNKNOWN"))
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


    def test_final_page_threshold_is_not_duplicate_numeric_row(self):
        from scripts.naruv_tax_source_audit import extract
        # Synthetic layout fixture tests parsing, not independent legal data.
        pages=["2026. 2. 27."]
        low=770
        for count in [17]+[26]*24+[5]:
            lines=[]
            for _ in range(count):
                step=5 if low<1500 else (10 if low<3000 else 20)
                lines.append(f"{low:,} {low+step:,} "+" ".join(["-"]*11))
                low+=step
            pages.append("\n".join(lines))
        self.assertEqual(low,10000)
        last="\n10,000천원 "+" ".join(["1,000"]*11)
        formula="\n10,000천원 초과 (10,000천원인 경우의 해당 세액)\n14,000천원 이하"
        pages[-1]+=last+formula
        rows,ten=extract("\f".join(pages)+"\f")
        self.assertEqual(len(rows),646)
        self.assertEqual(ten,(1000,)*11)
        pages[-1]+=last
        with self.assertRaisesRegex(ValueError,"SOURCE_DUPLICATE_10M"):
            extract("\f".join(pages)+"\f")


class LocalCollectionReference(unittest.TestCase):
    def test_assessed_base_and_truncation(self):
        from app.naruv_kr_payroll_review import local_collection_review_2026
        args=dict(tenant="a",worker="w",period="2026-11",assessment_sha256="a"*64,
                  scope="ASSESSED_ORDINARY_MONTHLY_WITHHOLDING_NO_EXCEPTIONS")
        for national,expected in ((0,0),(1000,100),(1010,100),(1090,100),(1100,110),(74350,7430)):
            with self.subTest(national=national):
                r=local_collection_review_2026(**args,assessed_national_collection_krw=national)
                self.assertEqual(r["local_collection_krw"],expected)
                self.assertFalse(r["payment_authorized"])
                self.assertFalse(r["statutory_validated"])
        for val in (True,-10,990,1001,10**9+10):
            with self.assertRaises(PayrollBlocked):
                local_collection_review_2026(**args,assessed_national_collection_krw=val)
        for change in (dict(scope="INSTALLMENT"),dict(assessment_sha256="bad"),dict(period="2027-01")):
            with self.assertRaises(PayrollBlocked):
                local_collection_review_2026(**dict(args,**change),assessed_national_collection_krw=1000)


class SourceEditionPin(unittest.TestCase):
    def test_changed_pdf_fails_closed(self):
        from scripts.naruv_tax_source_audit import verify_source_digest,OFFICIAL_PDF_SHA256
        self.assertRegex(OFFICIAL_PDF_SHA256,r"^[0-9a-f]{64}$")
        for raw in (b"%PDF-modified",b"",None):
            with self.assertRaisesRegex(ValueError,"SOURCE_EDITION_DIGEST_CHANGED"):verify_source_digest(raw)


class AgencyDeductionReview(unittest.TestCase):
    def test_declared_base_clamp_and_assessment(self):
        from app.naruv_kr_payroll_review import pension_declared_base_review_2026
        args=dict(tenant="a",worker="w",assessment_sha256="a"*64)
        for period,declared,base in (("2026-06",399999,400000),("2026-07",409999,410000),
            ("2026-07",1234567,1234000),("2026-07",6600000,6590000),("2026-06",6600000,6370000)):
            with self.subTest(period=period,declared=declared):
                r=pension_declared_base_review_2026(**args,period=period,declared_income_krw=declared,assessed_base_krw=base)
                self.assertEqual(r["reference_base_krw"],base)
                self.assertEqual(r["status"],"DECLARED_BASE_REFERENCE_MATCH_ONLY")
                self.assertFalse(r["payment_authorized"])
        r=pension_declared_base_review_2026(**args,period="2026-07",declared_income_krw=1234567,assessed_base_krw=1235000)
        self.assertEqual(r["status"],"AGENCY_BASE_DIFFERENCE_REVIEW_REQUIRED")
        for val in (True,-1,10**9+1):
            with self.assertRaises(PayrollBlocked):pension_declared_base_review_2026(**args,period="2026-07",declared_income_krw=val,assessed_base_krw=410000)

    def test_agency_scope_and_snapshot(self):
        from app.naruv_kr_payroll_review import source_bound_agency_deduction_review_2026
        from app.naruv_payroll_draft import hash_input
        args=SourceBoundKRReview().inputs()
        args["deductions"]["pension"]=dict(amount_krw=0,evidence_sha256="c"*64,assessment="ASSESSED")
        args["deductions"]["employment_insurance"]=dict(amount_krw=0,evidence_sha256="d"*64,assessment="NOT_APPLICABLE")
        cases={k:dict(tenant="a",worker="w",period="2026-11",case="ORDINARY",
            amount_krw=args["deductions"][k]["amount_krw"],evidence_sha256=args["deductions"][k]["evidence_sha256"])
            for k in ("pension","health","long_term_care","employment_insurance")}
        cases["pension"]["case"]="CONTRIBUTION_EXCEPTION"
        cases["employment_insurance"]["case"]="NOT_ENROLLED"
        cases["health"]["case"]="LEAVE"
        digest=lambda rows:hash_input({"v":"KR_AGENCY_SNAPSHOT_2026_V1","tenant":"a","worker":"w","period":"2026-11","cases":rows})
        args.update(agency_cases=cases,expected_agency_snapshot_sha256=digest(cases))
        r=source_bound_agency_deduction_review_2026(**args)
        self.assertEqual(r["exception_items"],["employment_insurance","health","pension"])
        self.assertEqual(r["source_bound_review"]["deductions"]["net_estimate_krw"],116000)
        self.assertFalse(r["payment_authorized"])
        self.assertFalse(r["statutory_validated"])
        for change in (dict(expected_draft_sha256="0"*64),dict(expected_agency_snapshot_sha256="0"*64),
                       dict(agency_cases={}),dict(classified_days=[day(o=59)])):
            with self.assertRaises(PayrollBlocked):source_bound_agency_deduction_review_2026(**dict(args,**change))
        for change in (dict(tenant="b"),dict(worker="other"),dict(period="2026-12"),
                       dict(amount_krw=1001),dict(evidence_sha256="e"*64),dict(case="EXEMPTION")):
            bad=dict(cases,health=dict(cases["health"],**change))
            with self.assertRaises(PayrollBlocked):source_bound_agency_deduction_review_2026(**dict(args,agency_cases=bad,expected_agency_snapshot_sha256=digest(bad)))


class PensionCollectionReference(unittest.TestCase):
    def test_ordinary_rounding_and_mismatch(self):
        from app.naruv_kr_payroll_review import pension_collection_reference_2026
        args=dict(tenant="a",worker="w",period="2026-07",assessment_sha256="b"*64,
                  scope="ORDINARY_SINGLE_WORKPLACE_NO_RELIEF")
        for base,want in ((410000,19470),(411000,19520),(1000000,47500),(6590000,313020)):
            with self.subTest(base=base):
                r=pension_collection_reference_2026(**args,assessed_base_krw=base,assessed_employee_krw=want)
                self.assertEqual(r["employee_collection_reference_krw"],want)
                self.assertEqual(r["status"],"REFERENCE_MATCH_ONLY")
                self.assertFalse(r["payment_authorized"])
        r=pension_collection_reference_2026(**args,assessed_base_krw=411000,assessed_employee_krw=19522)
        self.assertEqual(r["status"],"AGENCY_AMOUNT_DIFFERENCE_REVIEW_REQUIRED")
        for change in (dict(scope="SUBSIDY"),dict(assessed_employee_krw=True),dict(assessed_base_krw=409000)):
            with self.assertRaises(PayrollBlocked):
                pension_collection_reference_2026(**(dict(args,assessed_base_krw=411000,assessed_employee_krw=19520)|change))


class KRRequestParser(unittest.TestCase):
    def test_nested_manual_submission_and_strict_shape(self):
        import json
        from fastapi import HTTPException
        from app.naruv_draft_review import _decode_kr_body
        data=dict(expected_draft_sha256="a"*64,ordinary_hourly=12000,
            classification_sha256="b"*64,classified_days=[day()],
            deductions=deductions(),pension_assessed_base_krw=410000)
        raw=json.dumps(data).encode()
        self.assertEqual(_decode_kr_body(raw),data)
        bad=[raw.replace(b'"ordinary_hourly": 12000',b'"ordinary_hourly": 12000,"ordinary_hourly": 1'),
            raw.replace(b'"amount_krw": 1000',b'"amount_krw": true',1),
            raw.replace(b'"amount_krw": 1000',b'"amount_krw": 1.0',1),
            raw.replace(b'"amount_krw": 1000',b'"amount_krw": NaN',1),
            json.dumps(dict(data,tenant="ci-b")).encode(), b"x"*32769, b"["*10000]
        for v in bad:
            with self.subTest(prefix=v[:30]),self.assertRaises(HTTPException) as ex:
                _decode_kr_body(v)
            self.assertEqual(ex.exception.status_code,422)

    def test_annual_leave_optional_shape_and_conflicts(self):
        import json
        from fastapi import HTTPException
        from app.naruv_draft_review import _decode_kr_body
        a=dict(employment_start="2025-07-01",service_year=1,as_of="2026-07-01",
            last_employed_on=None,months=[],attendance_sha256="b"*64,contract_sha256="c"*64,
            scope="CONTINUOUS_FULLTIME_5PLUS_FIRST_OF_MONTH_HIRE")
        base=dict(expected_draft_sha256="a"*64,ordinary_hourly=12000,
            classification_sha256="b"*64,classified_days=[day()],
            deductions=deductions(),pension_assessed_base_krw=410000)
        data=dict(base,annual_leave_accrual_review=a)
        self.assertEqual(_decode_kr_body(json.dumps(data).encode()),data)
        for bad in (dict(a,tenant="ci-b"),dict(a,service_year=True),dict(a,months=[{}]),
                    dict(a,first_year_low_attendance_assessment=None),dict(a,as_of=1)):
            with self.subTest(bad=bad),self.assertRaises(HTTPException) as ex:
                _decode_kr_body(json.dumps(dict(base,annual_leave_accrual_review=bad)).encode())
            self.assertEqual(ex.exception.status_code,422)
        for key in ("part_time_leave_review","unused_leave_review"):
            with self.assertRaises(HTTPException):_decode_kr_body(json.dumps(dict(data,**{key:{}})).encode())

    def test_fixed_week_shape_and_alternative_gross_conflicts(self):
        import json
        from fastapi import HTTPException
        from app.naruv_draft_review import _decode_kr_body
        a=dict(schedule_sha256="b"*64,attendance_sha256="c"*64,
            scope="HOURLY_MON_FRI_40H_SUNDAY_REST_ORDINARY_LEAVE_RATE",
            weeks=[dict(monday="2026-06-29",employed_full_week=True,
                days=[dict(date=f"2026-07-{i:02}",status="PRESENT",actual_minutes=480,evidence_sha256="a"*64) for i in range(1,8)])])
        base=dict(expected_draft_sha256="a"*64,ordinary_hourly=12000,
            classification_sha256="b"*64,classified_days=[day()],deductions=deductions(),pension_assessed_base_krw=410000)
        data=dict(base,fixed_week_paid_review=a)
        self.assertEqual(_decode_kr_body(json.dumps(data).encode()),data)
        for key in ("paid_holiday_review","unused_leave_review","part_time_leave_review","shift_review","monthly_tax_review","annual_leave_accrual_review","settlement_components","insurance_assessed_bases"):
            with self.subTest(key=key),self.assertRaises(HTTPException):
                _decode_kr_body(json.dumps(dict(data,**{key:{}})).encode())
        for bad in (dict(a,tenant="ci-b"),dict(a,weeks=[]),dict(a,weeks=[dict(a["weeks"][0],employed_full_week=1)])):
            with self.subTest(bad=bad),self.assertRaises(HTTPException):
                _decode_kr_body(json.dumps(dict(base,fixed_week_paid_review=bad)).encode())


class InsuranceCollectionComparison(unittest.TestCase):
    def test_reference_sequences_no_automatic_selection(self):
        from app.naruv_kr_payroll_review import insurance_collection_review_2026
        args=dict(tenant="a",worker="w",period="2026-11",health_base_krw=3000000,
            employment_base_krw=3000000,assessment_sha256="b"*64,
            scope="ORDINARY_FULL_MONTH_NO_RELIEF_ASSESSED_BASES",
            assessed_employee_krw={"health":107850,"long_term_care":14170,"employment_insurance":27000})
        out=insurance_collection_review_2026(**args)
        self.assertEqual(out["candidates"]["health_10won"],107850)
        self.assertEqual(out["candidates"]["ltc_exact_base_10won"],14170)
        self.assertEqual(out["flags"],[])
        self.assertFalse(out["statutory_validated"])
        self.assertFalse(out["payment_authorized"])
        mismatch=insurance_collection_review_2026(**dict(args,assessed_employee_krw=dict(args["assessed_employee_krw"],health=107840,employment_insurance=26999)))
        self.assertIn("HEALTH_REFERENCE_DIFFERENCE",mismatch["flags"])
        self.assertIn("EMPLOYMENT_ASSESSMENT_DIFFERENCE",mismatch["flags"])
        for change in (dict(scope="RELIEF"),dict(health_base_krw=999999),dict(assessed_employee_krw={}),
            dict(assessed_employee_krw=dict(args["assessed_employee_krw"],health=True))):
            with self.assertRaises(PayrollBlocked):insurance_collection_review_2026(**dict(args,**change))

    def test_ambiguous_ltc_sequence_is_never_selected(self):
        from app.naruv_kr_payroll_review import insurance_collection_review_2026
        # Independent boundary example: 35995.69245 health and
        # 4730.004204 LTC before truncation; truncating health first changes LTC.
        base=1001271
        r=insurance_collection_review_2026(tenant="a",worker="w",period="2026-11",
            health_base_krw=base,employment_base_krw=base,assessment_sha256="c"*64,
            scope="ORDINARY_FULL_MONTH_NO_RELIEF_ASSESSED_BASES",
            assessed_employee_krw={"health":0,"long_term_care":0,"employment_insurance":0})
        self.assertIn("LTC_SEQUENCE_REQUIRES_AGENCY_CONFIRMATION",r["flags"])
        self.assertEqual(r["candidates"]["ltc_exact_base_10won"],4730)
        self.assertEqual(r["candidates"]["ltc_truncated_health_base_10won"],4720)
        self.assertFalse(r["production_authorized"])


class FixedWeekPaidRestLeave(unittest.TestCase):
    def fixture(self):
        from datetime import date,timedelta
        weeks=[]
        for i in range(6):
            monday=date(2026,10,26)+timedelta(days=7*i)
            days=[]
            for j in range(7):
                d=monday+timedelta(days=j)
                status="PRESENT" if j<5 else ("NON_WORK_DAY" if j==5 else "WEEKLY_REST")
                days.append(dict(date=d.isoformat(),status=status,actual_minutes=480 if j<5 else 0,evidence_sha256="a"*64))
            weeks.append(dict(monday=monday.isoformat(),employed_full_week=True,days=days))
        return dict(tenant="a",worker="w",period="2026-11",ordinary_hourly=12000,
            schedule_sha256="b"*64,attendance_sha256="c"*64,weeks=weeks,
            scope="HOURLY_MON_FRI_40H_SUNDAY_REST_ORDINARY_LEAVE_RATE")
    def test_complete_boundary_and_leave(self):
        from app.naruv_kr_payroll_review import fixed_week_paid_rest_leave_review_2026 as review
        a=self.fixture()
        r=review(**a)
        self.assertEqual(r["weekly_rest_dates"],["2026-11-01","2026-11-08","2026-11-15","2026-11-22","2026-11-29"])
        self.assertEqual(r["weekly_rest_krw"],480000)
        self.assertEqual(r["annual_leave_krw"],0)
        a["weeks"][0]["days"][0].update(status="ABSENT",actual_minutes=0)
        a["weeks"][1]["days"][1].update(status="APPROVED_FULL_DAY_ANNUAL_LEAVE",actual_minutes=0)
        a["weeks"][2]["days"][0]["actual_minutes"]=420
        r2=review(**a)
        self.assertEqual(r2["weekly_rest_krw"],384000)
        self.assertEqual(r2["annual_leave_dates"],["2026-11-03"])
        self.assertEqual(r2["annual_leave_krw"],96000)
        self.assertNotEqual(r["review_sha256"],r2["review_sha256"])
        self.assertFalse(r2["payment_authorized"])
        self.assertEqual(r2,review(**dict(a,weeks=a["weeks"][::-1])))
    def test_fail_closed_unsupported_cases(self):
        from app.naruv_kr_payroll_review import fixed_week_paid_rest_leave_review_2026 as review
        for change in (dict(scope="MONTHLY_SALARY"),dict(schedule_sha256="bad"),dict(ordinary_hourly=True)):
            with self.assertRaises(PayrollBlocked):review(**dict(self.fixture(),**change))
        for kind in ("missing","duplicate","partial","holiday","all_leave","worked_leave"):
            a=self.fixture()
            w=a["weeks"][1]
            if kind=="missing":a["weeks"].pop()
            elif kind=="duplicate":a["weeks"][0]=w
            elif kind=="partial":w["employed_full_week"]=False
            elif kind=="holiday":w["days"][0].update(status="PUBLIC_HOLIDAY",actual_minutes=0)
            elif kind=="all_leave":
                for row in w["days"][:5]:row.update(status="APPROVED_FULL_DAY_ANNUAL_LEAVE",actual_minutes=0)
            else:w["days"][0]["status"]="APPROVED_FULL_DAY_ANNUAL_LEAVE"
            with self.subTest(kind=kind),self.assertRaises(PayrollBlocked):review(**a)


    def test_monthly_integration_with_confirmed_draft(self):
        from app.naruv_kr_payroll_review import fixed_week_monthly_payroll_review_2026 as review
        from app.naruv_payroll_draft import draft_gross
        a=self.fixture()
        a["weeks"][1]["days"][1].update(status="APPROVED_FULL_DAY_ANNUAL_LEAVE",actual_minutes=0)
        rows=[dict(date=d["date"],regular=d["actual_minutes"],additional=0) for w in a["weeks"] for d in w["days"]
              if d["date"].startswith("2026-11-") and d["status"]=="PRESENT"]
        def draft(rows):
            return draft_gross(tenant="a",worker="w",period="2026-11",policy_revision="r1",
                hourly_krw=12000,minutes_by_day=rows,multiplier_bps={"regular":10000,"additional":15000})["draft_sha256"]
        a.update(base_hourly=12000,policy_revision="r1",minutes_by_day=rows,additional_bps=15000,
            expected_draft_sha256=draft(rows),deductions=deductions())
        r=review(**a)
        self.assertEqual(r["gross_estimate_krw"],2496000)
        self.assertEqual(r["deductions"]["net_estimate_krw"],2490000)
        self.assertFalse(r["payment_authorized"])
        tampered=rows+[dict(date="2026-11-03",regular=480,additional=0)]
        with self.assertRaisesRegex(PayrollBlocked,"KR_PAID_WORK_SOURCE_MISMATCH"):
            review(**dict(a,minutes_by_day=tampered,expected_draft_sha256=draft(tampered)))
        with self.assertRaisesRegex(PayrollBlocked,"KR_PAID_DRAFT_CHANGED"):
            review(**dict(a,expected_draft_sha256="0"*64))


class FixedPartTimeRest(unittest.TestCase):
    def args(self,minutes):
        from datetime import date,timedelta
        end=date(2026,11,29)
        weeks=[]
        for k in range(4):
            mon=end-timedelta(days=6+7*k)
            rows=[dict(date=(mon+timedelta(days=i)).isoformat(),
                status="PRESENT" if i<3 else ("WEEKLY_REST" if i==6 else "NON_WORK_DAY"),
                actual_minutes=minutes[i] if i<3 else 0,evidence_sha256="a"*64) for i in range(7)]
            weeks.append(dict(monday=mon.isoformat(),employed_full_week=True,days=rows))
        return dict(tenant="a",worker="w",sunday=end.isoformat(),hourly_krw=12000,
            contracted_minutes=minutes+[0,0,0],comparator_minutes=[480]*5+[0],
            weeks=weeks,contract_sha256="b"*64,attendance_sha256="c"*64,
            scope="FIXED_PART_TIME_4_COMPLETE_WEEKS_SUNDAY_REST")
    def test_threshold_comparator_and_absence(self):
        from app.naruv_kr_payroll_review import fixed_part_time_weekly_rest_2026 as review
        a=self.args([300,300,300])
        r=review(**a)
        self.assertEqual(r["rest_pay_estimate_krw"],36000)
        self.assertTrue(r["eligible_in_scope"])
        self.assertFalse(r["payment_authorized"])
        self.assertEqual(review(**self.args([300,300,299]))["rest_pay_estimate_krw"],0)
        a["weeks"][0]["days"][0].update(status="ABSENT",actual_minutes=0)
        self.assertEqual(review(**a)["rest_pay_estimate_krw"],0)
        self.assertEqual(review(**dict(a,weeks=a["weeks"][::-1])),review(**a))
        for change in (dict(weeks=a["weeks"][:3]),dict(comparator_minutes=[0]*6),dict(hourly_krw=True)):
            with self.assertRaises(PayrollBlocked):review(**dict(a,**change))
        b=self.args([300,300,300])
        b["weeks"][0]["days"][0].update(status="PUBLIC_HOLIDAY",actual_minutes=0)
        with self.assertRaises(PayrollBlocked):review(**b)

    def test_confirmed_month_overlap_and_premium_rejection(self):
        from app.naruv_kr_payroll_review import source_bound_part_time_rest_2026
        a=self.args([300,300,300]);a["ordinary_hourly"]=a.pop("hourly_krw")
        rows=[dict(date=r["date"],regular=r["actual_minutes"],additional=0)
              for w in a["weeks"] for r in w["days"] if r["status"]=="PRESENT"]
        classified=[dict(date=r["date"],regular=r["regular"],overtime=0,holiday_first8=0,holiday_after8=0,night=0) for r in rows]
        a.update(period="2026-11",minutes_by_day=rows,classified_days=classified,source_review_sha256="d"*64)
        out=source_bound_part_time_rest_2026(**a)
        self.assertEqual(out["rest_pay_estimate_krw"],36000)
        self.assertFalse(out["included_in_gross"]);self.assertFalse(out["historical_attendance_authenticity_verified"])
        self.assertFalse(out["zero_minutes_attendance_status_verified"])
        self.assertEqual(out["matched_confirmed_positive_work_days"],12)
        self.assertEqual(out["manual_zero_work_status_days"],16)
        for change in (dict(minutes_by_day=rows[:-1]),dict(period="2026-10"),dict(classified_days=[dict(classified[0],night=60)]+classified[1:])):
            with self.subTest(change=change),self.assertRaises(PayrollBlocked):source_bound_part_time_rest_2026(**dict(a,**change))


class AnnualLeaveAccrualAndCompensation(unittest.TestCase):
    def args(self,hire="2025-01-01",year=1,stop="2026-01-01",n=12):
        from datetime import date
        h=date.fromisoformat(hire)
        rows=[dict(start=date(h.year+year-1+(h.month-1+i)//12,(h.month-1+i)%12+1,1).isoformat(),
            scheduled_days=20,credited_days=20,evidence_sha256="a"*64) for i in range(n)]
        return dict(tenant="a",worker="w",employment_start=hire,service_year=year,as_of="2026-11-26",
            last_employed_on=stop,months=rows,attendance_sha256="b"*64,contract_sha256="c"*64,
            scope="CONTINUOUS_FULLTIME_5PLUS_FIRST_OF_MONTH_HIRE")
    def test_anniversary_and_threshold(self):
        from app.naruv_kr_payroll_review import annual_leave_accrual_review_2026 as review
        self.assertEqual(review(**self.args(stop="2025-12-31",n=11))["earned_days_in_review"],11)
        r=review(**self.args())
        self.assertEqual(r["earned_days_in_review"],26)
        self.assertFalse(r["payment_authorized"])
        for year,expected in ((3,16),(5,17),(21,25),(25,25)):
            a=self.args(hire=f"{2026-year}-01-01",year=year)
            self.assertEqual(review(**a)["earned_days_in_review"],expected)
        low=self.args()
        for r in low["months"]:r["credited_days"]=10
        with self.assertRaisesRegex(PayrollBlocked,"KR_LEAVE_FIRST_YEAR_LOW_ATTENDANCE_REVIEW_REQUIRED"):
            review(**low)
        a=self.args(hire="2024-01-01",year=2)
        for r in a["months"]:r["credited_days"]=16
        self.assertEqual(review(**a)["earned_days_in_review"],15)
        a["months"][0]["credited_days"]=15
        self.assertEqual(review(**a)["earned_days_in_review"],0)
        a["months"][1]["credited_days"]=20
        a["months"][2]["credited_days"]=10
        self.assertEqual(review(**a)["earned_days_in_review"],1)
        for change in (dict(months=a["months"][:-1]),dict(scope="UNSUPPORTED"),dict(service_year=True)):
            with self.assertRaises(PayrollBlocked):review(**dict(a,**change))
    def test_first_year_low_attendance_explicit_assessment(self):
        from app.naruv_kr_payroll_review import annual_leave_accrual_review_2026 as review
        a=self.args()
        for r in a["months"][4:]:r["credited_days"]=10
        evidence=dict(attendance_sha256=a["attendance_sha256"],contract_sha256=a["contract_sha256"],
            anniversary="2026-01-01",assessed_additional_days=4,assessment_sha256="d"*64)
        with self.assertRaises(PayrollBlocked):review(**a)
        out=review(**a,first_year_low_attendance_assessment=evidence)
        self.assertEqual(out["earned_days_in_review"],8)
        self.assertEqual(out["grants"][-1]["kind"],"FIRST_YEAR_LOW_ATTENDANCE_ASSESSED_REFERENCE")
        self.assertFalse(out["statutory_validated"])
        self.assertFalse(out["payment_authorized"])
        self.assertNotEqual(out["review_sha256"],review(**a,first_year_low_attendance_assessment=dict(evidence,assessment_sha256="e"*64))["review_sha256"])
        for bad in (dict(evidence,assessed_additional_days=5),dict(evidence,assessed_additional_days=True),
            dict(evidence,anniversary="2025-12-31"),dict(evidence,attendance_sha256="f"*64),dict(evidence,contract_sha256="f"*64)):
            with self.subTest(bad=bad),self.assertRaises(PayrollBlocked):review(**a,first_year_low_attendance_assessment=bad)
        with self.assertRaises(PayrollBlocked):review(**self.args(),first_year_low_attendance_assessment=evidence)
        with self.assertRaises(PayrollBlocked):review(**self.args(stop="2025-12-31",n=11),first_year_low_attendance_assessment=evidence)
    def test_calendar_month_actual_length(self):
        from calendar import monthrange
        from datetime import date
        from app.naruv_kr_payroll_review import annual_leave_accrual_review_2026 as review
        for hire,year in (("2024-01-01",1),("2025-01-01",1),("2025-10-01",1)):
            h=date.fromisoformat(hire)
            stop=date(h.year+1,h.month,1).isoformat()
            for i in range(12):
                a=self.args(hire=hire,year=year,stop=stop)
                d=date.fromisoformat(a["months"][i]["start"])
                days=monthrange(d.year,d.month)[1]
                a["months"][i].update(scheduled_days=days,credited_days=days)
                with self.subTest(hire=hire,month=d.isoformat()):
                    self.assertEqual(review(**a)["earned_days_in_review"],26)
                    a["months"][i].update(scheduled_days=days+1,credited_days=days+1)
                    with self.assertRaisesRegex(PayrollBlocked,"KR_LEAVE_ATTENDANCE"):review(**a)
    def test_settlement_pending_and_duplicate_payment(self):
        from app.naruv_kr_payroll_review import unused_leave_compensation_review_2026 as review
        from app.naruv_payroll_draft import hash_input
        row=dict(grant_id="g1",tenant="a",worker="w",earned=15,used=7,previously_paid=3,payable=5,
            disposition="ASSESSED_PAYABLE",assessment_sha256="a"*64)
        def args(r):
            return dict(tenant="a",worker="w",period="2026-11",ordinary_hourly=12000,expected_grant_ids=["g1"],entries=[r],
                grant_ledger_sha256=hash_input({"v":"KR_LEAVE_SETTLEMENT_LEDGER_V1","tenant":"a","worker":"w",
                    "period":"2026-11","ids":["g1"],"entries":[r]}))
        out=review(**args(row))
        self.assertEqual(out["reference_krw"],480000)
        self.assertFalse(out["payment_authorized"])
        self.assertIsNone(review(**args(dict(row,payable=0,disposition="PENDING")))["reference_krw"])
        for r in (dict(row,payable=6),dict(row,tenant="b"),dict(row,disposition="PENDING")):
            with self.assertRaises(PayrollBlocked):review(**args(r))
        with self.assertRaises(PayrollBlocked):review(**dict(args(row),grant_ledger_sha256="0"*64))


class AssessedSettlementComponents(unittest.TestCase):
    def test_all_four_components_and_signed_difference(self):
        from app.naruv_kr_payroll_review import assessed_settlement_components_2026 as review
        a="a"*64
        rows=dict(bonus=dict(months=3,bonus_krw=300000,regular_taxable_krw=9000000,
            assessed_monthly_table_tax_krw=100000,already_withheld_krw=270000,assessment_sha256=a),
            year_end=dict(kind="MIDYEAR_TERMINATION",decided_national_krw=100000,previous_national_krw=130000,special_payment_krw=0,assessment_sha256=a),
            severance=dict(eligible_confirmed=True,service_days=730,average_period_days=90,included_wages_krw=9000000,ordinary_daily_krw=120000,assessment_sha256=a),
            health_leave=dict(kind="ORDINARY_LEAVE_50_PERCENT_DIFFERENCE",prior_full_premium_krw=100000,leave_full_premium_krw=20000,assessed_full_premium_krw=60000,assessment_sha256=a))
        args=dict(tenant="a",worker="w",period="2026-11",components=rows)
        r=review(**args)
        self.assertEqual(r["components"]["bonus"]["signed_difference_krw"],30000)
        self.assertEqual(r["components"]["year_end"]["refund_reference_krw"],30000)
        self.assertEqual(r["components"]["severance"]["estimate_krw"],7200000)
        self.assertEqual(r["components"]["health_leave"]["status"],"REFERENCE_MATCH_ONLY")
        self.assertFalse(r["payment_authorized"])
        for change in (dict(bonus=dict(rows["bonus"],months=0)),dict(severance=dict(rows["severance"],eligible_confirmed=False)),
            dict(health_leave=dict(rows["health_leave"],kind="PARENTAL_LEAVE")),dict(year_end=dict(rows["year_end"],decided_national_krw=True))):
            with self.assertRaises(PayrollBlocked):review(**dict(args,components=dict(rows,**change)))

    def test_assessed_holiday_variable_schedule_and_duplicate(self):
        from app.naruv_kr_payroll_review import approved_paid_holiday_review_2026 as review
        row=dict(date="2026-10-09",paid_minutes=360,actual_minutes=120,kind="ASSESSED_PUBLIC_HOLIDAY",assessment_sha256="a"*64)
        args=dict(tenant="a",worker="w",period="2026-10",ordinary_hourly=12000,calendar_sha256="b"*64,days=[row])
        r=review(**args)
        self.assertEqual(r["estimate_krw"],72000)
        self.assertFalse(r["statutory_validated"])
        for rows in ([row,row],[dict(row,date="2026-09-09")],[dict(row,paid_minutes=True)],[dict(row,kind="INFERRED")]):
            with self.assertRaises(PayrollBlocked):review(**dict(args,days=rows))


    def test_isolated_html_view_does_not_embed_evidence(self):
        from app.naruv_kr_payroll_review import isolated_payroll_review_html
        r=dict(status="MANUAL_SUBMISSION_REFERENCE_ONLY",evidence_authenticity_verified=False,persisted=False,
            statutory_validated=False,payment_authorized=False,production_authorized=False,
            review={"deductions":{"gross_estimate_krw":120000,"deductions_krw":6000,"net_estimate_krw":114000}},
            paid_holiday_reference={"estimate_krw":72000,"evidence":"<script>unsafe</script>"})
        html=isolated_payroll_review_html(r)
        self.assertIn("114,000",html)
        self.assertIn("72,000",html)
        self.assertNotIn("<script",html)
        self.assertNotIn("unsafe",html)
        with self.assertRaises(PayrollBlocked):isolated_payroll_review_html(dict(r,payment_authorized=True))


class ShiftNightBoundary(unittest.TestCase):
    def test_cross_midnight_overlap_and_breaks(self):
        from app.naruv_kr_payroll_review import shift_night_source_review_2026 as review
        segments=[dict(start="2026-11-01T21:00+09:00",end="2026-11-02T02:00+09:00",evidence_sha256="a"*64),
            dict(start="2026-11-02T03:00+09:00",end="2026-11-02T07:00+09:00",evidence_sha256="b"*64)]
        rows=[day(d="2026-11-01",r=180,n=120),day(d="2026-11-02",r=360,n=300)]
        a=dict(tenant="a",worker="w",period="2026-11",segments=segments,shift_sha256="c"*64,classified_days=rows)
        r=review(**a)
        self.assertEqual(r["days"],[{"date":"2026-11-01","work_minutes":180,"night_minutes":120},
            {"date":"2026-11-02","work_minutes":360,"night_minutes":300}])
        self.assertEqual(r,review(**dict(a,segments=segments[::-1])))
        for change in (dict(segments=segments+[segments[0]]),dict(classified_days=[rows[0],dict(rows[1],night=301)]),
            dict(segments=[dict(segments[0],start="2026-11-01T21:00+00:00"),segments[1]])):
            with self.assertRaises(PayrollBlocked):review(**dict(a,**change))

    def test_zero_work_days_have_unique_valid_period_dates(self):
        from app.naruv_kr_payroll_review import shift_night_source_review_2026 as review
        segments=[dict(start="2026-11-01T21:00+09:00",end="2026-11-02T02:00+09:00",evidence_sha256="a"*64),
            dict(start="2026-11-02T03:00+09:00",end="2026-11-02T07:00+09:00",evidence_sha256="b"*64)]
        rows=[day(d="2026-11-01",r=180,n=120),day(d="2026-11-02",r=360,n=300)]
        a=dict(tenant="a",worker="w",period="2026-11",segments=segments,shift_sha256="c"*64)
        good=review(**a,classified_days=rows)
        zero=day(d="2026-11-03",r=0)
        self.assertEqual(review(**a,classified_days=rows+[zero])["days"],good["days"])
        for bad in (rows+[zero,zero],rows+[day(d="2026-11-31",r=0)],rows+[day(d="2026-12-01",r=0)],
                    rows+[day(d="x",r=0)],[day(d="2026-11-01",r=0)]+rows):
            with self.subTest(bad=bad),self.assertRaisesRegex(PayrollBlocked,"KR_SHIFT_CLASSIFIED"):
                review(**a,classified_days=bad)


class SeveranceExcludedPeriod(unittest.TestCase):
    def test_assessed_exclusions_and_ordinary_floor(self):
        from app.naruv_kr_payroll_review import assessed_settlement_components_2026 as review
        row=dict(eligible_confirmed=True,service_days=730,average_period_days=90,
            included_wages_krw=9000000,ordinary_daily_krw=100000,excluded_days=30,
            excluded_wages_krw=1800000,assessment_sha256="a"*64)
        def call(r):
            return review(tenant="a",worker="w",period="2026-11",components={"severance":r})
        result=call(row)
        self.assertEqual(result["components"]["severance"]["estimate_krw"],7200000)
        self.assertFalse(result["payment_authorized"])
        self.assertFalse(result["statutory_validated"])
        self.assertEqual(call(dict(row,ordinary_daily_krw=130000))["components"]["severance"]["estimate_krw"],7800000)
        for change in (dict(excluded_days=90),dict(excluded_days=-1),dict(excluded_days=True),
                dict(excluded_wages_krw=9000001),dict(excluded_days=0),dict(excluded_wages_krw=-1)):
            with self.subTest(change=change),self.assertRaises(PayrollBlocked):
                call(dict(row,**change))
        partial=dict(row);del partial["excluded_wages_krw"]
        with self.assertRaises(PayrollBlocked):call(partial)
        legacy={k:v for k,v in row.items() if k not in ("excluded_days","excluded_wages_krw")}
        self.assertEqual(call(legacy)["components"]["severance"]["estimate_krw"],6000000)

class FixedPartTimeAnnualLeave(unittest.TestCase):
    def test_assessed_fixed_schedule_hours_and_boundaries(self):
        from app.naruv_kr_payroll_review import fixed_part_time_annual_leave_reference_2026 as review
        a=dict(tenant="a",worker="w",period="2026-11",comparator_grant_days=15,
            contracted_week_minutes=1200,ordinary_hourly=12000,contract_sha256="a"*64,grant_assessment_sha256="b"*64)
        r=review(**a)
        self.assertEqual(r["grant_hours"],60)
        self.assertEqual(r["full_unused_value_reference_krw"],720000)
        self.assertEqual(review(**dict(a,contracted_week_minutes=1210))["grant_hours"],61)
        self.assertEqual(review(**dict(a,contracted_week_minutes=900))["grant_hours"],45)
        self.assertEqual(review(**dict(a,comparator_grant_days=1,contracted_week_minutes=901))["grant_hours"],4)
        for k in ("payment_authorized","statutory_validated","production_authorized"):
            self.assertFalse(r[k])
        for change in (dict(contracted_week_minutes=899),dict(contracted_week_minutes=2400),
                dict(contracted_week_minutes=True),dict(comparator_grant_days=26),
                dict(grant_assessment_sha256=""),dict(period="2027-01")):
            with self.subTest(change=change),self.assertRaises(PayrollBlocked):
                review(**dict(a,**change))

class AnnualResidentTaxReview(unittest.TestCase):
    def args(self):
        return dict(tenant="a",worker="w",period="2026-11",kind="ANNUAL_PREVIEW",
            scope="RESIDENT_WAGE_ONLY_NO_RELIEF_ASSESSED_OTHER_DEDUCTIONS_CREDITS",
            annual_income_krw=200000000,exempt_income_krw=5000000,
            assessed_other_deductions_krw=7000000,assessed_cap_addback_krw=0,
            assessed_other_credits_krw=0,previous_national_krw=44334000,
            annual_source_sha256="a"*64,deduction_assessment_sha256="b"*64,
            credit_assessment_sha256="c"*64,assessment_sha256="d"*64)
    def test_official_example_and_denials(self):
        from app.naruv_kr_payroll_review import annual_resident_wage_tax_review_2026 as review,assessed_settlement_components_2026
        a=self.args();r=review(**a)
        self.assertEqual(r["earned_income_deduction_exact"],{"numerator":16650000,"denominator":1})
        self.assertEqual(r["taxable_exact"],{"numerator":171350000,"denominator":1})
        self.assertEqual(r["calculated_tax_exact"],{"numerator":45173000,"denominator":1})
        self.assertEqual(r["employee_tax_credit_exact"],{"numerator":200000,"denominator":1})
        self.assertEqual(r["decided_national_estimate_krw"],44973000)
        self.assertEqual(r["signed_difference_krw"],639000)
        self.assertEqual(review(**dict(a,previous_national_krw=50000000))["refund_reference_krw"],5027000)
        self.assertEqual(review(**dict(a,assessed_other_credits_krw=999999999))["decided_national_estimate_krw"],0)
        self.assertEqual(review(**dict(a,annual_income_krw=0,exempt_income_krw=0))["decided_national_estimate_krw"],0)
        for change in (dict(exempt_income_krw=200000001),dict(assessed_cap_addback_krw=7000001),
                dict(annual_income_krw=True),dict(scope="OTHER_INCOME"),dict(period="2026-06"),
                dict(annual_source_sha256="bad"),dict(kind="ACTUAL_FINAL_FILING")):
            with self.subTest(change=change),self.assertRaises(PayrollBlocked):
                review(**dict(a,**change))
        for key in ("statutory_validated","payment_authorized","production_authorized"):
            self.assertFalse(r[key])
        row={k:v for k,v in a.items() if k not in ("tenant","worker","period")}
        scoped=assessed_settlement_components_2026(tenant="a",worker="w",period="2026-11",components={"year_end_calculated":row})
        self.assertEqual(scoped["components"]["year_end_calculated"],r)
        with self.assertRaises(PayrollBlocked):
            assessed_settlement_components_2026(tenant="a",worker="w",period="2026-11",
                components={"year_end_calculated":row,"year_end":{}})

    def test_all_income_and_tax_bracket_edges(self):
        from fractions import Fraction
        from app.naruv_kr_payroll_review import (_annual_wage_deduction_2026 as d,_annual_progressive_tax_2026 as tax,
            _annual_employee_credit_2026 as credit)
        for edge,value,left,right in ((5000000,3500000,70,40),(15000000,7500000,40,15),
                (45000000,12000000,15,5),(100000000,14750000,5,2)):
            with self.subTest(edge=edge):
                self.assertEqual(d(edge),value);self.assertEqual(d(edge)-d(edge-1),Fraction(left,100))
                self.assertEqual(d(edge+1)-d(edge),Fraction(right,100))
        self.assertEqual(d(33800000),10320000);self.assertEqual(d(10**9),20000000)
        for edge,value,left,right in ((14000000,840000,6,15),(50000000,6240000,15,24),
                (88000000,15360000,24,35),(150000000,37060000,35,38),
                (300000000,94060000,38,40),(500000000,174060000,40,42),
                (1000000000,384060000,42,45)):
            with self.subTest(edge=edge):
                self.assertEqual(tax(edge),value);self.assertEqual(tax(edge)-tax(edge-1),Fraction(left,100))
                self.assertEqual(tax(edge+1)-tax(edge),Fraction(right,100))
        for gross,cap in ((33000000,740000),(43000000,660000),(70000000,660000),
                (70320000,500000),(120000000,500000),(120600000,200000)):
            self.assertEqual(credit(gross,Fraction(100000000))[1],cap)
        self.assertEqual(credit(30000000,Fraction(1300000))[0],715000)
        self.assertEqual(credit(30000000,Fraction(1300001))[0],Fraction(7150003,10))


class AssessedMonthlyTaxComparison(unittest.TestCase):
    def test_reference_and_scope(self):
        from app.naruv_kr_payroll_review import assessed_monthly_tax_comparison_2026 as compare,national_collection_review_2026
        a=dict(tenant="a",worker="w",period="2026-11",gross_krw=3000000,
            withholding_date="2026-11-25",taxable_monthly_krw=3000000,
            eligible_family_count=1,eligible_children_8_20=0,selection_percent=100,
            assessment_sha256="a"*64)
        tax=national_collection_review_2026(**{k:v for k,v in a.items() if k not in ("period","gross_krw")},
            scope="ASSESSED_ORDINARY_MONTHLY_TABLE_NO_RELIEF")["national_collection_krw"]
        rows=deductions()
        rows["income_tax"]=dict(amount_krw=tax,evidence_sha256="a"*64,assessment="ASSESSED")
        rows["local_income_tax"]=dict(amount_krw=tax//100*10,evidence_sha256="b"*64,assessment="ASSESSED")
        a["deductions"]=rows
        r=compare(**a)
        self.assertEqual(r["status"],"REFERENCE_MATCH_ONLY")
        self.assertFalse(r["payment_authorized"])
        self.assertEqual(r["national_reference_krw"],tax)
        bad=dict(rows,local_income_tax=dict(rows["local_income_tax"],amount_krw=1))
        self.assertEqual(compare(**dict(a,deductions=bad))["mismatches"],["local_income_tax"])
        for change in (dict(gross_krw=2999999),dict(withholding_date="2026-10-25"),
                dict(assessment_sha256="b"*64),dict(eligible_children_8_20=1),
                dict(deductions=dict(rows,income_tax=dict(rows["income_tax"],assessment="NOT_APPLICABLE")))):
            with self.subTest(change=change),self.assertRaises(PayrollBlocked):
                compare(**dict(a,**change))
