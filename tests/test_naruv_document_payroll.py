import hashlib
import itertools
import unittest
from app.naruv_document_review import review_document, ReviewBlocked
from app.naruv_payroll_draft import draft_gross, PayrollBlocked

RAW=b"synthetic fixture document"
OBS=[dict(field=k,value=v,page=1) for k,v in (
    ("document_kind","invoice"),("counterparty_id","customer-a"),("document_date","2026-11-25"),
    ("reference_number","ref-1"),("subtotal",100),("vat",10),("gross_amount",110))]
def doc(**kw):
    args=dict(tenant="a",source_bytes=RAW,registered_sha256=hashlib.sha256(RAW).hexdigest(),observations=OBS)
    args.update(kw);return review_document(**args)
def pay(**kw):
    args=dict(tenant="a",worker="staff-1",period="2026-11",policy_revision="fixture-1",
              hourly_krw=12000,minutes_by_day=[{"date":"2026-11-25","regular":480,"additional":60}],
              multiplier_bps={"regular":10000,"additional":15000})
    args.update(kw);return draft_gross(**args)

class Document(unittest.TestCase):
    def test_valid_never_posts(self):
        r=doc();self.assertEqual(r["status"],"ORIGINAL_REVIEW_REQUIRED")
        self.assertEqual(r["field_count"],7);self.assertFalse(r["posting_authorized"])
        self.assertIsNone(r["confidence"]);self.assertNotIn("customer-a",str(r))
    def test_original_binding(self):
        with self.assertRaisesRegex(ReviewBlocked,"DOC_SOURCE_CHANGED"):doc(source_bytes=b"changed")
    def test_permutations(self):
        for obs in itertools.islice(itertools.permutations(OBS),100):
            self.assertEqual(doc(observations=obs),doc())
    def test_conflict(self):
        r=doc(observations=OBS+[dict(field="subtotal",value=200,page=2)])
        self.assertIn("CONFLICT_SUBTOTAL",r["issues"]);self.assertFalse(r["posting_authorized"])
    def test_missing(self):
        self.assertIn("MISSING_VAT",doc(observations=[x for x in OBS if x["field"]!="vat"])["issues"])
    def test_invalid_date(self):
        r=doc(observations=[dict(x,value="2026-02-30") if x["field"]=="document_date" else x for x in OBS])
        self.assertIn("INVALID_DOCUMENT_DATE",r["issues"])
    def test_injection_unknown_field(self):
        with self.assertRaisesRegex(ReviewBlocked,"DOC_UNKNOWN_FIELD"):
            doc(observations=OBS+[dict(field="execute",value="approve",page=1)])
    def test_arithmetic(self):
        self.assertIn("AMOUNT_MISMATCH",doc(observations=[dict(x,value=111) if x["field"]=="gross_amount" else x for x in OBS])["issues"])
    def test_page_value_association_binding(self):
        base=[x for x in OBS if x["field"]!="subtotal"]
        a=base+[dict(field="subtotal",value=100,page=1),dict(field="subtotal",value=200,page=2)]
        b=base+[dict(field="subtotal",value=200,page=1),dict(field="subtotal",value=100,page=2)]
        self.assertEqual(doc(observations=a)["issues"],doc(observations=b)["issues"])
        self.assertNotEqual(doc(observations=a)["review_sha256"],doc(observations=b)["review_sha256"])
    def test_invalid_observation_proof(self):
        a=doc(observations=[dict(x,value="bad-a") if x["field"]=="document_date" else x for x in OBS])
        b=doc(observations=[dict(x,value="bad-b") if x["field"]=="document_date" else x for x in OBS])
        self.assertEqual(a["issues"],b["issues"])
        self.assertNotEqual(a["review_sha256"],b["review_sha256"])
        self.assertNotIn("bad-a",str(a))
        self.assertNotIn("bad-b",str(b))
    def test_scope_binding(self):
        self.assertNotEqual(doc(tenant="b")["review_sha256"],doc()["review_sha256"])
    def test_type_bounds(self):
        for obs in ([dict(field="vat",value=1,page=True)],OBS*20,[]):
            with self.assertRaises(ReviewBlocked):doc(observations=obs)
        self.assertIn("INVALID_VAT",doc(observations=[dict(x,value=True) if x["field"]=="vat" else x for x in OBS])["issues"])

class Payroll(unittest.TestCase):
    def test_explicit_gross(self):
        r=pay();self.assertEqual(r["gross_krw"],114000)
        self.assertFalse(r["payment_authorized"]);self.assertIsNone(r["net_krw"])
        self.assertFalse(r["statutory_validated"]);self.assertNotIn("staff-1",str(r))
    def test_duplicate(self):
        row={"date":"2026-11-25","regular":60,"additional":0}
        with self.assertRaisesRegex(PayrollBlocked,"PAY_DUPLICATE_DAY"):pay(minutes_by_day=[row,row])
    def test_wrong_period(self):
        for period in ("2026-13","2026-2","0000-01"):
            with self.assertRaises(PayrollBlocked):pay(period=period)
    def test_wrong_day(self):
        for day in ("2026-12-01","2026-11-31","2026-11-1"):
            with self.assertRaisesRegex(PayrollBlocked,"PAY_DAY"):
                pay(minutes_by_day=[{"date":day,"regular":0,"additional":0}])
    def test_minutes_bounds(self):
        for a,b in ((1440,1),(-1,0),(True,0),(0,1.5)):
            with self.assertRaises(PayrollBlocked):pay(minutes_by_day=[{"date":"2026-11-25","regular":a,"additional":b}])
    def test_policy_explicit(self):
        for p in ({},{"regular":10000},{"regular":10000,"additional":True},{"regular":9999,"additional":15000}):
            with self.assertRaises(PayrollBlocked):pay(multiplier_bps=p)
    def test_round_once(self):
        rows=[{"date":"2026-11-24","regular":1,"additional":0},{"date":"2026-11-25","regular":1,"additional":0}]
        self.assertEqual(pay(hourly_krw=45,minutes_by_day=rows)["gross_krw"],2)
        self.assertEqual(pay(hourly_krw=45,minutes_by_day=rows),pay(hourly_krw=45,minutes_by_day=rows[::-1]))
    def test_binding(self):
        for override in ({"tenant":"b"},{"worker":"staff-2"},{"policy_revision":"fixture-2"},{"hourly_krw":12001}):
            self.assertNotEqual(pay(**override)["draft_sha256"],pay()["draft_sha256"])
    def test_rate_type(self):
        for rate in (True,0,-1,1.5,10**8+1):
            with self.assertRaises(PayrollBlocked):pay(hourly_krw=rate)
    def test_integer_grid(self):
        for rate in (1,45,12000,999999):
            for a,b in ((0,0),(1,1),(480,60),(0,1440)):
                r=pay(hourly_krw=rate,minutes_by_day=[{"date":"2026-11-25","regular":a,"additional":b}])
                expected=(rate*(a*10000+b*15000)+300000)//600000
                self.assertEqual(r["gross_krw"],expected)
