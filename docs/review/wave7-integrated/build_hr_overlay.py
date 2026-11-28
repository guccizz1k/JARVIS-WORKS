"""Exact-source overlay for existing disposable CI-only payroll API.
Requires the Wave5 payroll candidate (statement constructor + verifier).
Never modifies the original checkout or enables the feature flag.
"""
import hashlib,sys
from pathlib import Path
EXPECTED='929dc07c40e181b1e1176924ae9378d8bb2fdf47'
def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
ANCHORS=[
('"agency_exception_review","wage_statement_review"}', '"agency_exception_review","wage_statement_review","fixed_week_statement_review"}'),
('        if "wage_statement_review" in d:\n', '''        if "fixed_week_statement_review" in d:
            a=d["fixed_week_statement_review"]
            if (set(d)!=required|{"fixed_week_paid_review","fixed_week_statement_review"}
                or type(a) is not dict or set(a)!={"payment_date","completeness_assessment_sha256","expected_monthly_review_sha256"}
                or any(type(v) is not str for v in a.values())):
                raise ValueError("fixed week statement scope")
        if "wage_statement_review" in d:
'''),
('ordinary_comparison_coverage_2026,restricted_wage_statement_2026)', 'ordinary_comparison_coverage_2026,restricted_wage_statement_2026,fixed_week_wage_statement_draft_2026,verify_fixed_week_statement_source_2026)'),
('                details["fixed_week_paid_reference"]=dict(fixed,classification_authenticity_verified=False)\n', '''                details["fixed_week_paid_reference"]=dict(fixed,classification_authenticity_verified=False)
                if "fixed_week_statement_review" in data:
                    request=data["fixed_week_statement_review"]
                    statement=fixed_week_wage_statement_draft_2026(tenant=org,worker=worker,period=period,
                        base_hourly=rate,ordinary_hourly=data["ordinary_hourly"],policy_revision=revision,
                        minutes_by_day=days,additional_bps=bps,expected_draft_sha256=data["expected_draft_sha256"],
                        deductions=data["deductions"],**data["fixed_week_paid_review"],**request)
                    verify_fixed_week_statement_source_2026(draft=statement,tenant=org,
                        assessment_sha256=request["completeness_assessment_sha256"],expected_review_sha256=statement["review_sha256"])
                    details["fixed_week_statement_reference"]=statement
                    proof["fixed_week_statement"]=statement["review_sha256"]
''')]
def transform(text):
    for old,new in ANCHORS:
        if text.count(old)!=1:raise ValueError('HR_ANCHOR_NOT_UNIQUE')
        text=text.replace(old,new,1)
    return text

def build(source,output):
    raw=Path(source).read_bytes()
    if blob(raw)!=EXPECTED:raise ValueError('HR_SOURCE_BLOB_MISMATCH')
    result=transform(raw.decode('utf-8'));compile(result,'naruv_draft_review.py','exec')
    with Path(output).open('x',encoding='utf-8',newline='') as f:f.write(result)
if __name__=='__main__':build(*sys.argv[1:])
