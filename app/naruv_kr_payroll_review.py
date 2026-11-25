"""Restricted Korean 2026 wage arithmetic review, not a legal payroll engine.

Inputs must be classified by authorized HR; no automatic eligibility, tax,
minimum-wage inclusion, weekly-rest or holiday determination. Never posts or pays.
"""
from datetime import date
from fractions import Fraction
import re
from .naruv_payroll_draft import PayrollBlocked,require,hash_input,ID,draft_gross

POLICY="KR_2026_ART56_RESTRICTED_V1"
SOURCES={
 "minimum_wage":"https://www.moel.go.kr/news/enews/report/enewsView.do?news_seq=18144",
 "premium":"https://1350.moel.go.kr/rtmview.do?id=1000262936",
 "statement":"https://www.moel.go.kr/wageCal.do",
 "income_tax":"https://nts.go.kr/nts/cm/cntnts/cntntsView.do?cntntsId=7862&mi=6426",
 "pension":"https://www.nps.or.kr/pnsinfo/ntpsklg/getOHAF0038M0.do",
 "health":"https://edi.nhis.or.kr/portal/images/popup/20251204_pop01longdesc.html",
}
KINDS=("regular","overtime","holiday_first8","holiday_after8","night")
DEDUCTIONS=("income_tax","local_income_tax","pension","health","long_term_care","employment_insurance")
HEX=re.compile(r"[0-9a-f]{64}")
def _whole(x,lo,hi):return type(x) is int and lo<=x<=hi
def _money(value):
    return {"numerator":value.numerator,"denominator":value.denominator}
def _round(value):
    return (2*value.numerator+value.denominator)//(2*value.denominator)

def wage_review(*,tenant,worker,period,base_hourly,ordinary_hourly,classification_sha256,days,scope):
    require(all(type(x) is str and ID.fullmatch(x) for x in (tenant,worker)),"KR_SCOPE")
    require(type(scope) is str and scope=="ADULT_HOURLY_5PLUS_MANUALLY_CLASSIFIED","KR_UNSUPPORTED_SCOPE")
    require(type(period) is str and re.fullmatch(r"2026-(0[1-9]|1[0-2])",period),"KR_POLICY_PERIOD")
    require(_whole(base_hourly,1,10**8) and _whole(ordinary_hourly,base_hourly,10**8),"KR_RATE")
    require(type(classification_sha256) is str and HEX.fullmatch(classification_sha256),"KR_CLASSIFICATION_PROOF")
    require(type(days) in (list,tuple) and 1<=len(days)<=31,"KR_DAYS")
    seen=set();normalized=[]
    for row in days:
        require(type(row) is dict and set(row)=={"date",*KINDS},"KR_DAY_SHAPE")
        day=row["date"]
        require(type(day) is str and re.fullmatch(r"2026-[0-9]{2}-[0-9]{2}",day) and day.startswith(period+"-"),"KR_DAY")
        try:date.fromisoformat(day)
        except ValueError:raise PayrollBlocked("KR_DAY") from None
        require(day not in seen,"KR_DUPLICATE_DAY")
        regular,over,first,after,night=(row[k] for k in KINDS)
        require(all(_whole(x,0,1440) for x in (regular,over,first,after,night)),"KR_MINUTES")
        work=regular+over+first+after
        require(work<=1440 and regular<=480 and first<=480 and night<=work,"KR_MINUTES")
        require(not ((regular or over) and (first or after)) and (not after or first==480),"KR_CLASSIFICATION")
        seen.add(day);normalized.append((day,regular,over,first,after,night))
    totals={k:sum(r[i+1] for r in normalized) for i,k in enumerate(KINDS)}
    work=sum(totals[k] for k in KINDS[:-1])
    require(work>0,"KR_EMPTY_WORK")
    components={"work_base":Fraction(base_hourly*work,60),
                "overtime_premium":Fraction(ordinary_hourly*totals["overtime"],120),
                "holiday_first8_premium":Fraction(ordinary_hourly*totals["holiday_first8"],120),
                "holiday_after8_premium":Fraction(ordinary_hourly*totals["holiday_after8"],60),
                "night_premium":Fraction(ordinary_hourly*totals["night"],120)}
    total=sum(components.values(),Fraction())
    require(total<=10**12,"KR_LIMIT")
    proof=hash_input({"policy":POLICY,"tenant":tenant,"worker":worker,"period":period,"scope":scope,
         "base_hourly":base_hourly,"ordinary_hourly":ordinary_hourly,"classification_sha256":classification_sha256,"days":sorted(normalized)})
    return {"policy":POLICY,"review_sha256":proof,"components":{k:_money(v) for k,v in components.items()},
        "work_minutes":work,"gross_exact":_money(total),"gross_estimate_krw":_round(total),
        "base_hourly_below_2026_floor":base_hourly<10320,
        "status":"RESTRICTED_ARITHMETIC_REVIEW","requires_human_review":True,"statutory_validated":False,"payment_authorized":False,
        "unresolved":["CLASSIFICATION_AND_ELIGIBILITY","WEEKLY_PAID_REST_AND_LEAVE","ADDITIONAL_ALLOWANCES","STATUTORY_ROUNDING","TAX_AND_INSURANCE"]}

def deduction_reconciliation(*,wage_result,deductions):
    """Arithmetic only for separately assessed items; evidence digest is not a validation of the evidence."""
    require(type(wage_result) is dict and wage_result.get("policy")==POLICY
            and wage_result.get("statutory_validated") is False and wage_result.get("payment_authorized") is False
            and type(wage_result.get("review_sha256")) is str and HEX.fullmatch(wage_result["review_sha256"]),"KR_WAGE_REVIEW")
    gross=wage_result.get("gross_estimate_krw")
    require(_whole(gross,0,10**12),"KR_GROSS")
    require(type(deductions) is dict and set(deductions)==set(DEDUCTIONS),"KR_DEDUCTIONS")
    clean={}
    for key,row in deductions.items():
        require(type(row) is dict and set(row)=={"amount_krw","evidence_sha256","assessment"},"KR_DEDUCTION_SHAPE")
        amount=row["amount_krw"];assessment=row["assessment"];proof=row["evidence_sha256"]
        require(_whole(amount,0,10**12) and type(assessment) is str and assessment in ("ASSESSED","NOT_APPLICABLE"),"KR_DEDUCTION_VALUE")
        require(assessment!="NOT_APPLICABLE" or amount==0,"KR_DEDUCTION_VALUE")
        require(type(proof) is str and HEX.fullmatch(proof),"KR_DEDUCTION_PROOF")
        clean[key]={"amount_krw":amount,"assessment":assessment,"evidence_sha256":proof}
    total=sum(r["amount_krw"] for r in clean.values())
    require(total<=gross,"KR_NEGATIVE_NET")
    return {"status":"MANUAL_DEDUCTION_ARITHMETIC_ONLY","gross_estimate_krw":gross,
        "deductions_krw":total,"net_estimate_krw":gross-total,
        "reconciliation_sha256":hash_input({"policy":POLICY,"wage_review":wage_result["review_sha256"],"gross":gross,"deductions":clean}),
        "requires_human_review":True,"statutory_validated":False,"payment_authorized":False}


def source_bound_review(*,tenant,worker,period,policy_revision,hourly_krw,
                        minutes_by_day,additional_bps,expected_draft_sha256,
                        ordinary_hourly,classification_sha256,classified_days,
                        deductions):
    """Recompute from confirmed server-owned inputs, never client gross totals.

    Caller must load source with the existing authenticated PG pay_source RPC.
    Manual classification must account for every stored minute. This restricted
    mapping rejects cases requiring different regular/additional categories;
    it does NOT establish statutory eligibility, tax or insurance correctness.
    """
    source=draft_gross(tenant=tenant,worker=worker,period=period,
        policy_revision=policy_revision,hourly_krw=hourly_krw,
        minutes_by_day=minutes_by_day,multiplier_bps={"regular":10000,"additional":additional_bps})
    require(type(expected_draft_sha256) is str and expected_draft_sha256==source["draft_sha256"],"KR_SOURCE_CHANGED")
    review=wage_review(tenant=tenant,worker=worker,period=period,base_hourly=hourly_krw,
        ordinary_hourly=ordinary_hourly,classification_sha256=classification_sha256,
        days=classified_days,scope="ADULT_HOURLY_5PLUS_MANUALLY_CLASSIFIED")
    # All shapes already validated independently by the existing pure functions.
    actual={r["date"]:(r["regular"],r["additional"]) for r in minutes_by_day}
    classified={r["date"]:(r["regular"],r["overtime"]+r["holiday_first8"]+r["holiday_after8"]) for r in classified_days}
    require(actual==classified,"KR_ATTENDANCE_MISMATCH")
    net=deduction_reconciliation(wage_result=review,deductions=deductions)
    return {"status":"SOURCE_BOUND_MANUAL_REVIEW_ONLY",
        "source_draft_sha256":source["draft_sha256"],"policy_revision":policy_revision,
        "wage":review,"deductions":net,
        "review_binding_sha256":hash_input({"v":1,"source":source["draft_sha256"],
            "wage":review["review_sha256"],"deductions":net["reconciliation_sha256"]}),
        "requires_human_review":True,"statutory_validated":False,"payment_authorized":False,
        "production_authorized":False}


PENSION_REFERENCE_2026="KR_NPS_2026_EMPLOYEE_REFERENCE_V1"

def pension_reference_2026(*,tenant,worker,period,assessed_base_krw,assessment_sha256):
    """Exact arithmetic on the agency-assessed monthly base, NOT current gross.

    Single ordinary workplace, full-month, before statutory rounding or relief.
    Eligibility, multi-workplace allocation, subsidies, exceptions and actual
    withholding are not established by this function.
    Source: https://www.nps.or.kr/pnsinfo/ntpsklg/getOHAF0038M0.do
    https://www.nps.or.kr/pnsinfo/ntpsklg/getOHAF0097M0.do
    """
    require(all(type(x) is str and ID.fullmatch(x) for x in (tenant,worker)),"KR_NPS_SCOPE")
    require(type(period) is str and re.fullmatch(r"2026-(0[1-9]|1[0-2])",period),"KR_NPS_PERIOD")
    low,high=(400000,6370000) if int(period[-2:])<=6 else (410000,6590000)
    require(_whole(assessed_base_krw,low,high) and assessed_base_krw%1000==0,"KR_NPS_BASE")
    require(type(assessment_sha256) is str and HEX.fullmatch(assessment_sha256),"KR_NPS_EVIDENCE")
    half=Fraction(assessed_base_krw*475,10000)
    return {"status":"UNROUNDED_REFERENCE_ONLY","policy":PENSION_REFERENCE_2026,
        "employee_exact":_money(half),"employer_exact":_money(half),
        "total_exact":_money(half*2),"base_limits_krw":[low,high],
        "reference_sha256":hash_input({"policy":PENSION_REFERENCE_2026,"tenant":tenant,"worker":worker,
            "period":period,"base":assessed_base_krw,"assessment":assessment_sha256}),
        "requires_human_review":True,"statutory_validated":False,"payment_authorized":False}


def insurance_reference_2026(*,tenant,worker,period,health_base_krw,employment_base_krw,
                             assessment_sha256,scope):
    """Unrounded references only, ordinary full-month employee, no relief.

    Health base is agency-assessed and must be in the uncapped/unfloored
    range; employment base is separately assessed. Do not infer from gross.
    LTC is calculated as exact health contribution x 0.9448 / 7.19.
    Source: https://edi.nhis.or.kr/portal/images/popup/20251204_pop01longdesc.html
    https://www.law.go.kr/lsLawLinkInfo.do?chrClsCd=010202&lsJoLnkSeq=1000953537
    https://www.law.go.kr/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1029337291
    """
    require(all(type(x) is str and ID.fullmatch(x) for x in (tenant,worker)),"KR_INSURANCE_SCOPE")
    require(type(period) is str and re.fullmatch(r"2026-(0[1-9]|1[0-2])",period),"KR_INSURANCE_PERIOD")
    require(scope=="ORDINARY_FULL_MONTH_NO_RELIEF_ASSESSED_BASES","KR_INSURANCE_SCOPE")
    # Conservative supported subrange, not statutory thresholds.
    require(_whole(health_base_krw,1000000,10000000)
            and _whole(employment_base_krw,0,10**9),"KR_INSURANCE_BASE")
    require(type(assessment_sha256) is str and HEX.fullmatch(assessment_sha256),"KR_INSURANCE_EVIDENCE")
    amounts={"health":Fraction(health_base_krw*719,20000),
             "long_term_care":Fraction(health_base_krw*9448,2000000),
             "employment_insurance":Fraction(employment_base_krw*9,1000)}
    return {"policy":"KR_INSURANCE_2026_RESTRICTED_V1","status":"UNROUNDED_REFERENCE_ONLY",
        "employee_exact":{k:_money(v) for k,v in amounts.items()},
        "employee_total_exact":_money(sum(amounts.values(),Fraction())),
        "reference_sha256":hash_input({"v":"KR_INSURANCE_2026_RESTRICTED_V1","tenant":tenant,"worker":worker,
            "period":period,"health_base":health_base_krw,"employment_base":employment_base_krw,
            "assessment":assessment_sha256,"scope":scope}),
        "requires_human_review":True,"statutory_validated":False,"payment_authorized":False,
        "unresolved":["ELIGIBILITY","RELIEF_AND_CAPS","STATUTORY_ROUNDING","ASSESSMENT_RECONCILIATION","TAX"]}
