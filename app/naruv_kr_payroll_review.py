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


def withholding_reference_2026(*,tenant,worker,period,table_amount_krw,selection_percent,
                               assessment_sha256,scope):
    """Restricted unrounded reference from externally assessed table amount.

    No official table lookup, family deductions, bonus, relief, settlement,
    minimum collection or statutory truncation. Sources: NTS guidance,
    Income Tax Act Enforcement Decree Art.194, Local Tax Act Art.103-13.
    """
    require(all(type(x) is str and ID.fullmatch(x) for x in (tenant,worker)),"KR_TAX_SCOPE")
    require(type(period) is str and re.fullmatch(r"2026-(0[1-9]|1[0-2])",period),"KR_TAX_PERIOD")
    require(scope=="ASSESSED_ORDINARY_MONTHLY_TABLE_NO_RELIEF","KR_TAX_SCOPE")
    require(_whole(table_amount_krw,0,10**9) and type(selection_percent) is int
            and selection_percent in (80,100,120),"KR_TAX_AMOUNT")
    require(type(assessment_sha256) is str and HEX.fullmatch(assessment_sha256),"KR_TAX_EVIDENCE")
    national=Fraction(table_amount_krw*selection_percent,100)
    local=national/10
    return {"policy":"KR_WITHHOLDING_2026_REFERENCE_V1","status":"UNROUNDED_REFERENCE_ONLY",
        "national_exact":_money(national),"local_exact":_money(local),"total_exact":_money(national+local),
        "reference_sha256":hash_input({"policy":"KR_WITHHOLDING_2026_REFERENCE_V1","tenant":tenant,
            "worker":worker,"period":period,"table_amount":table_amount_krw,"selection":selection_percent,
            "assessment":assessment_sha256,"scope":scope}),
        "requires_human_review":True,"statutory_validated":False,"payment_authorized":False,
        "unresolved":["OFFICIAL_TABLE_LOOKUP","ELIGIBILITY_AND_RELIEF","BONUS","STATUTORY_ROUNDING","YEAR_END_SETTLEMENT"]}


# Official decree Appendix 2, amended 2026-02-27, PDF page 14.
# Matched against both text and rendered page. Scope deliberately limited;
# unsupported bands must fail closed. No guessed/interpolated table values.
KR_TABLE_SOURCE="https://law.go.kr/flDownload.do?bylClsCd=110201&flSeq=163623339&gubun="
KR_TABLE_EFFECTIVE="2026-03-01"
KR_TABLE_LOW=3140000
KR_TABLE_HIGH=3660000
KR_TABLE_STEP=20000
KR_TABLE_ROWS=(
    (86330,68830,36560,31310,26060,20810,16700,13320,9950,6570,3200),
    (88040,70540,37220,31970,26720,21470,17120,13750,10370,7000,3620),
    (89750,72250,37880,32630,27380,22130,17540,14170,10790,7420,4040),
    (91460,73960,38540,33290,28040,22790,17970,14590,11220,7840,4470),
    (93170,75670,40120,33950,28700,23450,18390,15020,11640,8270,4890),
    (95430,77380,41770,34610,29360,24110,18860,15440,12070,8690,5320),
    (97880,79100,43420,35270,30020,24770,19520,15870,12490,9120,5740),
    (100320,80810,45070,35920,30670,25420,20170,16290,12910,9540,6160),
    (102770,82520,46720,36580,31330,26080,20830,16710,13340,9960,6590),
    (105210,84230,48370,37240,31990,26740,21490,17140,13760,10390,7010),
    (107660,85940,49940,37870,32620,27370,22120,17540,14170,10790,7420),
    (110100,87650,51510,38500,33250,28000,22750,17950,14570,11200,7820),
    (112550,89370,53070,39950,33880,28630,23380,18350,14970,11600,8220),
    (114990,91080,54640,41510,34500,29250,24000,18750,15370,12000,8620),
    (117440,92790,56200,43080,35130,29880,24630,19380,15780,12400,9030),
    (119880,94880,57770,44640,35750,30500,25250,20000,16180,12800,9430),
    (122330,97330,59330,46210,36380,31130,25880,20630,16580,13210,9830),
    (124770,99770,60900,47770,37010,31760,26510,21260,16980,13610,10230),
    (127220,102220,62460,49340,37630,32380,27130,21880,17390,14010,10640),
    (129660,104660,64030,50900,38260,33010,27760,22510,17790,14410,11040),
    (132110,107110,65590,52460,39340,33630,28380,23130,18190,14820,11440),
    (134550,109550,67150,54030,40900,34260,29010,23760,18590,15220,11840),
    (137000,112000,68720,55590,42470,34880,29630,24380,19130,15620,12250),
    (139440,114440,70280,57160,44030,35510,30260,25010,19760,16020,12650),
    (141890,116890,71850,58720,45600,36140,30890,25640,20390,16420,13050),
    (144330,119330,73410,60290,47160,36760,31510,26260,21010,16830,13450),
)

# Additional checked pages 13, 15 and 16. The original page-14 proof stays stable.
KR_TABLE_BEFORE=(
    (57660,40160,25510,20260,16350,12970,9600,6220,2850,0,0),
    (58520,41020,25840,20590,16560,13180,9810,6430,3060,0,0),
    (59370,41870,26170,20920,16770,13400,10020,6650,3270,0,0),
    (60230,42730,26500,21250,16980,13610,10230,6860,3480,0,0),
    (61080,43580,26830,21580,17190,13820,10440,7070,3690,0,0),
    (61940,44440,27160,21910,17410,14030,10660,7280,3910,0,0),
    (62790,45290,27490,22240,17620,14240,10870,7490,4120,0,0),
    (63650,46150,27820,22570,17830,14460,11080,7710,4330,0,0),
    (64510,47010,28150,22900,18040,14670,11290,7920,4540,1170,0),
    (65360,47860,28480,23230,18250,14880,11500,8130,4750,1380,0),
    (66220,48720,28810,23560,18470,15090,11720,8340,4970,1590,0),
    (67070,49570,29140,23890,18680,15300,11930,8550,5180,1800,0),
    (67930,50430,29470,24220,18970,15510,12140,8760,5390,2010,0),
    (68780,51280,29800,24550,19300,15730,12350,8980,5600,2230,0),
    (69640,52140,30130,24880,19630,15940,12560,9190,5810,2440,0),
    (70500,53000,30460,25210,19960,16150,12780,9400,6030,2650,0),
    (71350,53850,30790,25540,20290,16360,12990,9610,6240,2860,0),
    (72210,54710,31120,25870,20620,16570,13200,9820,6450,3070,0),
    (73060,55560,31450,26200,20950,16790,13410,10040,6660,3290,0),
    (74350,56850,31940,26690,21440,17100,13730,10350,6980,3600,0),
    (76060,58560,32600,27350,22100,17530,14150,10780,7400,4030,0),
    (77770,60270,33260,28010,22760,17950,14580,11200,7830,4450,1080),
    (79480,61980,33920,28670,23420,18380,15000,11630,8250,4880,1500),
    (81190,63690,34580,29330,24080,18830,15430,12050,8680,5300,1930),
    (82900,65400,35240,29990,24740,19490,15850,12470,9100,5720,2350),
    (84620,67120,35900,30650,25400,20150,16270,12900,9520,6150,2770),
)
KR_TABLE_AFTER=(
    (146780,121780,74980,61850,48730,37390,32140,26890,21640,17230,13850),
    (149220,124220,76540,63420,50290,38010,32760,27510,22260,17630,14260),
    (151670,126670,78110,64980,51860,38730,33390,28140,22890,18030,14660),
    (154110,129110,79670,66550,53420,40300,34020,28770,23520,18440,15060),
    (156560,131560,81230,68110,54980,41860,34640,29390,24140,18890,15460),
    (163920,136090,84260,71130,58010,44880,35850,30600,25350,20100,16240),
    (166590,138740,85970,72850,59720,46600,36540,31290,26040,20790,16680),
    (169260,141400,87680,74560,61430,48310,37220,31970,26720,21470,17120),
    (171930,144050,89390,76270,63140,50020,37900,32650,27400,22150,17560),
    (174600,146710,91100,77980,64850,51730,38600,33340,28090,22840,18000),
    (177270,149360,92820,79690,66570,53440,40320,34020,28770,23520,18440),
    (179940,152020,94920,81400,68280,55150,42030,34710,29460,24210,18960),
    (182610,154670,97370,83110,69990,56860,43740,35390,30140,24890,19640),
    (185280,157330,99810,84830,71700,58580,45450,36080,30830,25580,20330),
    (187950,159980,102260,86540,73410,60290,47160,36760,31510,26260,21010),
    (190620,162640,104700,88250,75120,62000,48870,37450,32200,26950,21700),
    (193290,165290,107150,89960,76840,63710,50590,38130,32880,27630,22380),
    (195960,167950,109590,91670,78550,65420,52300,39170,33570,28320,23070),
    (198630,170600,112040,93380,80260,67130,54010,40880,34250,29000,23750),
    (201300,173260,114480,95730,81970,68840,55720,42590,34930,29680,24430),
    (203970,175910,116930,98180,83680,70560,57430,44310,35620,30370,25120),
    (206640,178570,119370,100620,85390,72270,59140,46020,36300,31050,25800),
    (209310,181220,121820,103070,87100,73980,60850,47730,36990,31740,26490),
    (211980,183880,124260,105510,88820,75690,62570,49440,37670,32420,27170),
    (214650,186530,126710,107960,90530,77400,64280,51150,38360,33110,27860),
    (217320,189190,129150,110400,92240,79110,65990,52860,39740,33790,28540),
    (219990,191840,131600,112850,94100,80830,67700,54580,41450,34480,29230),
    (222660,194500,134040,115290,96540,82540,69410,56290,43160,35160,29910),
    (225330,197150,136490,117740,98990,84250,71120,58000,44870,35850,30600),
    (228000,199810,138930,120180,101430,85960,72830,59710,46580,36530,31280),
    (230670,202460,141380,122630,103880,87670,74550,61420,48300,37220,31970),
    (233340,205120,143820,125070,106320,89380,76260,63130,50010,37900,32650),
    (236010,207770,146270,127520,108770,91090,77970,64840,51720,38590,33330),
    (238680,210430,148710,129960,111210,92810,79680,66560,53430,40310,34020),
    (241350,213080,151160,132410,113660,94910,81390,68270,55140,42020,34700),
    (244020,215740,153600,134850,116100,97350,83100,69980,56850,43730,35390),
    (246690,218390,156050,137300,118550,99800,84820,71690,58570,45440,36070),
    (249360,221050,158490,139740,120990,102240,86530,73400,60280,47150,36760),
    (252030,223700,160940,142190,123440,104690,88240,75110,61990,48860,37440),
    (254700,226360,163380,144630,125880,107130,89950,76820,63700,50570,38130),
    (257370,229010,165830,147080,128330,109580,91660,78540,65410,52290,39160),
    (260040,231670,168270,149520,130770,112020,93370,80250,67120,54000,40870),
    (262840,234460,170850,152100,133350,114600,95850,82050,68930,55800,42680),
    (265650,237250,173430,154680,135930,117180,98430,83860,70730,57610,44480),
    (268450,240040,176010,157260,138510,119760,101010,85670,72540,59420,46290),
    (271260,242830,178590,159840,141090,122340,103590,87470,74350,61220,48100),
    (276560,248120,183670,164920,146170,127420,108670,89920,76150,63030,49900),
    (279370,250910,186250,167500,148750,130000,111250,92500,77960,64830,51710),
    (282170,253700,188830,170080,151330,132580,113830,95080,79760,66640,53510),
    (284980,256490,191410,172660,153910,135160,116410,97660,81570,68450,55320),
    (287780,259280,193990,175240,156490,137740,118990,100240,83380,70250,57130),
    (290590,262070,196570,177820,159070,140320,121570,102820,85180,72060,58930),
)
KR_TABLE_REVIEW_LOW=2810000
KR_TABLE_REVIEW_HIGH=4700000

def _checked_table_row(wage):
    if wage<3000000:
        idx=(wage-2810000)//10000
        return KR_TABLE_BEFORE[idx],2810000+idx*10000,2820000+idx*10000,"KR_TABLE_2026_PAGE13_V1"
    if wage<KR_TABLE_LOW:
        idx=(wage-3000000)//20000
        return KR_TABLE_BEFORE[19+idx],3000000+idx*20000,3020000+idx*20000,"KR_TABLE_2026_PAGE13_V1"
    if wage<KR_TABLE_HIGH:
        idx=(wage-KR_TABLE_LOW)//KR_TABLE_STEP
        return KR_TABLE_ROWS[idx],KR_TABLE_LOW+idx*KR_TABLE_STEP,KR_TABLE_LOW+(idx+1)*KR_TABLE_STEP,"KR_TABLE_2026_PAGE14_V1"
    idx=(wage-KR_TABLE_HIGH)//KR_TABLE_STEP
    return KR_TABLE_AFTER[idx],KR_TABLE_HIGH+idx*KR_TABLE_STEP,KR_TABLE_HIGH+(idx+1)*KR_TABLE_STEP,"KR_TABLE_2026_PAGE"+str(15+idx//26)+"_V1"

def withholding_table_review_2026(*,tenant,worker,withholding_date,taxable_monthly_krw,
                                  eligible_family_count,eligible_children_8_20,
                                  selection_percent,assessment_sha256,scope):
    """Actual table lookup for four checked official pages.

    Family/child eligibility and taxable monthly wage are assessed upstream.
    No statutory rounding, collection threshold, bonus, relief or filing.
    Applies only to withholding dates March–December 2026, pending change
    control; not a calculation for unsupported pay bands or years.
    """
    require(type(withholding_date) is str and re.fullmatch(r"2026-[0-9]{2}-[0-9]{2}",withholding_date),"KR_TABLE_DATE")
    from datetime import date
    try:d=date.fromisoformat(withholding_date)
    except ValueError:raise PayrollBlocked("KR_TABLE_DATE") from None
    require(d>=date(2026,3,1),"KR_TABLE_DATE")
    require(_whole(taxable_monthly_krw,KR_TABLE_REVIEW_LOW,KR_TABLE_REVIEW_HIGH-1),"KR_TABLE_BAND_UNSUPPORTED")
    require(_whole(eligible_family_count,1,11) and _whole(eligible_children_8_20,0,eligible_family_count-1),"KR_TABLE_FAMILY_SCOPE")
    require(scope=="ASSESSED_ORDINARY_MONTHLY_TABLE_NO_RELIEF","KR_TABLE_SCOPE")
    row,low,high,version=_checked_table_row(taxable_monthly_krw)
    amount=row[eligible_family_count-1]
    children=eligible_children_8_20
    relief=0 if children==0 else (20830 if children==1 else 45830+33330*(children-2))
    adjusted=max(0,amount-relief)
    review=withholding_reference_2026(tenant=tenant,worker=worker,period=withholding_date[:7],
        table_amount_krw=adjusted,selection_percent=selection_percent,assessment_sha256=assessment_sha256,scope=scope)
    proof=hash_input({"v":version,"source":KR_TABLE_SOURCE,"effective":KR_TABLE_EFFECTIVE,
        "date":withholding_date,"tenant":tenant,"worker":worker,"taxable":taxable_monthly_krw,
        "family":eligible_family_count,"children":children,"row":row,"selection":selection_percent,
        "assessment":assessment_sha256,"reference":review["reference_sha256"]})
    return {"status":"RESTRICTED_OFFICIAL_TABLE_REFERENCE_ONLY","table_amount_krw":amount,
        "child_adjusted_krw":adjusted,"table_low_krw":low,
        "table_high_exclusive_krw":high,"reference":review,
        "table_source":KR_TABLE_SOURCE,"review_sha256":proof,"statutory_validated":False,
        "payment_authorized":False,"production_authorized":False}
