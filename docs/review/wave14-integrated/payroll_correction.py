"""Review-only adjustment arithmetic on two independently verified draft snapshots.
No wage recovery, payment, deduction authority, statutory or tax conclusion.
Inputs must come from authenticated historical and current records, not HTTP claims.
"""
import hashlib,json,re
from copy import deepcopy
from review_gates import need,digest

def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')

def compare(*,previous,current,old_pin,new_pin,tenant,worker,period,old_assessment,new_assessment,verifier):
    need(all(digest(x) for x in (old_pin,new_pin,old_assessment,new_assessment)), 'CORRECTION_PIN')
    need(all(type(x) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',x) for x in (tenant,worker)) and type(period) is str and re.fullmatch(r'2026-(0[1-9]|1[0-2])',period),'CORRECTION_SCOPE')
    a,b=deepcopy((previous,current))
    def check(d,pin,assessment):
        need(type(d) is dict and (d.get('worker'),d.get('period'),d.get('review_sha256'))==(worker,period,pin),'CORRECTION_SCOPE')
        result=verifier(draft=deepcopy(d),tenant=tenant,assessment_sha256=assessment,expected_review_sha256=pin)
        need(type(result) is dict and result.get('status')=='DRAFT_SOURCE_INTEGRITY_ONLY' and all(result.get(k) is False for k in ('statutory_validated','payment_authorized','delivery_authorized','production_authorized')),'CORRECTION_VERIFIER')
        fields=('gross_krw','deductions_krw','net_krw')
        need(all(type(d.get(k)) is int and 0<=d[k]<=10**12 for k in fields) and d['gross_krw']-d['deductions_krw']==d['net_krw'],'CORRECTION_TOTAL')
        def lines(k):
            rows=d.get(k);need(type(rows) is list and 1<=len(rows)<=64,'CORRECTION_LINES');out={}
            for r in rows:
                need(type(r) is dict and type(r.get('kind')) is str and re.fullmatch(r'[a-z][a-z0-9_]{0,63}',r['kind']) and r['kind'] not in out and type(r.get('amount_krw')) is int and 0<=r['amount_krw']<=10**12,'CORRECTION_LINE')
                out[r['kind']]=r['amount_krw']
            return out
        gross,ds=lines('components'),lines('deductions')
        need(sum(gross.values())==d['gross_krw'] and sum(ds.values())==d['deductions_krw'],'CORRECTION_LINE_TOTAL')
        return gross,ds
    ag,ad=check(a,old_pin,old_assessment);bg,bd=check(b,new_pin,new_assessment)
    def deltas(x,y):return {k:y.get(k,0)-x.get(k,0) for k in sorted(x.keys()|y.keys())}
    gd,dd=deltas(ag,bg),deltas(ad,bd)
    g=b['gross_krw']-a['gross_krw'];d=b['deductions_krw']-a['deductions_krw'];n=b['net_krw']-a['net_krw']
    need(sum(gd.values())==g and sum(dd.values())==d and g-d==n,'CORRECTION_RECONCILIATION')
    return dict(status='ADJUSTMENT_REVIEW_ONLY',gross_delta_krw=g,deductions_delta_krw=d,net_delta_krw=n,component_deltas=gd,deduction_deltas=dd,issues=['NEGATIVE_NET_DELTA_MANUAL_REVIEW'] if n<0 else [],review_sha256=hashlib.sha256(canonical(['NARUV_PAY_CORRECTION_V1',tenant,worker,period,old_pin,new_pin,old_assessment,new_assessment,gd,dd])).hexdigest(),statutory_validated=False,payment_authorized=False,recovery_authorized=False,production_authorized=False)
