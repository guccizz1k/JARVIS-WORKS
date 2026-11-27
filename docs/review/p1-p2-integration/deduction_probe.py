"""Synthetic assessed deduction arithmetic only, no statutory determination."""
from copy import deepcopy
from itertools import product
from statement_probe import make
from app.naruv_kr_payroll_review import DEDUCTIONS,source_bound_review,restricted_wage_statement_2026
from app.naruv_payroll_draft import PayrollBlocked

def rebind(a, deductions):
    src=dict(tenant=a['tenant'],worker=a['worker'],period=a['period'],policy_revision='r1',hourly_krw=a['base_hourly'],
        minutes_by_day=[dict(date=r['date'],regular=r['regular'],additional=r['overtime']+r['holiday_first8']+r['holiday_after8']) for r in a['classified_days']],additional_bps=15000,
        expected_draft_sha256=a['bound_review']['source_draft_sha256'],ordinary_hourly=a['ordinary_hourly'],classification_sha256=a['classification_sha256'],classified_days=a['classified_days'],deductions=deductions)
    return dict(a,deductions=deductions,bound_review=source_bound_review(**src))

def main():
    count=0
    for rate,minutes,night in product((10320,12001,15007,100000000),(1,60,479,480),(False,True)):
        a=make('2026-11',rate,rate,minutes,0,0,0,minutes if night else 0)
        gross=a['bound_review']['wage']['gross_estimate_krw']
        for mask in range(1,64):
            active=[k for i,k in enumerate(DEDUCTIONS) if mask & (1<<i)]
            for total in (1,gross//2,gross):
                q,r=divmod(total,len(active));d={k:dict(amount_krw=0,evidence_sha256='a'*64,assessment='NOT_APPLICABLE') for k in DEDUCTIONS}
                for i,k in enumerate(active):d[k]=dict(amount_krw=q+(i<r),evidence_sha256=format(DEDUCTIONS.index(k)+1,'064x'),assessment='ASSESSED')
                b=rebind(a,d);out=restricted_wage_statement_2026(**b)
                assert out['gross_krw']==gross and out['deductions_krw']==total and out['net_krw']==gross-total
                assert {x['kind']:x['amount_krw'] for x in out['deductions']}=={k:v['amount_krw'] for k,v in d.items()}
                assert all(out[k] is False for k in ('statutory_validated','payment_authorized','delivery_authorized','production_authorized'))
                count+=1
    a=make('2026-11',12001,12001,480,0,0,0,0);gross=a['bound_review']['wage']['gross_estimate_krw'];d=deepcopy(a['deductions']);k=DEDUCTIONS[0]
    bad=[dict(amount_krw=-1,assessment='ASSESSED'),dict(amount_krw=gross+1,assessment='ASSESSED'),dict(amount_krw=True,assessment='ASSESSED'),dict(amount_krw=1,assessment='NOT_APPLICABLE'),dict(amount_krw=1,assessment='ASSESSED',evidence_sha256='bad'),dict(amount_krw=0,assessment='UNASSESSED')]
    denied=0
    for change in bad:
        rows=deepcopy(d);rows[k].update(change)
        try:rebind(a,rows)
        except PayrollBlocked:denied+=1
        else:raise AssertionError('invalid deductions accepted')
    d[k].update(amount_krw=1,assessment='ASSESSED');b=rebind(a,d)
    for change in (dict(amount_krw=2),dict(evidence_sha256='b'*64)):
        rows=deepcopy(d);rows[k].update(change)
        try:restricted_wage_statement_2026(**dict(b,deductions=rows))
        except PayrollBlocked:denied+=1
        else:raise AssertionError('deduction source drift accepted')
    print('NONZERO_DEDUCTION_ARITHMETIC_PASS',count,'DEDUCTION_DENIAL_PASS',denied)
if __name__=='__main__':main()
