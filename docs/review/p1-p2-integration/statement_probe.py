"""Synthetic review-only checks; no DB, payments, or statutory validation."""
import copy
from fractions import Fraction
from itertools import product
from app.naruv_payroll_draft import draft_gross,PayrollBlocked
from app.naruv_kr_payroll_review import source_bound_review,restricted_wage_statement_2026,DEDUCTIONS

def make(period,base,ordinary,regular,overtime,first,after,night):
    row=dict(date=period+'-02',regular=regular,overtime=overtime,holiday_first8=first,holiday_after8=after,night=night)
    minutes=[dict(date=row['date'],regular=regular,additional=overtime+first+after)]
    common=dict(tenant='synthetic-a',worker='worker-1',period=period)
    source=dict(common,policy_revision='r1',hourly_krw=base,minutes_by_day=minutes)
    proof=draft_gross(**source,multiplier_bps=dict(regular=10000,additional=15000))['draft_sha256']
    d={k:dict(amount_krw=0,evidence_sha256='a'*64,assessment='NOT_APPLICABLE') for k in DEDUCTIONS}
    bound=source_bound_review(**source,additional_bps=15000,expected_draft_sha256=proof,ordinary_hourly=ordinary,classification_sha256='b'*64,classified_days=[row],deductions=d)
    return dict(common,base_hourly=base,ordinary_hourly=ordinary,classification_sha256='b'*64,classified_days=[row],deductions=d,bound_review=bound,payment_date=period+'-25',scope='MANUALLY_ASSESSED_WORK_AND_PREMIUMS_ONLY',completeness_assessment_sha256='e'*64)

def main():
    count=0
    for base,extra in product((10320,10321,12001,15007,100000000),(0,1,777)):
        ordinary=min(base+extra,100000000)
        for r,o,f,a in [(r,o,0,0) for r,o in product((1,59,60,479,480),(0,1,59,60,960)) if r+o<=1440]+[(0,0,f,a) for f,a in [(1,0),(479,0),(480,0),(480,1),(480,59),(480,960)]]:
            for n in sorted({0,1,(r+o+f+a)//2,r+o+f+a}):
                args=make('2026-11',base,ordinary,r,o,f,a,n)
                out=restricted_wage_statement_2026(**args)
                independent=Fraction(base*(r+o+f+a),60)+Fraction(ordinary*(o+f+2*a+n),120)
                expect=(2*independent.numerator+independent.denominator)//(2*independent.denominator)
                assert out['gross_krw']==expect==sum(x['amount_krw'] for x in out['components'])
                assert out['net_krw']==expect-out['deductions_krw']
                assert all(abs(Fraction(**x['exact'])-x['amount_krw'])<1 for x in out['components'])
                assert out==restricted_wage_statement_2026(**args)
                assert all(out[k] is False for k in ('statutory_validated','payment_authorized','delivery_authorized','production_authorized','completeness_verified','payment_date_verified'))
                count+=1
    a=make('2026-12',12001,12001,479,59,0,0,59)
    assert restricted_wage_statement_2026(**dict(a,payment_date='2027-01-31'))['proposed_payment_date']=='2027-01-31'
    denied=0
    for change in (dict(payment_date='2027-02-01'),dict(payment_date='2026-12-32'),dict(worker='other'),dict(tenant='other'),dict(scope='ALL_WAGES'),dict(bound_review=dict(a['bound_review'],review_binding_sha256='0'*64)),dict(completeness_assessment_sha256='bad'),dict(deductions={}),dict(classified_days=[dict(a['classified_days'][0],night=600)])):
        try:restricted_wage_statement_2026(**dict(a,**change))
        except PayrollBlocked:denied+=1
        else:raise AssertionError('unexpected acceptance')
    print('STATEMENT_ARITHMETIC_PASS',count,'BOUNDARY_DATE_PASS 1','NEGATIVE_PASS',denied)
if __name__=='__main__':main()
