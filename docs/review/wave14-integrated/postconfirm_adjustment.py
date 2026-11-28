"""Separate adjustment proposal record, never changes original payroll.
Read the original trusted receipt and a separately approved replacement assessment.
This adapter is review-only; DB installation and legal authority remain external.
"""
import json,hashlib,re
from review_gates import need,digest
from payroll_correction import compare,canonical

def sha(x):return hashlib.sha256(canonical(x)).hexdigest()
def proposal(*,tenant,worker,period,original,old_receipt,old_receipt_pin,proposed,new_assessment_pin,new_review_pin,reason_pin,verifier):
    need(type(original) is dict and type(proposed) is dict,'ADJUSTMENT_DRAFT_SHAPE')
    need(type(old_receipt) is dict and set(old_receipt)=={'tenant','worker','period','receipt_sha256','assessment_sha256','expected_review_sha256','expected_monthly_review_sha256'},'ADJUSTMENT_RECEIPT')
    need((old_receipt['tenant'],old_receipt['worker'],old_receipt['period'])==(tenant,worker,period) and all(digest(x) for x in (old_receipt_pin,new_assessment_pin,new_review_pin,reason_pin)) and old_receipt['receipt_sha256']==old_receipt_pin,'ADJUSTMENT_SCOPE')
    need(all(digest(old_receipt[k]) for k in ('assessment_sha256','expected_review_sha256','expected_monthly_review_sha256')) and original.get('source_review_sha256')==old_receipt['expected_monthly_review_sha256'],'ADJUSTMENT_SOURCE')
    need(new_review_pin!=old_receipt['expected_review_sha256'] and new_assessment_pin!=old_receipt['assessment_sha256'],'ADJUSTMENT_NEW_ASSESSMENT')
    result=compare(previous=original,current=proposed,old_pin=old_receipt['expected_review_sha256'],new_pin=new_review_pin,tenant=tenant,worker=worker,period=period,old_assessment=old_receipt['assessment_sha256'],new_assessment=new_assessment_pin,verifier=verifier)
    record=dict(tenant=tenant,worker=worker,period=period,original_receipt_sha256=old_receipt_pin,original_review_sha256=old_receipt['expected_review_sha256'],proposed_review_sha256=new_review_pin,new_assessment_sha256=new_assessment_pin,reason_sha256=reason_pin,comparison=result)
    return dict(record,proposal_sha256=sha(record),status='POSTCONFIRM_ADJUSTMENT_PROPOSAL_ONLY',payment_authorized=False,recovery_authorized=False,statutory_validated=False,production_authorized=False)

def load_original(cur,*,tenant,worker,period,confirmation_pin,receipt_pin,csrf):
    need(digest(confirmation_pin) and digest(receipt_pin),'ADJUSTMENT_RECEIPT_PIN')
    cur.execute('SELECT naruv_draft.read_payroll_review_receipt(%s,%s,%s,%s,%s)',(worker,period,confirmation_pin,receipt_pin,csrf))
    row=cur.fetchone();need(type(row) in (tuple,list) and len(row)==1 and type(row[0]) is dict,'ADJUSTMENT_RECEIPT')
    result=row[0];r=result.get('record')
    need(result.get('confirmation_sha256')==confirmation_pin and type(r) is dict and set(r)=={'tenant','worker','period','assessment_sha256','expected_review_sha256','expected_monthly_review_sha256'},'ADJUSTMENT_RECEIPT')
    need((r['tenant'],r['worker'],r['period'])==(tenant,worker,period) and all(digest(r[k]) for k in ('assessment_sha256','expected_review_sha256','expected_monthly_review_sha256')),'ADJUSTMENT_SCOPE')
    return dict(r,receipt_sha256=receipt_pin)

def persist(cur,*,request_id,confirmation_pin,csrf,record):
    need(type(request_id) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',request_id) and digest(confirmation_pin),'ADJUSTMENT_REQUEST')
    need(type(record) is dict and set(record)=={'tenant','worker','period','original_receipt_sha256','original_review_sha256','proposed_review_sha256','new_assessment_sha256','reason_sha256','comparison','proposal_sha256','status','payment_authorized','recovery_authorized','statutory_validated','production_authorized'},'ADJUSTMENT_RECORD')
    core={k:v for k,v in record.items() if k not in ('proposal_sha256','status','payment_authorized','recovery_authorized','statutory_validated','production_authorized')}
    need(record['status']=='POSTCONFIRM_ADJUSTMENT_PROPOSAL_ONLY' and all(record[k] is False for k in ('payment_authorized','recovery_authorized','statutory_validated','production_authorized')) and record['proposal_sha256']==sha(core),'ADJUSTMENT_RECORD_PIN')
    cur.execute('SELECT naruv_draft.propose_postconfirm_adjustment(%s,%s,%s,%s,%s,%s,%s::jsonb,%s)',(record['worker'],record['period'],request_id,confirmation_pin,record['original_receipt_sha256'],record['proposal_sha256'],json.dumps(record,ensure_ascii=True,allow_nan=False),csrf))
    row=cur.fetchone();need(type(row) in (list,tuple) and len(row)==1 and type(row[0]) is dict and row[0].get('proposal_sha256')==record['proposal_sha256'] and row[0].get('status')=='POSTCONFIRM_ADJUSTMENT_PROPOSAL_ONLY' and all(row[0].get(k) is False for k in ('payment_authorized','recovery_authorized','statutory_validated','production_authorized')),'ADJUSTMENT_DB_RESPONSE')
    return row[0]


def read_proposal(cur,*,tenant,worker,period,request_id,proposal_pin,csrf):
    need(type(request_id) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',request_id) and digest(proposal_pin),'ADJUSTMENT_REQUEST')
    cur.execute('SELECT naruv_draft.read_postconfirm_adjustment(%s,%s,%s,%s,%s)',(worker,period,request_id,proposal_pin,csrf))
    row=cur.fetchone();need(type(row) in (tuple,list) and len(row)==1 and type(row[0]) is dict,'ADJUSTMENT_DB_RESPONSE')
    r=row[0];need((r.get('tenant'),r.get('worker'),r.get('period'))==(tenant,worker,period) and r.get('proposal_sha256')==proposal_pin and r.get('status')=='POSTCONFIRM_ADJUSTMENT_PROPOSAL_ONLY','ADJUSTMENT_SCOPE')
    need(all(r.get(k) is False for k in ('payment_authorized','recovery_authorized','statutory_validated','production_authorized')),'ADJUSTMENT_RECORD_AUTHORITY')
    core={k:v for k,v in r.items() if k not in ('proposal_sha256','status','payment_authorized','recovery_authorized','statutory_validated','production_authorized')}
    need(sha(core)==proposal_pin,'ADJUSTMENT_RECORD_PIN')
    return r
