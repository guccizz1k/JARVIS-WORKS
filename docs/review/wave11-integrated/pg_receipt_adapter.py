"""Caller supplies already authenticated restricted cursor, independent receipt pin.
No connection creation or migration installation. Only a review result.
Work dates are returned from the same confirmed DB snapshot, never HTTP inputs.
"""
from handoff import payroll_handoff
from review_gates import need,digest

def read_review(cur,*,tenant,worker,period,confirmation_pin,receipt_pin,csrf,draft,verifier):
    need(digest(confirmation_pin) and digest(receipt_pin),'HR_STORE_PIN')
    cur.execute('SELECT naruv_draft.read_payroll_review_receipt(%s,%s,%s,%s,%s)',(worker,period,confirmation_pin,receipt_pin,csrf))
    row=cur.fetchone();need(type(row) in (tuple,list) and len(row)==1 and type(row[0]) is dict,'HR_STORE_NOT_FOUND')
    doc=row[0];need(set(doc)=={'record','confirmed_days','confirmation_sha256'} and doc['confirmation_sha256']==confirmation_pin,'HR_STORE_CONFIRMATION')
    r=doc['record'];need(type(r) is dict and (r.get('tenant'),r.get('worker'),r.get('period'))==(tenant,worker,period),'HR_STORE_SCOPE')
    days=doc['confirmed_days'];need(type(days) is list and 1<=len(days)<=31,'HR_STORE_DAYS')
    need(all(type(d) is list and len(d)==3 and type(d[0]) is str and d[0].startswith(period+'-') and all(type(v) is int and 0<=v<=1440 for v in d[1:]) and sum(d[1:])<=1440 for d in days) and len({d[0] for d in days})==len(days),'HR_STORE_DAYS')
    return payroll_handoff(draft=draft,trusted=r,confirmed_days=[d[0] for d in days if sum(d[1:])>0],verifier=verifier)
