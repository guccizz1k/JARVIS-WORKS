"""Trusted independent reviewer adapter. PostgreSQL enforces issuer separation,
not Ed25519 itself. Only synthetic fixture use; no real payroll approval."""
import copy,json
from datetime import datetime,timezone
from correction_approval import verify
from review_gates import need

def issue(cur,*,csrf,**kwargs):
    k=copy.deepcopy(kwargs)
    # Use the actual clock, never caller-supplied validation time.
    k['now']=datetime.now(timezone.utc)
    a=verify(**k);r=k['record']
    cur.execute('SELECT naruv_draft.assert_adjustment_review(%s,%s,%s,%s,%s,%s,%s,%s,%s::timestamptz,%s::jsonb,%s)',(r['worker'],r['period'],k['request_id'],k['confirmation_pin'],r['original_receipt_sha256'],r['proposal_sha256'],a['approval_sha256'],k['policy_pin'],k['claim']['expires_at'],json.dumps(r,ensure_ascii=True,allow_nan=False),csrf))
    row=cur.fetchone()
    need(type(row) is tuple and len(row)==1 and type(row[0]) is dict and row[0].get('status')=='REVIEW_ASSERTION_ONLY' and row[0].get('approval_sha256')==a['approval_sha256'] and row[0].get('production_authorized') is False,'ADJUSTMENT_APPROVAL_DB_RESPONSE')
    return row[0]
