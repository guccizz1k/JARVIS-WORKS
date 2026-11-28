"""Independent signed assessment authorization for a review proposal only.
The trusted publisher must call this before persist; no payment authorization.
No actual reviewer qualification or legal acceptance inferred from a signature.
"""
from datetime import datetime,timedelta
import hashlib,hmac,re,json,copy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from review_gates import need,digest,utc,Blocked
from postconfirm_adjustment import sha,persist

def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def hash_bytes(x):return hashlib.sha256(x).hexdigest()
def verify(*,record,confirmation_pin,request_id,policy,policy_pin,claim,public_key,signature,now):
    need(utc(now) and digest(confirmation_pin) and type(request_id) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',request_id),'CORRECTION_APPROVAL_SCOPE')
    r,p,c=copy.deepcopy((record,policy,claim))
    need(type(p) is dict and set(p)=={'tenant','candidate_sha','reviewer_pin','publisher_pin','max_age_seconds'} and digest(policy_pin) and hash_bytes(canonical(p))==policy_pin,'CORRECTION_APPROVAL_POLICY')
    need(digest(p['candidate_sha'],40) and digest(p['reviewer_pin']) and digest(p['publisher_pin']) and p['reviewer_pin']!=p['publisher_pin'] and type(p['max_age_seconds']) is int and 1<=p['max_age_seconds']<=86400,'CORRECTION_APPROVAL_INDEPENDENCE')
    flags=('payment_authorized','recovery_authorized','statutory_validated','production_authorized')
    need(type(r) is dict and r.get('tenant')==p['tenant'] and r.get('status')=='POSTCONFIRM_ADJUSTMENT_PROPOSAL_ONLY' and all(r.get(k) is False for k in flags),'CORRECTION_APPROVAL_RECORD')
    fields={'tenant','worker','period','original_receipt_sha256','original_review_sha256','proposed_review_sha256','new_assessment_sha256','reason_sha256','comparison','proposal_sha256','status',*flags}
    need(set(r)==fields and all(type(r[k]) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',r[k]) for k in ('tenant','worker')) and type(r['period']) is str and re.fullmatch(r'2026-(0[1-9]|1[0-2])',r['period']),'CORRECTION_APPROVAL_RECORD_SCHEMA')
    need(all(digest(r[k]) for k in ('original_receipt_sha256','original_review_sha256','proposed_review_sha256','new_assessment_sha256','reason_sha256')) and r['original_review_sha256']!=r['proposed_review_sha256'],'CORRECTION_APPROVAL_RECORD_SCHEMA')
    comp=r['comparison'];amounts=('gross_delta_krw','deductions_delta_krw','net_delta_krw')
    need(type(comp) is dict and set(comp)=={'status',*amounts,'component_deltas','deduction_deltas','issues','review_sha256',*flags} and comp['status']=='ADJUSTMENT_REVIEW_ONLY' and digest(comp['review_sha256']) and all(comp[k] is False for k in flags),'CORRECTION_APPROVAL_COMPARISON')
    need(all(type(comp[k]) is int and abs(comp[k])<=10**12 for k in amounts) and comp['gross_delta_krw']-comp['deductions_delta_krw']==comp['net_delta_krw'],'CORRECTION_APPROVAL_TOTAL')
    for field,total in (('component_deltas','gross_delta_krw'),('deduction_deltas','deductions_delta_krw')):
        d=comp[field];need(type(d) is dict and 1<=len(d)<=128 and all(type(k) is str and re.fullmatch(r'[a-z][a-z0-9_]{0,63}',k) and type(v) is int and abs(v)<=10**12 for k,v in d.items()) and sum(d.values())==comp[total],'CORRECTION_APPROVAL_TOTAL')
    need(comp['issues']==(['NEGATIVE_NET_DELTA_MANUAL_REVIEW'] if comp['net_delta_krw']<0 else []),'CORRECTION_APPROVAL_WARNING')
    core={k:v for k,v in r.items() if k not in (*flags,'status','proposal_sha256')}
    need(digest(r.get('proposal_sha256')) and sha(core)==r['proposal_sha256'],'CORRECTION_APPROVAL_RECORD_PIN')
    required={'tenant':p['tenant'],'worker':r.get('worker'),'period':r.get('period'),'candidate_sha':p['candidate_sha'],'request_id':request_id,'confirmation_sha256':confirmation_pin,'proposal_sha256':r['proposal_sha256'],'assessment_sha256':r.get('new_assessment_sha256'),'reason_sha256':r.get('reason_sha256'),'decision':'REVIEW_PROPOSAL_ONLY'}
    need(type(c) is dict and set(c)==set(required)|{'issued_at','expires_at'} and all(c[k]==v for k,v in required.items()),'CORRECTION_APPROVAL_BINDING')
    try:a,b=(datetime.fromisoformat(c[k]) for k in ('issued_at','expires_at'))
    except (TypeError,ValueError):raise Blocked('CORRECTION_APPROVAL_TIME') from None
    need(utc(a) and utc(b) and timedelta(0)<b-a<=timedelta(seconds=p['max_age_seconds']) and a<=now<=b,'CORRECTION_APPROVAL_TIME')
    need(type(public_key) is bytes and len(public_key)==32 and hmac.compare_digest(hash_bytes(public_key),p['reviewer_pin']) and type(signature) is bytes and len(signature)==64,'CORRECTION_APPROVAL_KEY')
    msg=b'NARUV_CORRECTION_APPROVAL_V1\0'+bytes.fromhex(policy_pin)+canonical(c)
    try:Ed25519PublicKey.from_public_bytes(public_key).verify(signature,msg)
    except (ValueError,InvalidSignature):raise Blocked('CORRECTION_APPROVAL_SIGNATURE') from None
    return dict(status='SIGNED_REVIEW_PROPOSAL_ASSERTION_ONLY',approval_sha256=hash_bytes(msg),proposal_sha256=r['proposal_sha256'],request_id=request_id,statutory_validated=False,payment_authorized=False,recovery_authorized=False,production_authorized=False)


def publish_review(cur,*,csrf,**kwargs):
    """Trusted publisher adapter only. DB RPC remains an independent access boundary.
    A caller who can invoke the predecessor RPC directly is not constrained by this wrapper.
    Same request id is idempotent; this is not a distributed replay journal.
    """
    k=copy.deepcopy(kwargs)
    approval=verify(**k)
    result=persist(cur,request_id=k['request_id'],confirmation_pin=k['confirmation_pin'],csrf=csrf,record=k['record'])
    return dict(approval=approval,receipt=result,production_authorized=False)
