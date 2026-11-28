"""Detached signature verification, not proof of physical/legal facts.
Separate artifact environments, scopes and authority pins supplied by trusted policy.
No private keys, external updates, or deployment actions.
"""
import json,hashlib,hmac,re
from datetime import datetime,timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from review_gates import need,digest,utc,Blocked
from release_evidence import REQUIRED

def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def sha(x):return hashlib.sha256(x).hexdigest()
def text(x):return type(x) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',x)

def assess(*,policy,policy_pin,receipts,now):
    need(utc(now) and type(policy) is dict and set(policy)=={'candidate_sha','tenant','requirements'} and digest(policy_pin) and hmac.compare_digest(sha(canonical(policy)),policy_pin),'EVIDENCE_POLICY_PIN')
    need(digest(policy['candidate_sha'],40) and text(policy['tenant']),'EVIDENCE_POLICY_SCOPE')
    req=policy['requirements'];need(type(req) is dict and set(req)==set(REQUIRED) and type(receipts) is dict and set(receipts)<=set(req),'EVIDENCE_REQUIREMENTS')
    pins=[]
    for k,r in req.items():
        need(type(r) is dict and set(r)=={'scope','environment','signer_pin','artifact_pin','max_age_hours'} and r['scope']==REQUIRED[k] and text(r['environment']) and digest(r['signer_pin']) and digest(r['artifact_pin']) and type(r['max_age_hours']) is int and 1<=r['max_age_hours']<=168,'EVIDENCE_RULE')
        pins.append(r['signer_pin'])
    # Independent review, offline custody, and recovery approvers must not share keys.
    critical=['payroll_expert_review','offline_key_access','recovery_acl_baseline','historical_provenance']
    need(len({req[k]['signer_pin'] for k in critical})==len(critical),'EVIDENCE_INDEPENDENCE')
    findings={}
    for k,r in req.items():
        v=receipts.get(k)
        if v is None:findings[k]='BLOCKED_MISSING';continue
        try:
            need(type(v) is dict and set(v)=={'claim','public_key','signature'},'EVIDENCE_SHAPE')
            c=v['claim'];key=v['public_key'];sig=v['signature']
            need(type(c) is dict and set(c)=={'kind','scope','environment','candidate_sha','tenant','artifact_sha256','observed_at','result'},'EVIDENCE_SHAPE')
            need((c['kind'],c['scope'],c['environment'],c['candidate_sha'],c['tenant'],c['artifact_sha256'],c['result'])==(k,r['scope'],r['environment'],policy['candidate_sha'],policy['tenant'],r['artifact_pin'],'PASS'),'EVIDENCE_SCOPE')
            t=datetime.fromisoformat(c['observed_at']);need(utc(t) and timedelta(0)<=now-t<=timedelta(hours=r['max_age_hours']),'EVIDENCE_EXPIRED')
            need(type(key) is bytes and len(key)==32 and hmac.compare_digest(sha(key),r['signer_pin']) and type(sig) is bytes and len(sig)==64,'EVIDENCE_SIGNER')
            Ed25519PublicKey.from_public_bytes(key).verify(sig,b'NARUV_EXTERNAL_EVIDENCE_V1\0'+bytes.fromhex(policy_pin)+canonical(c))
            findings[k]='SIGNED_ASSERTION_ONLY'
        except (Blocked,InvalidSignature,ValueError,TypeError,OverflowError):findings[k]='BLOCKED_INVALID'
    return dict(status='BLOCKED' if any(x.startswith('BLOCKED') for x in findings.values()) else 'SIGNED_ASSERTIONS_REVIEW_REQUIRED',findings=findings,physical_custody_verified=False,statutory_validated=False,release_authorized=False,production_authorized=False)
