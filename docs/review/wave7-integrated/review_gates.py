"""Offline candidate; inputs must be independently retrieved by trusted server code.
No network, payments, backup access, or production authorization.
"""
import hashlib, re, json
from datetime import datetime, timedelta

class Blocked(ValueError): pass

def need(ok,code):
    if not ok: raise Blocked(code)

def digest(x,n=64): return type(x) is str and re.fullmatch(r'[0-9a-f]{%d}'%n,x) is not None

def utc(x): return type(x) is datetime and x.utcoffset()==timedelta(0)

def operations_gate(*, expected_sha, observed_sha, observed_at, now, probe, deployment_live):
    need(digest(expected_sha,40) and digest(observed_sha,40),'OPS_SOURCE')
    need(utc(observed_at) and utc(now),'OPS_TIME')
    need(type(deployment_live) is bool and type(probe) is dict,'OPS_SHAPE')
    reasons=[]
    if expected_sha!=observed_sha: reasons.append('OPS_SOURCE_MISMATCH')
    if not timedelta(0)<=now-observed_at<=timedelta(minutes=5): reasons.append('OPS_STALE')
    if not deployment_live: reasons.append('OPS_DEPLOY_NOT_LIVE')
    if probe.get('status')!='QA_HEALTH_AND_UNAUTHENTICATED_BARRIER_PASS': reasons.append('OPS_PROBE_BLOCKED')
    obs=probe.get('observations')
    # The Wave6 receipt's final health + root observations must be successful.
    if (type(obs) is not list or not 2<=len(obs)<=5 or any(type(r) is not dict for r in obs)
        or any(not (type(r.get(k)) is int and r[k]==v) for r, code in zip(obs[-2:],(200,401)) for k,v in [('curl_exit',0),('http',code),('tls',0)])
        or [r.get('path') for r in obs[-2:]]!=['health','root']): reasons.append('OPS_PROBE_SHAPE')
    if any(probe.get(k) is not False for k in ('release_authorized','database_verified','deployed_sha_verified','production_sla_verified')): reasons.append('OPS_AUTHORITY')
    return {'status':'BLOCKED_EVIDENCE' if reasons else 'TRANSPORT_AND_DEPLOY_METADATA_MATCH_ONLY','reasons':reasons,'database_verified':False,'authenticated_business_verified':False,'production_authorized':False}

def reconcile_restore_inventory(*, expected, vault, b2, signed_review, trusted_evidence_sha256, signed_message):
    """Compare independently acquired inventories; never infer physical custody.
    expected maps unique logical asset IDs to ciphertext SHA256; each provider
    inventory contains those IDs plus provider-specific immutable version IDs.
    """
    need(type(expected) is dict and 1<=len(expected)<=10000 and all(type(k) is str and 1<=len(k)<=257 and digest(v) for k,v in expected.items()),'RESTORE_EXPECTED')
    need(digest(trusted_evidence_sha256) and type(signed_review) is dict and signed_review.get('status')=='SIGNED_CUSTODY_ASSERTIONS_REVIEW_ONLY' and signed_review.get('evidence_sha256')==trusted_evidence_sha256,'RESTORE_SIGNED_EVIDENCE')
    need(type(signed_message) is bytes and 0<len(signed_message)<=8*1024*1024 and hashlib.sha256(signed_message).hexdigest()==trusted_evidence_sha256,'RESTORE_MESSAGE_PIN')
    try: payload=json.loads(signed_message)
    except (ValueError,UnicodeError,RecursionError):raise Blocked('RESTORE_MESSAGE') from None
    need(type(payload) is list and len(payload)==7 and payload[0]=='NARUV_RECOVERY_CUSTODY_V2' and type(payload[2]) is dict,'RESTORE_MESSAGE')
    linked={}
    for key,entry in payload[2].items():
        need(type(key) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',key) and type(entry) is dict and type(entry.get('expected_assets')) is dict,'RESTORE_MESSAGE')
        for asset,h in entry['expected_assets'].items():
            need(type(asset) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',asset) and digest(h),'RESTORE_MESSAGE')
            linked[key+'/'+asset]=h
    need(linked==expected,'RESTORE_SIGNED_INVENTORY_MISMATCH')
    need(type(signed_review.get('restore_assertion_count')) is int and signed_review['restore_assertion_count']==len(expected),'RESTORE_ASSERTION_COUNT')
    need(all(signed_review.get(k) is False for k in ('physical_custody_verified','independent_site_verified','key_activation_authorized','key_retirement_authorized','deletion_authorized','production_authorized')),'RESTORE_AUTHORITY')
    for rows in (vault,b2):
        need(type(rows) is list and len(rows)==len(expected),'RESTORE_COVERAGE')
        seen=set(); versions=set()
        for r in rows:
            need(type(r) is dict and set(r)=={'asset_id','ciphertext_sha256','version_id'},'RESTORE_ROW')
            a,h,v=r['asset_id'],r['ciphertext_sha256'],r['version_id']
            need(type(a) is str and a in expected and a not in seen and digest(h) and h==expected[a],'RESTORE_DIGEST')
            need(type(v) is str and 1<=len(v)<=256 and v not in versions,'RESTORE_VERSION')
            seen.add(a); versions.add(v)
    return {'status':'INVENTORY_MATCH_AND_SIGNED_ASSERTION_REFERENCE_ONLY','asset_count':len(expected),'physical_custody_verified':False,'restore_executed':False,'provider_authenticated':False,'production_authorized':False,'key_activation_authorized':False}
