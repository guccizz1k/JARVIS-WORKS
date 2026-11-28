"""One new composite local review journal for prospective ACL + custody assertions.
No link to old journal domains; no actual custody/site/identity/production attestation.
Four distinct trusted public key pins required. Independently supplied trust scope required.
"""
import os,stat,hashlib,hmac
from datetime import datetime,timezone,timedelta
from copy import deepcopy
from policy_approval import verify
from prospective_acl import canonical
from review_gates import need,digest,Blocked,reconcile_restore_inventory
from pinned.naruv_recovery_custody_review import custody_evidence_message,review_custody_evidence

def combine(fd,*,policy,custody,expected_scope,expected_tenant,expected_challenge,expected_policy_pin,expected_custody_pin,expected_policy_signers,expected,vault,b2):
    need(type(fd) is int and fd>=0,'COMBINED_DIRECTORY');st=os.fstat(fd)
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==0o700,'COMBINED_DIRECTORY')
    p,e,exp,v,b=deepcopy((policy,custody,expected,vault,b2))
    need(type(p) is dict and type(e) is dict and 'now' not in p and 'as_of' not in e,'COMBINED_SHAPE')
    need(all(digest(x) for x in (expected_challenge,expected_policy_pin,expected_custody_pin)) and p.get('expected_scope')==expected_scope and p.get('reference_pin')==expected_policy_pin and e.get('tenant')==expected_tenant and p.get('expected_challenge')==p.get('challenge')==e.get('challenge')==expected_challenge,'COMBINED_SCOPE')
    need(type(e.get('trust')) is dict and type(p.get('fingerprints')) is dict,'COMBINED_TRUST')
    need(type(expected_policy_signers) is dict and p['fingerprints']==expected_policy_signers,'COMBINED_POLICY_SIGNER_PIN')
    pins=list(p['fingerprints'].values())+[e['trust'].get('inventory_fingerprint'),e['trust'].get('custodian_fingerprint')]
    need(len(pins)==4 and all(digest(x) for x in pins) and len(set(pins))==4,'COMBINED_SIGNER_SEPARATION')
    pin=hashlib.sha256(canonical(['NARUV_CUSTODY_TRUST_PIN_V1',e['tenant'],e['expected_keys'],e['trust']])).hexdigest()
    need(hmac.compare_digest(pin,expected_custody_pin),'COMBINED_CUSTODY_PIN')
    now=datetime.now(timezone.utc)
    policy_result=verify(**p,now=now)
    need(policy_result['status']=='PROSPECTIVE_CHECKPOINT_AND_BEHAVIOR_CLAIMS_MATCH_ONLY' and policy_result['dual_signature_assertions_verified'] is True and policy_result['operational_policy_authorized'] is False,'COMBINED_POLICY_BLOCKED')
    signed=review_custody_evidence(**e,as_of=now)
    msg=custody_evidence_message(**{k:e[k] for k in ('tenant','expected_keys','observations','trust','challenge','issued_at')})
    r=reconcile_restore_inventory(expected=exp,vault=v,b2=b,signed_review=signed,trusted_evidence_sha256=signed['evidence_sha256'],signed_message=msg)
    now=datetime.now(timezone.utc)
    need(p['issued_at']<=now<=p['expires_at'] and timedelta(0)<=now-e['issued_at']<=timedelta(minutes=10),'COMBINED_EXPIRED')
    raw=canonical(dict(schema='NARUV_COMBINED_LOCAL_REVIEW_V1',challenge=expected_challenge,scope=expected_scope,tenant=expected_tenant,policy_pin=expected_policy_pin,custody_pin=expected_custody_pin,custody_evidence=signed['evidence_sha256'],production_authorized=False))+b'\n'
    try:f=os.open(expected_challenge+'.combined.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd)
    except FileExistsError:raise Blocked('COMBINED_REPLAY') from None
    with os.fdopen(f,'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
    os.fsync(fd)
    return dict(status='COMBINED_SIGNED_ASSERTIONS_LOCAL_REVIEW_ONLY',asset_count=r['asset_count'],challenge_consumed=True,distributed_replay_verified=False,physical_custody_verified=False,operational_policy_authorized=False,production_authorized=False)
