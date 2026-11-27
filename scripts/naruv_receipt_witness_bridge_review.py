"""CI-only bridge; a signed witness is a claim, not proof of independent custody.
Do not promote old archive observations or infer environment flags. A separately
pinned witness signs exact observation bytes, approval and execution interval.
The existing V4 format does not contain the witness itself; retain it separately.
"""
import hashlib
import os
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey,Ed25519PrivateKey
from scripts import naruv_future_receipt_review as v
from scripts import naruv_pg_signed_receipt_review as ledger

DOMAIN=b'NARUV_RECOVERY_WITNESS_REVIEW_V1\x00'
OBS_FIELDS={'status','binding_sha256','archive_results','host_isolation','signature','production_authorized'}
WITNESS_FIELDS={'version','approval_pin','binding_sha256','observation_sha256','started_at','ended_at','environment','cleanup'}

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def read_canonical(raw):
    doc=v.decode(raw)
    v.need(v.canonical(doc)==raw,'NONCANONICAL_EVIDENCE')
    return doc

def _verified_payloads(approval_raw,policy_raw,observations,witnesses,*,expected_policy_pin):
    v.need(os.environ.get('GITHUB_ACTIONS')=='true' and
           os.environ.get('GITHUB_REPOSITORY')=='guccizz1k/JARVIS-WORKS' and
           os.environ.get('NARUV_WITNESS_BRIDGE_CI')=='1','WITNESS_BRIDGE_CI_ONLY')
    pin,approval=ledger.parse_approval(approval_raw)
    policy=read_canonical(policy_raw)
    v.exact(policy,{'approval_pin','witness_public_key'},'WITNESS_POLICY_FIELDS')
    v.need(expected_policy_pin==digest(policy_raw),'WITNESS_POLICY_PIN')
    v.need(policy['approval_pin']==pin,'WITNESS_APPROVAL_PIN')
    wk=policy['witness_public_key']
    v.need(v.hexval(wk) and wk!=approval['public_key'],'WITNESS_KEY_SEPARATION')
    v.exact(observations,set(v.SCOPES),'OBSERVATION_SCOPES')
    v.exact(witnesses,set(v.SCOPES),'WITNESS_SCOPES')
    # Capture immutable byte references for both scopes before any signing.
    obs_raw={s:observations[s] for s in v.SCOPES}
    wit_raw={s:witnesses[s] for s in v.SCOPES}
    payloads={}
    for s in v.SCOPES:
        binding=approval['expected'][s]
        bp=digest(v.canonical(binding))
        obs=read_canonical(obs_raw[s]);v.exact(obs,OBS_FIELDS,'OBSERVATION_FIELDS')
        v.need(obs['status']=='PASS_ARCHIVE_OBSERVATIONS_ONLY' and
               obs['host_isolation']=='NOT_ATTESTED' and obs['signature']=='NOT_CREATED' and
               obs['production_authorized'] is False,'OBSERVATION_STATUS')
        v.need(obs['binding_sha256']==bp,'OBSERVATION_BINDING')
        expected=[dict(archive_sha256=h,authenticated=True,restored=True,rows_match=True,catalog_match=True) for h in binding['archives']]
        v.need(v.canonical(obs['archive_results'])==v.canonical(expected),'OBSERVATION_ARCHIVES')
        envelope=read_canonical(wit_raw[s]);v.exact(envelope,{'payload','signature_hex'},'WITNESS_ENVELOPE')
        w=envelope['payload'];v.exact(w,WITNESS_FIELDS,'WITNESS_FIELDS')
        signature=envelope['signature_hex']
        v.need(type(signature) is str and len(signature)==128 and v.hexval(signature[:64]) and v.hexval(signature[64:]),'WITNESS_SIGNATURE_FORMAT')
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(wk)).verify(bytes.fromhex(signature),DOMAIN+v.canonical(w))
        except (InvalidSignature,ValueError):
            raise ValueError('WITNESS_SIGNATURE_INVALID') from None
        v.need(type(w['version']) is int and w['version']==1 and w['approval_pin']==pin and
               w['binding_sha256']==bp and w['observation_sha256']==digest(obs_raw[s]),'WITNESS_BINDING')
        v.need(v.stamp(approval['start'])<=v.stamp(w['started_at'])<v.stamp(w['ended_at'])<=v.stamp(approval['end']),'WITNESS_WINDOW')
        for k,fields in [('environment',v.ENV),('cleanup',v.CLEANUP)]:
            v.exact(w[k],fields,'WITNESS_STATUS_FIELDS')
            v.need(all(x is True for x in w[k].values()),'WITNESS_STATUS_NOT_PASS')
        payloads[s]=dict(binding,version=4,started_at=w['started_at'],ended_at=w['ended_at'],
                         results=expected,environment=w['environment'],cleanup=w['cleanup'])
    return approval,payloads,dict(witness_sha256={s:digest(wit_raw[s]) for s in v.SCOPES},
                        observation_sha256={s:digest(obs_raw[s]) for s in v.SCOPES},
                        witness_policy_sha256=digest(policy_raw),witness_claims='PASS_SIGNATURE_AND_BINDING_ONLY',
                        independent_witness_control='NOT_ATTESTED',actual_host_isolation='NOT_ATTESTED')

def verify_existing_pair(approval_raw,policy_raw,observations,witnesses,reports,*,expected_policy_pin):
    approval,payloads,proof=_verified_payloads(approval_raw,policy_raw,observations,witnesses,expected_policy_pin=expected_policy_pin)
    v.exact(reports,set(v.SCOPES),'REPORT_SCOPES')
    reports={s:reports[s] for s in v.SCOPES}
    result=v.verify_pair(reports,approval['expected'],bytes.fromhex(approval['public_key']),window_start=approval['start'],window_end=approval['end'])
    for s in v.SCOPES:
        doc=read_canonical(reports[s])
        v.need(v.canonical(doc['payload'])==v.canonical(payloads[s]),'RECEIPT_WITNESS_PAYLOAD_MISMATCH')
    return dict(result,**proof)

def build_pair(approval_raw,policy_raw,observations,witnesses,signer):
    # Preserve the early signing-key rejection in the old entrypoint.
    v.need(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='guccizz1k/JARVIS-WORKS' and os.environ.get('NARUV_WITNESS_BRIDGE_CI')=='1','WITNESS_BRIDGE_CI_ONLY')
    _,approval=ledger.parse_approval(approval_raw)
    v.need(isinstance(signer,Ed25519PrivateKey) and signer.public_key().public_bytes_raw().hex()==approval['public_key'],'RECEIPT_SIGNER_KEY')
    approval,payloads,proof=_verified_payloads(approval_raw,policy_raw,observations,witnesses,expected_policy_pin=os.environ.get('NARUV_EXPECTED_WITNESS_POLICY_SHA256'))
    # Only after BOTH inputs validate; no external publication by this helper.
    reports={s:v.canonical(dict(payload=p,signature_hex=signer.sign(v.DOMAIN+v.canonical(p)).hex())) for s,p in payloads.items()}
    result=v.verify_pair(reports,approval['expected'],bytes.fromhex(approval['public_key']),window_start=approval['start'],window_end=approval['end'])
    return reports,dict(result,**proof)
