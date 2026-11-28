"""Review-only detached dual approval over an independently pinned prospective ACL policy.
Signatures authenticate assertions, not legal identity, actual RLS or external custody.
No changes to historical restore acceptance or operational authorization.
"""
import hashlib,secrets,re
from datetime import datetime,timezone,timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from prospective_acl import canonical,compare
from review_gates import need,digest,Blocked,utc

def message(*,reference_pin,scope,migration,challenge,issued_at,expires_at):
    need(digest(reference_pin) and digest(migration,40) and digest(challenge) and type(scope) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',scope),'ACL_APPROVAL_SCOPE')
    need(utc(issued_at) and utc(expires_at) and timedelta(0)<expires_at-issued_at<=timedelta(hours=24),'ACL_APPROVAL_WINDOW')
    return canonical(['NARUV_PROSPECTIVE_POLICY_APPROVAL_V1',reference_pin,scope,migration,challenge,issued_at.isoformat(),expires_at.isoformat()])

def verify(*,reference,reference_pin,expected_scope,expected_migration,expected_challenge,challenge,issued_at,expires_at,now,public_keys,fingerprints,signatures,observed,behavior):
    need(type(reference) is dict and digest(reference_pin) and secrets.compare_digest(hashlib.sha256(canonical(reference)).hexdigest(),reference_pin),'ACL_REFERENCE_PIN')
    need(reference.get('scope')==expected_scope and reference.get('migration_sha')==expected_migration and digest(expected_challenge) and challenge==expected_challenge,'ACL_APPROVAL_SCOPE')
    msg=message(reference_pin=reference_pin,scope=expected_scope,migration=expected_migration,challenge=challenge,issued_at=issued_at,expires_at=expires_at)
    need(utc(now) and issued_at<=now<=expires_at,'ACL_APPROVAL_EXPIRED')
    roles={'policy_owner','independent_reviewer'}
    need(all(type(x) is dict and set(x)==roles for x in (public_keys,fingerprints,signatures)) and all(digest(v) for v in fingerprints.values()) and len(set(fingerprints.values()))==2,'ACL_APPROVAL_TRUST')
    for role in roles:
        key,sig=public_keys[role],signatures[role]
        need(type(key) is bytes and len(key)==32 and type(sig) is bytes and len(sig)==64 and secrets.compare_digest(hashlib.sha256(key).hexdigest(),fingerprints[role]),'ACL_APPROVAL_TRUST')
        try:Ed25519PublicKey.from_public_bytes(key).verify(sig,role.encode('ascii')+b':'+msg)
        except (ValueError,InvalidSignature):raise Blocked('ACL_APPROVAL_SIGNATURE') from None
    r=compare(reference=reference,reference_pin=reference_pin,observed=observed,observed_scope=expected_scope,behavior=behavior,expected_migration_sha=expected_migration)
    return dict(r,dual_signature_assertions_verified=True,reviewer_identity_verified=False,challenge_consumed=False,operational_policy_authorized=False)
