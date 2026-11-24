"""Offline, fail-closed verification of *signed claims*, not live release authorization.

No I/O, network, secrets or production changes. All trust anchors and the exact
release challenge must be supplied out-of-band by an authorized verifier.
A signature binds a claim; it cannot establish physical custody, historical
completeness, or legal compliance without separate independent evidence.
"""
import hashlib
import json
import re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

SCHEMA = 'JW-RELEASE-EVIDENCE-V1'
DOM = b'JW-RELEASE-EVIDENCE-V1\x00'
H40 = re.compile(r'[0-9a-f]{40}\Z', re.ASCII)
H64 = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
FIELDS = {'schema','kind','review_sha','old_vault_sha','new_vault_sha','scope_sha256',
          'challenge_sha256','observed_at','expires_at','evidence_sha256','checks'}
CHECKS = {
    'archive': {'cipher_count':11,'restore_count':11,'table_count_per_archive':65,
                'historical_row_comparison_count':11,'catalog_comparison_count':11,
                'cleanup':True},
    'custody': {'independent_key_retrieval':True,'separate_administrator':True,
                'separate_host':True,'restore_count':11,'cleanup':True},
    'operations': {'compliance_versions':22,'roles_and_memberships_complete':True,
                   'source_era_signature_verified':True,'main_protection_verified':True,
                   'real_https_e2e_verified':True,'release_ci_verified':True},
}
BINDINGS = ('review_sha','old_vault_sha','new_vault_sha','scope_sha256','challenge_sha256')
class Blocked(ValueError): pass

def require(ok, reason):
    if not ok: raise Blocked(reason)

def canonical(doc):
    return json.dumps(doc,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')

def unique(items):
    d={}
    for k,v in items:
        require(k not in d,'DUPLICATE_JSON_KEY'); d[k]=v
    return d

def digest(data): return hashlib.sha256(data).hexdigest()

def hexvalue(x,pattern): return type(x) is str and pattern.fullmatch(x) is not None

def verify_claim(raw,signature,public_key,expected,key_pin,now,kind,evidence):
    require(kind in CHECKS,'KIND')
    require(type(raw) is bytes and 0<len(raw)<=8192,'CLAIM_SIZE')
    require(type(signature) is bytes and len(signature)==64,'SIGNATURE_FORMAT')
    require(type(public_key) is bytes and len(public_key)==32 and hexvalue(key_pin,H64) and digest(public_key)==key_pin,'SIGNER_PIN')
    require(type(now) is int and now>0,'CLOCK')
    require(type(expected) is dict and set(expected)==set(BINDINGS),'EXPECTED_BINDINGS')
    try:
        d=json.loads(raw.decode('ascii'),object_pairs_hook=unique)
        require(type(d) is dict and set(d)==FIELDS and raw==canonical(d),'CLAIM_SCHEMA')
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature,DOM+raw)
    except (ValueError,UnicodeError,InvalidSignature,TypeError,RecursionError) as e:
        if isinstance(e,Blocked): raise
        raise Blocked('CLAIM_OR_SIGNATURE_INVALID') from None
    require(d['schema']==SCHEMA and d['kind']==kind,'CLAIM_KIND')
    for name in BINDINGS:
        require(hexvalue(d[name],H40 if name.endswith('_sha') else H64) and d[name]==expected[name],'BINDING_MISMATCH')
    require(d['old_vault_sha']!=d['new_vault_sha'],'VAULT_ALIAS')
    observed,expires=d['observed_at'],d['expires_at']
    require(type(observed) is int and type(expires) is int and 0<observed<=now<expires<=observed+86400,'STALE_OR_FUTURE_CLAIM')
    require(type(evidence) is bytes and 0<len(evidence)<=8*1024*1024 and hexvalue(d['evidence_sha256'],H64) and digest(evidence)==d['evidence_sha256'],'EVIDENCE_BINDING')
    checks=d['checks']; want=CHECKS[kind]
    require(type(checks) is dict and set(checks)==set(want) and all(type(checks[k]) is type(v) and checks[k]==v for k,v in want.items()),'CHECKS_INCOMPLETE')
    return d

def evaluate(claims,*,expected,trust_pins,now):
    """Verify three separately pinned signers. Never returns release PASS.

    trust_pins and challenge must come from an authenticated external channel,
    not the candidate evidence itself. This function does not consume challenges
    across runs, verify the content semantics of evidence bytes, or authorize
    promotion. A live operator must perform those checks separately.
    """
    result={'archive':'BLOCKED','custody':'BLOCKED','operations':'BLOCKED',
            'signature_binding':'BLOCKED','live_release':'BLOCKED'}
    try:
        require(type(trust_pins) is dict and set(trust_pins)==set(CHECKS) and all(hexvalue(x,H64) for x in trust_pins.values()) and len(set(trust_pins.values()))==3,'INDEPENDENT_SIGNER_PINS')
        require(type(claims) is dict and set(claims)<=set(CHECKS),'CLAIM_SET')
        seen=set()
        for kind in CHECKS:
            if kind not in claims: continue
            bundle=claims[kind]
            require(type(bundle) is tuple and len(bundle)==4,'BUNDLE_FORMAT')
            raw,sig,pub,evidence=bundle
            d=verify_claim(raw,sig,pub,expected,trust_pins[kind],now,kind,evidence)
            require(d['evidence_sha256'] not in seen,'EVIDENCE_REUSE')
            seen.add(d['evidence_sha256']);result[kind]='SIGNED_CLAIM_BOUND'
        if all(result[k]=='SIGNED_CLAIM_BOUND' for k in CHECKS): result['signature_binding']='PASS'
    except Blocked as e:
        result['blocker']=str(e)
    return result
