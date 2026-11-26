"""Offline key-custody evidence gate, never key activation or retirement.
Trust roots, scope and challenge must originate outside this function.
A valid signature authenticates an assertion, not physical custody or site independence.
"""
import hashlib,json,re,secrets
from datetime import datetime,timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

ID=re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
HEX=re.compile(r"[a-f0-9]{64}")
def need(ok,code):
    if not ok:raise ValueError(code)
def identifier(x):return type(x) is str and ID.fullmatch(x) is not None
def digest(x):return type(x) is str and HEX.fullmatch(x) is not None
def canonical(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
def sha(x):return hashlib.sha256(x).hexdigest()

def custody_evidence_message(*,tenant,expected_keys,observations,trust,challenge,issued_at):
    need(identifier(tenant) and digest(challenge),"CUSTODY_SCOPE")
    need(type(issued_at) is datetime and issued_at.utcoffset()==timedelta(0),"CUSTODY_TIME")
    need(type(trust) is dict and set(trust)=={"primary_site","independent_site","inventory_fingerprint","custodian_fingerprint"}
        and identifier(trust["primary_site"]) and identifier(trust["independent_site"]) and trust["primary_site"]!=trust["independent_site"]
        and digest(trust["inventory_fingerprint"]) and digest(trust["custodian_fingerprint"])
        and trust["inventory_fingerprint"]!=trust["custodian_fingerprint"],"CUSTODY_TRUST")
    need(type(expected_keys) is dict and 2<=len(expected_keys)<=100,"CUSTODY_EXPECTED")
    for k,v in expected_keys.items():
        need(identifier(k) and type(v) is dict and set(v)=={"state","expected_assets"} and v["state"] in ("ACTIVE","STAGED","RECOVERY_ONLY")
            and type(v["expected_assets"]) is list and 1<=len(v["expected_assets"])<=10000
            and all(identifier(a) for a in v["expected_assets"]) and len(set(v["expected_assets"]))==len(v["expected_assets"]),"CUSTODY_EXPECTED")
    need(sum(v["state"]=="ACTIVE" for v in expected_keys.values())<=1
        and any(v["state"]=="RECOVERY_ONLY" for v in expected_keys.values()),"CUSTODY_KEY_STATE")
    need(type(observations) is list and len(observations)==len(expected_keys),"CUSTODY_COVERAGE")
    seen=set();normalized=[]
    for row in observations:
        need(type(row) is dict and set(row)=={"key_id","state","site_id","custody_receipt_sha256","restores"},"CUSTODY_ROW")
        k=row["key_id"]
        need(identifier(k) and k in expected_keys and k not in seen and row["state"]==expected_keys[k]["state"]
            and row["site_id"]==trust["independent_site"] and digest(row["custody_receipt_sha256"]),"CUSTODY_ROW")
        seen.add(k)
        restores=row["restores"];assets=expected_keys[k]["expected_assets"]
        need(type(restores) is list and len(restores)==len(assets),"CUSTODY_RESTORE_COVERAGE")
        restored=set();clean=[]
        for r in restores:
            need(type(r) is dict and set(r)=={"asset_id","ciphertext_sha256","restore_evidence_sha256","full_authentication","restore_ok","network_isolated"}
                and identifier(r["asset_id"]) and r["asset_id"] in assets and r["asset_id"] not in restored
                and digest(r["ciphertext_sha256"]) and digest(r["restore_evidence_sha256"])
                and all(r[x] is True for x in ("full_authentication","restore_ok","network_isolated")),"CUSTODY_RESTORE_ROW")
            restored.add(r["asset_id"]);clean.append(dict(r))
        normalized.append(dict(row,restores=sorted(clean,key=lambda r:r["asset_id"])))
    expected={k:dict(v,expected_assets=sorted(v["expected_assets"])) for k,v in expected_keys.items()}
    return canonical(["NARUV_RECOVERY_CUSTODY_V1",tenant,expected,sorted(normalized,key=lambda r:r["key_id"]),trust,challenge,issued_at.isoformat()])

def review_custody_evidence(*,tenant,expected_keys,observations,trust,challenge,issued_at,as_of,
        inventory_public_key,custodian_public_key,inventory_signature,custodian_signature):
    need(type(as_of) is datetime and as_of.utcoffset()==timedelta(0)
        and type(issued_at) is datetime and issued_at.utcoffset()==timedelta(0)
        and timedelta(0)<=as_of-issued_at<=timedelta(minutes=10),"CUSTODY_FRESHNESS")
    msg=custody_evidence_message(tenant=tenant,expected_keys=expected_keys,observations=observations,trust=trust,challenge=challenge,issued_at=issued_at)
    for role,key,sig in (("inventory",inventory_public_key,inventory_signature),("custodian",custodian_public_key,custodian_signature)):
        need(type(key) is bytes and len(key)==32 and type(sig) is bytes and len(sig)==64
            and secrets.compare_digest(sha(key),trust[role+"_fingerprint"]),"CUSTODY_SIGNER_PIN")
        try:Ed25519PublicKey.from_public_bytes(key).verify(sig,role.encode()+b":"+msg)
        except (InvalidSignature,ValueError):raise ValueError("CUSTODY_SIGNATURE") from None
    return {"status":"SIGNED_CUSTODY_ASSERTIONS_REVIEW_ONLY","evidence_sha256":sha(msg),
        "key_count":len(expected_keys),"restore_assertion_count":sum(len(v["expected_assets"]) for v in expected_keys.values()),
        "requires_atomic_challenge_consumption":True,"physical_custody_verified":False,
        "independent_site_verified":False,"key_activation_authorized":False,"key_retirement_authorized":False,
        "deletion_authorized":False,"production_authorized":False}
