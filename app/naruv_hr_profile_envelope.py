"""Offline HR profile encryption candidate; never mounted or persisted.

Caller owns authorization, key custody, lawful purpose, retention and audit.
No resident registration number, bank account or medical fields are accepted.
AES-GCM binds the immutable tenant, worker, revision and key identifier.
"""
import base64
import binascii
import json
import re
import secrets
import unicodedata
from datetime import date
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from .naruv_payroll_draft import ID

class ProfileBlocked(ValueError):pass

def _require(ok):
    if not ok:raise ProfileBlocked("HR_PROFILE_INVALID")

def _canonical(obj):
    return json.dumps(obj,ensure_ascii=True,sort_keys=True,separators=(",",":")).encode("ascii")

def _context(tenant,worker,revision,key_id):
    _require(all(type(x) is str and ID.fullmatch(x) for x in (tenant,worker,revision,key_id)))
    return _canonical(["NARUV_HR_PROFILE_V1",tenant,worker,revision,key_id])

def _profile(profile):
    _require(type(profile) is dict and set(profile)=={"display_name","work_email","employment_start"})
    name,email,start=(profile[k] for k in ("display_name","work_email","employment_start"))
    _require(type(name) is str and 1<=len(name)<=80 and name==name.strip()
        and any(c.isalpha() for c in name)
        and all(unicodedata.category(c)[0] in ("L","M") or c in " -'." for c in name))
    _require(type(email) is str and len(email)<=254 and re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,187}[A-Za-z0-9])?\.[A-Za-z]{2,24}",email))
    _require(type(start) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}",start))
    try:date.fromisoformat(start)
    except ValueError:raise ProfileBlocked("HR_PROFILE_INVALID") from None
    return dict(profile)

def seal_profile(*,tenant,worker,revision,key_id,key,profile):
    _require(type(key) is bytes and len(key)==32)
    aad=_context(tenant,worker,revision,key_id)
    plaintext=_canonical(_profile(profile))
    nonce=secrets.token_bytes(12)
    ciphertext=AESGCM(key).encrypt(nonce,plaintext,aad)
    return {"v":1,"key_id":key_id,"nonce":base64.b64encode(nonce).decode("ascii"),
            "ciphertext":base64.b64encode(ciphertext).decode("ascii")}

def open_profile(*,tenant,worker,revision,key_id,key,envelope):
    _require(type(key) is bytes and len(key)==32)
    aad=_context(tenant,worker,revision,key_id)
    _require(type(envelope) is dict and set(envelope)=={"v","key_id","nonce","ciphertext"}
        and type(envelope["v"]) is int and envelope["v"]==1 and envelope["key_id"]==key_id)
    try:
        _require(type(envelope["nonce"]) is str and len(envelope["nonce"])==16
            and type(envelope["ciphertext"]) is str and 24<=len(envelope["ciphertext"])<=4096)
        nonce=base64.b64decode(envelope["nonce"],validate=True)
        ciphertext=base64.b64decode(envelope["ciphertext"],validate=True)
        _require(len(nonce)==12 and base64.b64encode(nonce).decode("ascii")==envelope["nonce"]
            and base64.b64encode(ciphertext).decode("ascii")==envelope["ciphertext"])
        plaintext=AESGCM(key).decrypt(nonce,ciphertext,aad)
        return _profile(json.loads(plaintext.decode("ascii")))
    except (InvalidTag,ValueError,UnicodeError,TypeError,binascii.Error,RecursionError):
        raise ProfileBlocked("HR_PROFILE_INVALID") from None


def rotate_profile(*,tenant,worker,old_revision,new_revision,old_key_id,new_key_id,old_key,new_key,envelope):
    """Re-encrypt a verified envelope; caller must use transactional CAS.

    Never retire a key until inventory, recovery and backup checks succeed.
    This helper does not change any DB or key store.
    """
    _require(old_revision!=new_revision and old_key_id!=new_key_id
        and type(old_key) is bytes and type(new_key) is bytes
        and len(old_key)==len(new_key)==32 and old_key!=new_key)
    old=dict(tenant=tenant,worker=worker,revision=old_revision,key_id=old_key_id,key=old_key)
    new=dict(tenant=tenant,worker=worker,revision=new_revision,key_id=new_key_id,key=new_key)
    profile=open_profile(**old,envelope=envelope)
    rotated=seal_profile(**new,profile=profile)
    _require(open_profile(**new,envelope=rotated)==profile)
    return rotated

def retention_decision(*,tenant,worker,revision,as_of,purpose_closed,legal_review_complete,
                       legal_hold,retain_until,approval_sha256):
    """Decision-only policy, never a deletion authorization.

    All timestamps are timezone-aware UTC datetimes from the trusted custodian.
    A missing assessment fails closed. No default legal retention period.
    """
    from datetime import datetime,timedelta
    _require(all(type(x) is str and ID.fullmatch(x) for x in (tenant,worker,revision)))
    _require(all(type(x) is bool for x in (purpose_closed,legal_review_complete,legal_hold)))
    _require(type(as_of) is datetime and as_of.utcoffset()==timedelta(0))
    _require(retain_until is None or (type(retain_until) is datetime and retain_until.utcoffset()==timedelta(0)))
    _require(approval_sha256 is None or (type(approval_sha256) is str and re.fullmatch(r"[0-9a-f]{64}",approval_sha256)))
    if not purpose_closed:status="ACTIVE_PURPOSE"
    elif not legal_review_complete or approval_sha256 is None:status="REVIEW_REQUIRED"
    elif legal_hold:status="LEGAL_HOLD_SEPARATE_STORAGE_REQUIRED"
    elif retain_until is not None and as_of<retain_until:status="RETAIN_SEPARATELY"
    else:status="PURGE_CANDIDATE_ONLY"
    return {"status":status,"tenant":tenant,"worker":worker,"revision":revision,
        "requires_separate_storage":status in ("LEGAL_HOLD_SEPARATE_STORAGE_REQUIRED","RETAIN_SEPARATELY"),
        "normal_use_allowed":status=="ACTIVE_PURPOSE","deletion_authorized":False,
        "production_authorized":False}


def retirement_inventory_digest(*,tenant,old_key_id,new_key_id,expected_assets):
    """Canonical digest of a trusted snapshot's exact scoped asset IDs."""
    import hashlib
    _require(all(type(x) is str and ID.fullmatch(x) for x in (tenant,old_key_id,new_key_id)) and old_key_id!=new_key_id)
    _require(type(expected_assets) in (list,tuple) and 1<=len(expected_assets)<=10000
             and all(type(x) is str and ID.fullmatch(x) for x in expected_assets)
             and len(set(expected_assets))==len(expected_assets))
    return hashlib.sha256(_canonical(["NARUV_KEY_INVENTORY_V1",tenant,old_key_id,new_key_id,sorted(expected_assets)])).hexdigest()


def key_retirement_review(*,tenant,old_key_id,new_key_id,inventory_sha256,
                          expected_assets,observations):
    """Offline evidence completeness screen, never a key retirement action.

    Expected assets and observations must originate from independent trusted
    inventory/recovery systems. Hashes bind supplied evidence, not its truth.
    Retained immutable old-key archives must block retirement.
    """
    import hashlib
    _require(all(type(x) is str and ID.fullmatch(x) for x in (tenant,old_key_id,new_key_id))
             and old_key_id!=new_key_id)
    def digest(x):return type(x) is str and re.fullmatch(r"[0-9a-f]{64}",x) is not None
    _require(digest(inventory_sha256))
    _require(type(expected_assets) in (list,tuple) and 1<=len(expected_assets)<=10000
             and all(type(x) is str and ID.fullmatch(x) for x in expected_assets)
             and len(set(expected_assets))==len(expected_assets))
    _require(secrets.compare_digest(inventory_sha256,retirement_inventory_digest(
        tenant=tenant,old_key_id=old_key_id,new_key_id=new_key_id,expected_assets=expected_assets)))
    _require(type(observations) in (list,tuple) and len(observations)<=10000)
    expected_set=set(expected_assets)
    seen=set();blocked=[];normalized=[]
    for row in observations:
        _require(type(row) is dict and set(row)=={"asset","tenant","key_id","restore_sha256","old_key_denied"})
        asset=row["asset"]
        _require(type(asset) is str and asset in expected_set and asset not in seen
                 and row["tenant"]==tenant and type(row["key_id"]) is str
                 and ID.fullmatch(row["key_id"]) and digest(row["restore_sha256"])
                 and type(row["old_key_denied"]) is bool)
        seen.add(asset);normalized.append(dict(row))
        if row["key_id"]!=new_key_id or not row["old_key_denied"]:blocked.append(asset)
    missing=sorted(expected_set-seen)
    normalized.sort(key=lambda x:x["asset"])
    proof=hashlib.sha256(_canonical(["NARUV_KEY_RETIREMENT_REVIEW_V1",tenant,old_key_id,new_key_id,
        inventory_sha256,sorted(expected_assets),normalized])).hexdigest()
    return {"status":"BLOCKED" if missing or blocked else "EVIDENCE_REVIEW_ONLY",
            "missing_assets":missing,"blocked_assets":sorted(blocked),"review_sha256":proof,
            "key_retirement_authorized":False,"production_authorized":False}


def verify_retirement_attestations(*,review,inventory_sha256,inventory_public_key,recovery_public_key,
                                   inventory_signature,recovery_signature,challenge,issued_at,as_of):
    """Offline two-signer authenticity screen. Trusted keys and fresh challenge
    must be supplied by the server/custodian, never by a client. No key action.
    """
    from datetime import datetime,timedelta
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    _require(type(review) is dict and review.get("status")=="EVIDENCE_REVIEW_ONLY"
             and review.get("key_retirement_authorized") is False and review.get("production_authorized") is False
             and review.get("missing_assets")==[] and review.get("blocked_assets")==[])
    _require(all(type(x) is str and re.fullmatch(r"[0-9a-f]{64}",x) for x in
                 (inventory_sha256,review.get("review_sha256"),challenge)))
    _require(type(issued_at) is datetime and type(as_of) is datetime
             and issued_at.utcoffset()==timedelta(0) and as_of.utcoffset()==timedelta(0)
             and timedelta(0)<=as_of-issued_at<=timedelta(minutes=10))
    _require(type(inventory_public_key) is bytes and type(recovery_public_key) is bytes
             and len(inventory_public_key)==len(recovery_public_key)==32
             and inventory_public_key!=recovery_public_key)
    _require(type(inventory_signature) is bytes and type(recovery_signature) is bytes
             and len(inventory_signature)==len(recovery_signature)==64)
    msg=_canonical(["NARUV_RETIREMENT_ATTESTATION_V1",inventory_sha256,review["review_sha256"],challenge,issued_at.isoformat()])
    try:
        Ed25519PublicKey.from_public_bytes(inventory_public_key).verify(inventory_signature,b"inventory:"+msg)
        Ed25519PublicKey.from_public_bytes(recovery_public_key).verify(recovery_signature,b"recovery:"+msg)
    except (InvalidSignature,ValueError):raise ProfileBlocked("HR_PROFILE_INVALID") from None
    return {"status":"SIGNED_EVIDENCE_REVIEW_ONLY","key_retirement_authorized":False,"production_authorized":False}


def consume_retirement_attestation_ci(cur,**args):
    """Disposable QA ledger only; caller owns transaction and trusted scope.
    A valid dual signature is necessary, never sufficient for actual retirement.
    """
    import os
    _require(os.getenv("GITHUB_ACTIONS")=="true"
             and os.getenv("JW_PG_CI_ALLOW")=="ONLY_EPHEMERAL_LOCAL_DATABASE"
             and os.getenv("NARUV_ERP_RESTORE_ALLOW")=="TWO_DISPOSABLE_SERVICES_ONLY")
    cur.execute("SELECT current_database(),current_setting('server_version_num')::int/10000,session_user")
    _require(cur.fetchone()==("naruv_profile_quarantine_ci",17,"postgres"))
    verify_retirement_attestations(**args)
    cur.execute("""UPDATE naruv_retirement_ci.challenge
        SET consumed_at=%s
        WHERE challenge=%s AND inventory_sha256=%s AND review_sha256=%s
          AND issued_at=%s AND consumed_at IS NULL
          AND issued_at<=clock_timestamp()
          AND issued_at>=clock_timestamp()-interval '10 minutes'""",
        (args["as_of"],args["challenge"],args["inventory_sha256"],args["review"]["review_sha256"],args["issued_at"]))
    _require(cur.rowcount==1)
    return {"status":"SINGLE_USE_EVIDENCE_REVIEW_ONLY","key_retirement_authorized":False,"production_authorized":False}
