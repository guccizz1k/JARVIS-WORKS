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
    elif legal_hold:status="LEGAL_HOLD_SEPARATE_STORAGE_REQUIRED"
    elif not legal_review_complete or approval_sha256 is None or retain_until is None:status="REVIEW_REQUIRED"
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
        SET consumed_at=clock_timestamp()
        WHERE challenge=%s AND inventory_sha256=%s AND review_sha256=%s
          AND issued_at=%s AND consumed_at IS NULL
          AND issued_at<=clock_timestamp()
          AND issued_at>=clock_timestamp()-interval '10 minutes'""",
        (args["challenge"],args["inventory_sha256"],args["review"]["review_sha256"],args["issued_at"]))
    _require(cur.rowcount==1)
    return {"status":"SINGLE_USE_EVIDENCE_REVIEW_ONLY","key_retirement_authorized":False,"production_authorized":False}


def archive_lifecycle_review(*,tenant,as_of,expected_assets,inventory_sha256,records):
    """Offline review of a trusted archive inventory, not deletion or release.
    All existing copies must be included. A legal hold, unknown retention,
    or old-key dependency must remain visible even after a new copy exists.
    """
    from datetime import datetime,timedelta
    import hashlib
    _require(type(tenant) is str and ID.fullmatch(tenant) and type(as_of) is datetime
             and as_of.utcoffset()==timedelta(0))
    _require(type(expected_assets) in (list,tuple) and 1<=len(expected_assets)<=10000
             and all(type(x) is str and ID.fullmatch(x) for x in expected_assets)
             and len(set(expected_assets))==len(expected_assets))
    _require(type(records) in (list,tuple) and len(records)<=10000)
    expected=set(expected_assets);seen=set();normalized=[];holds=[];retained=[];old_keys=[];unknown=[]
    for row in records:
        _require(type(row) is dict and set(row)=={"asset","tenant","archive_sha256","retain_until","legal_hold","old_key_required"})
        asset=row["asset"];until=row["retain_until"]
        _require(type(asset) is str and asset in expected and asset not in seen and row["tenant"]==tenant
            and type(row["archive_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}",row["archive_sha256"])
            and type(row["legal_hold"]) is bool and type(row["old_key_required"]) is bool
            and (until is None or (type(until) is datetime and until.utcoffset()==timedelta(0))))
        seen.add(asset)
        normalized.append([asset,row["archive_sha256"],None if until is None else until.isoformat(),row["legal_hold"],row["old_key_required"]])
        if row["legal_hold"]:holds.append(asset)
        if until is None:unknown.append(asset)
        elif as_of<until:retained.append(asset)
        if row["old_key_required"]:old_keys.append(asset)
    digest=hashlib.sha256(_canonical(["NARUV_ARCHIVE_LIFECYCLE_V1",tenant,sorted(expected),sorted(normalized)])).hexdigest()
    _require(type(inventory_sha256) is str and secrets.compare_digest(digest,inventory_sha256))
    missing=sorted(expected-seen)
    return {"status":"BLOCKED" if missing or holds or retained or unknown or old_keys else "EVIDENCE_REVIEW_ONLY",
        "missing_assets":missing,"legal_hold_assets":sorted(holds),"retained_assets":sorted(retained),
        "unknown_retention_assets":sorted(unknown),"old_key_assets":sorted(old_keys),
        "review_sha256":hashlib.sha256(_canonical(["NARUV_ARCHIVE_LIFECYCLE_REVIEW_V1",digest,as_of.isoformat()])).hexdigest(),
        "deletion_authorized":False,"key_retirement_authorized":False,"production_authorized":False}


def verify_combined_retirement_evidence(*,tenant,old_key_id,new_key_id,expected_assets,
        inventory_sha256,observations,expected_archive_assets,archive_inventory_sha256,
        archive_records,inventory_public_key,recovery_public_key,trust_fingerprints,
        inventory_signature,recovery_signature,challenge,issued_at,as_of):
    """Recompute both reviews from server-owned inventories, bind pinned signers
    to the same scope and challenge. No client-provided precomputed review.
    Caller must obtain inventory and trust fingerprints independently, and
    consume the challenge atomically. No KMS operation or retirement authority.
    """
    import hashlib
    from datetime import datetime,timedelta
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    review=key_retirement_review(tenant=tenant,old_key_id=old_key_id,new_key_id=new_key_id,
        inventory_sha256=inventory_sha256,expected_assets=expected_assets,observations=observations)
    _require(review["status"]=="EVIDENCE_REVIEW_ONLY")
    _require(type(expected_archive_assets) in (list,tuple) and all(type(a) is str for a in expected_archive_assets)
        and set(expected_archive_assets)<=set(expected_assets))
    _require(type(issued_at) is datetime and type(as_of) is datetime
        and issued_at.utcoffset()==timedelta(0) and as_of.utcoffset()==timedelta(0)
        and timedelta(0)<=as_of-issued_at<=timedelta(minutes=10))
    lifecycle=archive_lifecycle_review(tenant=tenant,as_of=issued_at,expected_assets=expected_archive_assets,
        inventory_sha256=archive_inventory_sha256,records=archive_records)
    _require(lifecycle["status"]=="EVIDENCE_REVIEW_ONLY")
    _require(type(challenge) is str and re.fullmatch(r"[0-9a-f]{64}",challenge))
    _require(type(trust_fingerprints) is dict and set(trust_fingerprints)=={"inventory","recovery"})
    _require(type(inventory_public_key) is bytes and type(recovery_public_key) is bytes
        and len(inventory_public_key)==len(recovery_public_key)==32 and inventory_public_key!=recovery_public_key)
    _require(all(type(trust_fingerprints[k]) is str and re.fullmatch(r"[0-9a-f]{64}",trust_fingerprints[k])
        and secrets.compare_digest(trust_fingerprints[k],hashlib.sha256(key).hexdigest())
        for k,key in (("inventory",inventory_public_key),("recovery",recovery_public_key))))
    _require(type(inventory_signature) is bytes and type(recovery_signature) is bytes
        and len(inventory_signature)==len(recovery_signature)==64)
    msg=_canonical(["NARUV_COMBINED_RETIREMENT_V2",tenant,old_key_id,new_key_id,inventory_sha256,
        review["review_sha256"],archive_inventory_sha256,lifecycle["review_sha256"],trust_fingerprints,challenge,issued_at.isoformat()])
    try:
        Ed25519PublicKey.from_public_bytes(inventory_public_key).verify(inventory_signature,b"inventory:"+msg)
        Ed25519PublicKey.from_public_bytes(recovery_public_key).verify(recovery_signature,b"recovery:"+msg)
    except (InvalidSignature,ValueError):raise ProfileBlocked("HR_PROFILE_INVALID") from None
    return {"status":"COMBINED_SIGNED_EVIDENCE_REVIEW_ONLY","combined_sha256":hashlib.sha256(msg).hexdigest(),
        "requires_atomic_challenge_consumption":True,"key_retirement_authorized":False,
        "deletion_authorized":False,"production_authorized":False}


def consume_combined_retirement_ci(cur,**args):
    """Atomic V2 consumption in the isolated CI database only.
    The ledger row pins the independently provisioned combined proof and
    signer fingerprints; database time decides freshness, not caller time.
    """
    import os
    _require(os.getenv("GITHUB_ACTIONS")=="true"
        and os.getenv("JW_PG_CI_ALLOW")=="ONLY_EPHEMERAL_LOCAL_DATABASE"
        and os.getenv("NARUV_ERP_RESTORE_ALLOW")=="TWO_DISPOSABLE_SERVICES_ONLY")
    cur.execute("SELECT current_database(),current_setting('server_version_num')::int/10000,session_user,clock_timestamp()")
    db,version,user,now=cur.fetchone()
    _require((db,version,user)==("naruv_profile_quarantine_ci",17,"postgres"))
    # psycopg timezone may be non-UTC; normalize before verifying.
    from datetime import timezone
    proof=verify_combined_retirement_evidence(**dict(args,as_of=now.astimezone(timezone.utc)))
    cur.execute("""UPDATE naruv_retirement_ci.combined_challenge SET consumed_at=clock_timestamp()
        WHERE challenge=%s AND combined_sha256=%s AND tenant=%s AND old_key_id=%s AND new_key_id=%s
          AND inventory_fingerprint=%s AND recovery_fingerprint=%s AND issued_at=%s
          AND consumed_at IS NULL AND issued_at<=clock_timestamp()
          AND issued_at>=clock_timestamp()-interval '10 minutes'""",
        (args["challenge"],proof["combined_sha256"],args["tenant"],args["old_key_id"],args["new_key_id"],
         args["trust_fingerprints"]["inventory"],args["trust_fingerprints"]["recovery"],args["issued_at"]))
    _require(cur.rowcount==1)
    return {"status":"COMBINED_SINGLE_USE_CI_REVIEW_ONLY","combined_sha256":proof["combined_sha256"],
        "key_retirement_authorized":False,"production_authorized":False}


class MountedProfileKeyStore:
    """Read-only adapter for an externally provisioned POSIX secret directory.
    Deployment must own the directory and its ancestors; no key generation,
    deletion, remote KMS claim, or exposure to client-provided key IDs.
    Each tenant/key ID is explicitly enrolled in a trusted server manifest.
    """
    def __init__(self,directory,manifest):
        import os
        _require(type(directory) is str and os.path.isabs(directory) and type(manifest) is dict and 1<=len(manifest)<=1000)
        self._directory=directory
        self._manifest={}
        for tenant,entries in manifest.items():
            _require(type(tenant) is str and ID.fullmatch(tenant) and type(entries) is dict and 1<=len(entries)<=64)
            copied={}
            for key_id,entry in entries.items():
                _require(type(key_id) is str and ID.fullmatch(key_id) and type(entry) is dict
                    and set(entry)=={"file","state"} and type(entry["file"]) is str
                    and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\.key",entry["file"])
                    and entry["state"] in ("ACTIVE","RECOVERY_ONLY","DISABLED"))
                copied[key_id]=dict(entry)
            _require(sum(x["state"]=="ACTIVE" for x in copied.values())==1)
            self._manifest[tenant]=copied
        files=[e["file"] for entries in self._manifest.values() for e in entries.values()]
        _require(len(files)==len(set(files)))

    def _read(self,tenant,key_id,*,for_write):
        import os,stat
        _require(type(tenant) is str and type(key_id) is str and type(for_write) is bool)
        entry=self._manifest.get(tenant,{}).get(key_id)
        _require(entry is not None and entry["state"] in (("ACTIVE",) if for_write else ("ACTIVE","RECOVERY_ONLY")))
        _require(all(hasattr(os,k) for k in ("O_NOFOLLOW","O_DIRECTORY","O_NONBLOCK","O_CLOEXEC","geteuid")))
        directory_fd=None;fd=None
        try:
            directory_fd=os.open(self._directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            ds=os.fstat(directory_fd)
            _require(stat.S_ISDIR(ds.st_mode) and ds.st_uid==os.geteuid() and stat.S_IMODE(ds.st_mode)==0o700)
            fd=os.open(entry["file"],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory_fd)
            st=os.fstat(fd)
            _require(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and st.st_nlink==1
                and stat.S_IMODE(st.st_mode) in (0o400,0o600) and st.st_size==32)
            raw=bytearray()
            while len(raw)<33:
                chunk=os.read(fd,33-len(raw))
                if not chunk:break
                raw.extend(chunk)
            end=os.fstat(fd)
            _require(len(raw)==32 and (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns,st.st_mode,st.st_nlink)
                ==(end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns,end.st_ctime_ns,end.st_mode,end.st_nlink))
            return bytes(raw)
        except OSError:raise ProfileBlocked("HR_PROFILE_INVALID") from None
        finally:
            if fd is not None:os.close(fd)
            if directory_fd is not None:os.close(directory_fd)

    def seal(self,*,tenant,worker,revision,profile):
        _require(type(tenant) is str and tenant in self._manifest)
        key_id=next(k for k,e in self._manifest[tenant].items() if e["state"]=="ACTIVE")
        return seal_profile(tenant=tenant,worker=worker,revision=revision,key_id=key_id,
            key=self._read(tenant,key_id,for_write=True),profile=profile)

    def recover(self,*,tenant,worker,revision,envelope):
        _require(type(envelope) is dict and type(envelope.get("key_id")) is str)
        key_id=envelope["key_id"]
        return open_profile(tenant=tenant,worker=worker,revision=revision,key_id=key_id,
            key=self._read(tenant,key_id,for_write=False),envelope=envelope)

    def rotate(self,*,tenant,worker,old_revision,new_revision,envelope):
        _require(type(tenant) is str and tenant in self._manifest and type(envelope) is dict
            and type(envelope.get("key_id")) is str)
        old=envelope["key_id"]
        new=next(k for k,e in self._manifest[tenant].items() if e["state"]=="ACTIVE")
        return rotate_profile(tenant=tenant,worker=worker,old_revision=old_revision,new_revision=new_revision,
            old_key_id=old,new_key_id=new,old_key=self._read(tenant,old,for_write=False),
            new_key=self._read(tenant,new,for_write=True),envelope=envelope)


def reconcile_backup_provider_inventory(*,tenant,expected_assets,records,inventory_sha256):
    """Compare independently retrieved provider metadata. Never fetch keys,
    delete objects or assert WORM from a Git hash. Missing provider evidence blocks.
    """
    import hashlib
    _require(type(tenant) is str and ID.fullmatch(tenant))
    _require(type(expected_assets) is list and 1<=len(expected_assets)<=10000 and
        all(type(x) is str and ID.fullmatch(x) for x in expected_assets) and len(set(expected_assets))==len(expected_assets))
    _require(type(records) is list and len(records)<=20000)
    seen={};bad=[]
    for r in records:
        _require(type(r) is dict and set(r)=={"asset","tenant","provider","sha256","key_id","retention_verified","restore_verified"})
        _require(type(r["asset"]) is str and r["asset"] in expected_assets and r["tenant"]==tenant
            and type(r["provider"]) is str and r["provider"] in ("GITHUB_PRIVATE","BACKBLAZE_B2")
            and type(r["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}",r["sha256"])
            and type(r["key_id"]) is str and ID.fullmatch(r["key_id"])
            and type(r["retention_verified"]) is bool and type(r["restore_verified"]) is bool)
        k=(r["asset"],r["provider"]);_require(k not in seen);seen[k]=dict(r)
    missing=[]
    for asset in sorted(expected_assets):
        a=seen.get((asset,"GITHUB_PRIVATE"));b=seen.get((asset,"BACKBLAZE_B2"))
        if a is None or b is None:missing.append(asset);continue
        if a["sha256"]!=b["sha256"] or a["key_id"]!=b["key_id"] or not b["retention_verified"] or not a["restore_verified"] or not b["restore_verified"]:
            bad.append(asset)
    digest=hashlib.sha256(_canonical(["NARUV_PROVIDER_INVENTORY_V1",tenant,sorted(expected_assets),[seen[k] for k in sorted(seen)]])).hexdigest()
    _require(type(inventory_sha256) is str and secrets.compare_digest(digest,inventory_sha256))
    return {"status":"BLOCKED" if missing or bad else "INVENTORY_MATCH_ONLY","missing_assets":missing,"mismatch_assets":bad,
        "key_retirement_authorized":False,"deletion_authorized":False,"production_authorized":False}

class IncidentPinnedKeyStore(MountedProfileKeyStore):
    """Read-only custody with an independently supplied manifest of SHA256
    key fingerprints and quarantine list. Incident recovery is explicit,
    never a normal-use bypass. Caller owns authorization and persistence.
    """
    def __init__(self,directory,manifest,fingerprints,quarantined):
        import hashlib
        super().__init__(directory,manifest)
        _require(type(fingerprints) is dict and set(fingerprints)==set(self._manifest))
        self._fingerprints={}
        for tenant,entries in self._manifest.items():
            f=fingerprints[tenant]
            _require(type(f) is dict and set(f)==set(entries) and all(type(v) is str and re.fullmatch(r"[0-9a-f]{64}",v) for v in f.values()))
            self._fingerprints[tenant]=dict(f)
        flat=[v for f in self._fingerprints.values() for v in f.values()]
        _require(len(flat)==len(set(flat)))
        _require(type(quarantined) is list and all(type(x) is tuple and len(x)==2 and all(type(y) is str for y in x)
            and x[0] in self._manifest and x[1] in self._manifest[x[0]] for x in quarantined))
        self._quarantined=frozenset(quarantined)

    def _read(self,tenant,key_id,*,for_write):
        import hashlib
        _require(type(tenant) is str and type(key_id) is str and (tenant,key_id) not in self._quarantined)
        key=super()._read(tenant,key_id,for_write=for_write)
        _require(secrets.compare_digest(hashlib.sha256(key).hexdigest(),self._fingerprints[tenant][key_id]))
        return key

def reconcile_backup_provider_inventory_against_manifest(*,tenant,expected_manifest,expected_manifest_sha256,records,inventory_sha256):
    """Bind provider observations to an independently pinned original manifest.
    Caller must obtain both digests through trusted channels; review only.
    """
    import hashlib
    _require(type(expected_manifest) is dict and 1<=len(expected_manifest)<=10000)
    for asset,entry in expected_manifest.items():
        _require(type(asset) is str and ID.fullmatch(asset) and type(entry) is dict
            and set(entry)=={"sha256","key_id"} and type(entry["sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}",entry["sha256"]) and type(entry["key_id"]) is str and ID.fullmatch(entry["key_id"]))
    assets=sorted(expected_manifest)
    result=reconcile_backup_provider_inventory(tenant=tenant,expected_assets=assets,records=records,inventory_sha256=inventory_sha256)
    digest=hashlib.sha256(_canonical(["NARUV_ORIGINAL_BACKUP_MANIFEST_V1",tenant,expected_manifest])).hexdigest()
    _require(type(expected_manifest_sha256) is str and re.fullmatch(r"[0-9a-f]{64}",expected_manifest_sha256)
        and secrets.compare_digest(digest,expected_manifest_sha256))
    original_mismatch=sorted({r["asset"] for r in records if any(r[k]!=expected_manifest[r["asset"]][k] for k in ("sha256","key_id"))})
    return dict(result,status="BLOCKED" if original_mismatch or result["status"]=="BLOCKED" else "ORIGINAL_AND_PROVIDER_MATCH_ONLY",
        original_mismatch_assets=original_mismatch,original_manifest_sha256=digest)
