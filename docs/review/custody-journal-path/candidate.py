"""Owner-local readiness controls. No network access, no key activation, no
automatic approval. Challenge journal is local only, not a distributed ledger.
The caller must independently authenticate the owner and both trust roots.
"""
import hashlib,json,os,re,stat
from .naruv_b2_native_upload import authenticate_new_archive,scope_digest,_scope
from .naruv_b2_upload_policy import upload_policy_plan
from .naruv_b2_retention_journal import need
from .naruv_recovery_custody_review import review_custody_evidence,canonical,sha,digest

def prepare_upload_scope(*,account_id,bucket_id,bucket_name,operation_id,raw,archive_key,
        planned_at_ms,approval_expires_ms,approved_until_ms,max_upload_ms,max_clock_skew_ms):
    """Prepare an unsigned proposal; it must be separately approved outside this function."""
    need(type(operation_id) is str and re.fullmatch("[a-f0-9]{32}",operation_id)
        and type(bucket_name) is str and 1<=len(bucket_name)<=128,"READINESS_SCOPE")
    auth=authenticate_new_archive(raw,archive_key)
    need(type(planned_at_ms) is int and type(approval_expires_ms) is int and type(max_upload_ms) is int
        and planned_at_ms+max_upload_ms<approval_expires_ms<=planned_at_ms+5*3600000,"READINESS_EXPIRY")
    plan=upload_policy_plan(planned_at_ms=planned_at_ms,max_upload_ms=max_upload_ms,
        max_clock_skew_ms=max_clock_skew_ms,approved_until_ms=approved_until_ms)
    scope=dict(account_id=account_id,bucket_id=bucket_id,bucket_name_sha256=sha(bucket_name.encode()),
        name="naruv-one/new-backup/"+operation_id+"/"+auth["ciphertext_sha256"]+".jwpgbk",
        sha256=auth["ciphertext_sha256"],size=len(raw),approval_expires_ms=approval_expires_ms,
        approved_until_ms=approved_until_ms,max_upload_ms=max_upload_ms,max_clock_skew_ms=max_clock_skew_ms)
    pin=scope_digest(scope)
    _scope(scope,pin,raw,check_expiry=False)
    return {"status":"UNSIGNED_UPLOAD_SCOPE_PROPOSAL","scope":scope,"scope_sha256":pin,
        "planned_retention":plan,"authenticated_chunks":auth["authenticated_chunks"],
        "upload_authorized":False,"remote_read":False,"remote_write":False,"restore_verified":False}

def custody_trust_pin(*,tenant,expected_keys,trust):
    return sha(canonical(["NARUV_CUSTODY_TRUST_PIN_V1",tenant,expected_keys,trust]))

def review_and_consume_local_challenge(*,journal_dir,expected_trust_pin,expected_challenge,**evidence):
    """Validate a signed assertion and consume the independently issued challenge
    once, in an owner-private directory. A crash after creation blocks replay.
    Does not establish physical custody, independence, or distributed uniqueness.
    """
    need(digest(expected_trust_pin) and digest(expected_challenge)
        and evidence.get("challenge")==expected_challenge,"CUSTODY_LOCAL_CHALLENGE")
    pin=custody_trust_pin(tenant=evidence["tenant"],expected_keys=evidence["expected_keys"],trust=evidence["trust"])
    need(pin==expected_trust_pin,"CUSTODY_LOCAL_TRUST_PIN")
    result=review_custody_evidence(**evidence)
    from .naruv_hr_profile_envelope import _open_trusted_key_directory,ProfileBlocked
    try:d=_open_trusted_key_directory(journal_dir)
    except ProfileBlocked:raise ValueError("CUSTODY_LOCAL_DIRECTORY") from None
    try:
        st=os.fstat(d)
        need(st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o700,"CUSTODY_LOCAL_DIRECTORY")
        # Keyed solely by challenge, so changes to tenant or trust cannot reuse it.
        name=expected_challenge+".json"
        try:fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=d)
        except FileExistsError:raise ValueError("CUSTODY_LOCAL_REPLAY") from None
        with os.fdopen(fd,"wb") as f:
            record=dict(schema="NARUV_LOCAL_CUSTODY_CONSUMPTION_V1",challenge=expected_challenge,
                trust_pin=pin,evidence_sha256=result["evidence_sha256"],production_authorized=False)
            f.write(canonical(record)+b"\n");f.flush();os.fsync(f.fileno())
        os.fsync(d)
    finally:os.close(d)
    return dict(result,local_challenge_consumed=True,
        distributed_challenge_consumption_verified=False)
