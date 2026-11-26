"""Future B2 upload policy review, no network, credentials, or data writes.
Historical one-shot upload scripts remain unmodified and are NOT reusable for
new batches. These helpers define the pre/post upload gate for a future
separately authorized uploader, not an executable uploader.
"""
import re
from .naruv_b2_retention_journal import need,plan_upload_retention,verify_upload_retention

def upload_policy_plan(*,planned_at_ms,max_upload_ms,max_clock_skew_ms,approved_until_ms):
    """Fail if the bounded extra retention exceeds the explicit approval ceiling."""
    until=plan_upload_retention(planned_at_ms,max_upload_ms,max_clock_skew_ms)
    need(type(approved_until_ms) is int and until<=approved_until_ms,"UPLOAD_RETENTION_APPROVAL")
    return {"planned_at_ms":planned_at_ms,"max_upload_ms":max_upload_ms,
        "max_clock_skew_ms":max_clock_skew_ms,"retain_until_ms":until,
        "approved_until_ms":approved_until_ms,"mode":"compliance",
        "upload_authorized":False}

def verify_uploaded_metadata(*,plan,expected,info,now_ms):
    """Confirm exact identity and retention using provider upload timestamp.
    Does not verify ciphertext or authorize cleanup, retry, or key retirement.
    """
    need(type(plan) is dict and set(plan)=={"planned_at_ms","max_upload_ms","max_clock_skew_ms","retain_until_ms","approved_until_ms","mode","upload_authorized"},"UPLOAD_PLAN")
    p=upload_policy_plan(**{k:plan[k] for k in ("planned_at_ms","max_upload_ms","max_clock_skew_ms","approved_until_ms")})
    need(p==plan and plan["upload_authorized"] is False,"UPLOAD_PLAN_CHANGED")
    keys={"bucketId","fileName","fileId","contentLength","contentSha1"}
    need(type(expected) is dict and set(expected)==keys and type(info) is dict,"UPLOAD_EXPECTED")
    need(all(type(expected[k]) is str and 0<len(expected[k])<=1024 for k in ("bucketId","fileName","fileId"))
        and type(expected["contentLength"]) is int and 0<expected["contentLength"]<=32*1024*1024
        and type(expected["contentSha1"]) is str and re.fullmatch("[0-9a-f]{40}",expected["contentSha1"]),"UPLOAD_EXPECTED")
    need(all(type(info.get(k)) is type(expected[k]) and info[k]==expected[k] for k in keys)
        and info.get("action")=="upload","UPLOAD_IDENTITY")
    need(info.get("serverSideEncryption")=={"mode":"SSE-B2","algorithm":"AES256"},"UPLOAD_ENCRYPTION")
    lock=info.get("fileRetention");until=plan["retain_until_ms"]
    need(type(lock) is dict and lock.get("isClientAuthorizedToRead") is True
        and lock.get("value")=={"mode":"compliance","retainUntilTimestamp":until},"UPLOAD_RETENTION_METADATA")
    ts=info.get("uploadTimestamp")
    verify_upload_retention(ts,until,now_ms)
    need(ts>=plan["planned_at_ms"]-plan["max_clock_skew_ms"],"UPLOAD_TIMESTAMP_DRIFT")
    return {"status":"B2_UPLOAD_METADATA_MATCH_ONLY","retention_at_least_30days":True,
        "file_id_match":True,"ciphertext_verified":False,"retry_authorized":False,
        "deletion_authorized":False,"production_authorized":False}
