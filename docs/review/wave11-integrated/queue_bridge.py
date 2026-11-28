"""Opt-in adapter for the existing PgOcrQueue claim/complete/fail contract.
Use only an isolated, authorized synthetic store until full worker isolation is approved.
No API admission, real customer documents, auto-posting or new queue schema.
"""
import hashlib,re
from pathlib import PurePosixPath
from review_gates import Blocked
from isolated_document import review

FORMATS={'.pdf':'pdf','.png':'png','.jpg':'jpeg','.jpeg':'jpeg'}
MAX_BYTES=2*1024*1024
ACK='SYNTHETIC_REVIEW_ONLY'
def process_review_job(queue,store,*,ack,scan,parser=review):
    if ack!=ACK:raise Blocked('QUEUE_REVIEW_DISABLED')
    job=queue.claim()
    if job is None:return 'IDLE'
    # Claim originates from trusted queue, not HTTP inputs.
    if not (type(job.org_id) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}',job.org_id) and type(job.id) is str and re.fullmatch(r'[0-9a-f]{32}',job.id) and type(job.lease_token) is str and re.fullmatch(r'[0-9a-f]{64}',job.lease_token)):
        raise Blocked('QUEUE_INVALID_CLAIM')
    code='PROCESSOR_FAILED'
    try:
        if type(job.object_key) is not str or not re.fullmatch(r'tenant/'+re.escape(job.org_id)+r'/[0-9a-f]{32}',job.object_key):
            code='MALFORMED_DOCUMENT';raise ValueError('scope')
        if type(job.filename) is not str or len(job.filename)>150 or not job.filename or any(ord(c)<32 or ord(c)==127 for c in job.filename) or '/' in job.filename or '\\' in job.filename:
            code='MALFORMED_DOCUMENT';raise ValueError('filename')
        fmt=FORMATS.get(PurePosixPath(job.filename).suffix.lower())
        if fmt is None:
            code='MALFORMED_DOCUMENT';raise ValueError('format')
        # New store contract: enforce size before reading the object, not only afterwards.
        code='OBJECT_NOT_FOUND';raw=store.read_bounded(job.org_id,job.object_key,MAX_BYTES)
        code='MALFORMED_DOCUMENT'
        if type(raw) is not bytes or not 0<len(raw)<=MAX_BYTES:raise ValueError('size')
        code='HASH_MISMATCH'
        if hashlib.sha256(raw).hexdigest()!=job.sha256:raise ValueError('digest')
        code='SCAN_REJECTED'
        if scan(raw) is not True:raise ValueError('scan')
        code='PROCESSOR_FAILED'
        try:result=parser(raw=raw,registered=job.sha256,tenant=job.org_id,format=fmt,timeout=20)
        except Blocked as e:
            if str(e)=='OCR_WORKER_TIMEOUT':code='OCR_TIMEOUT'
            raise
        if type(result) is not dict or result.get('source_sha256')!=job.sha256 or result.get('status') not in ('ORIGINAL_REVIEW_REQUIRED','MANUAL_CORRECTION_REQUIRED') or result.get('posting_authorized') is not False or result.get('recognition_authorized') is not False or result.get('requires_human_review') is not True:raise ValueError('review')
        # Immutable lease-specific proposal; stale workers cannot overwrite another lease.
        result_key=f'tenant/{job.org_id}/ocr-result/{job.id}/{job.lease_token}'
        store.write_proposal(job.org_id,result_key,result)
        return 'NEEDS_REVIEW' if queue.complete(job,result_key=result_key) else 'LEASE_LOST'
    except Exception:
        return 'RETRY_OR_FAILED' if queue.fail(job,error_code=code) else 'LEASE_LOST'
