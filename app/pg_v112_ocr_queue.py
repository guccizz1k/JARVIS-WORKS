"""V11.2 opt-in durable PostgreSQL OCR work queue; no web routes or payouts.

No file bytes, passwords, user documents or raw OCR outputs in the queue.
An authorized client supplies an existing *tenant-scoped object key* and the
SHA-256. A unique idempotency key prevents duplicate admission. SKIP LOCKED,
leases, fencing tokens and finite retries protect concurrency/crash recovery.
This is a reviewed candidate, NOT an applied persistent database migration.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from typing import Any, Callable

HEX64 = re.compile(r'^[a-f0-9]{64}$')
KEY = re.compile(r'^[a-zA-Z0-9_-]{8,96}$')
IDENT = re.compile(r'^[a-zA-Z0-9_-]{1,128}$')


@dataclass(frozen=True)
class Claim:
    id: str
    org_id: str
    object_key: str
    sha256: str
    filename: str
    attempts: int
    lease_token: str


def _metadata(org_id: str, object_key: str, filename: str, digest: str,
              request_id: str) -> None:
    if not (isinstance(org_id, str) and IDENT.fullmatch(org_id)):
        raise ValueError('Invalid tenant id')
    if not (isinstance(object_key, str) and
            re.fullmatch(r'tenant/[A-Za-z0-9_-]{1,128}/[a-f0-9]{32}', object_key)
            and object_key.split('/')[1] == org_id):
        raise ValueError('Object key must belong to tenant and be server-generated')
    if not (isinstance(filename, str) and 1 <= len(filename) <= 150
            and all(ord(c) >= 32 and ord(c) != 127 for c in filename)):
        raise ValueError('Invalid filename')
    if not (isinstance(digest, str) and HEX64.fullmatch(digest)):
        raise ValueError('Invalid content hash')
    if not (isinstance(request_id, str) and KEY.fullmatch(request_id)):
        raise ValueError('Invalid idempotency key')


class PgOcrQueue:
    def __init__(self, connect: Callable[[], Any]):
        self._connect = connect

    def submit(self, *, org_id: str, object_key: str, filename: str,
               sha256: str, request_id: str, actor_id: str) -> tuple[str,bool]:
        _metadata(org_id, object_key, filename, sha256, request_id)
        if not isinstance(actor_id, str) or not IDENT.fullmatch(actor_id):
            raise ValueError('Invalid actor')
        task_id = secrets.token_hex(16)
        with self._connect() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute('''INSERT INTO jw_dev.ocr_jobs_v112
                       (id, org_id, actor_id, object_key, filename, file_sha256,
                        request_id, state, available_at)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,'queued',clock_timestamp())
                       ON CONFLICT (org_id,request_id) DO NOTHING RETURNING id''',
                       (task_id,org_id,actor_id,object_key,filename,sha256,request_id))
                    inserted=cur.fetchone()
                    if inserted:
                        return str(inserted[0]),True
                    cur.execute('''SELECT id,object_key,file_sha256,filename,actor_id
                       FROM jw_dev.ocr_jobs_v112 WHERE org_id=%s AND request_id=%s''',
                       (org_id,request_id))
                    previous=cur.fetchone()
                    if not previous or previous[1:] != (object_key,sha256,filename,actor_id):
                        raise ValueError('Idempotency key reused with different file')
                    return str(previous[0]),False

    def claim(self) -> Claim | None:
        token=secrets.token_hex(32)
        with self._connect() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute('''WITH next AS (
                       SELECT id FROM jw_dev.ocr_jobs_v112
                       WHERE ((state='queued' AND available_at<=clock_timestamp())
                         OR (state='running' AND lease_until<clock_timestamp()))
                         AND attempts < max_attempts
                       ORDER BY available_at,id FOR UPDATE SKIP LOCKED LIMIT 1
                     ) UPDATE jw_dev.ocr_jobs_v112 AS j
                       SET state='running',attempts=j.attempts+1,
                           lease_token=%s,lease_until=clock_timestamp()+interval '60 seconds'
                       FROM next WHERE j.id=next.id
                       RETURNING j.id,j.org_id,j.object_key,j.file_sha256,
                                 j.filename,j.attempts,j.lease_token''',(token,))
                    row=cur.fetchone()
                    if row is None:
                        return None
                    if (len(row)!=7 or row[-1]!=token):
                        raise RuntimeError('Invalid atomic work claim')
                    return Claim(*row)

    def expire_exhausted_leases(self) -> int:
        """Poison expired claims after max retries; never leave them RUNNING."""
        with self._connect() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute("""UPDATE jw_dev.ocr_jobs_v112
                       SET state='failed',lease_token=NULL,lease_until=NULL,
                           last_error_code='PROCESSOR_FAILED'
                       WHERE state='running' AND lease_until<clock_timestamp()
                         AND attempts>=max_attempts
                       RETURNING id""", ())
                    return len(cur.fetchall())

    def complete(self, claim: Claim, *, result_key: str) -> bool:
        if not isinstance(claim, Claim):
            raise ValueError('Invalid claim')
        if not (isinstance(result_key,str) and
                result_key==f'tenant/{claim.org_id}/ocr-result/{claim.id}'):
            raise ValueError('Result key must be tenant-bound and stable')
        with self._connect() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute('''UPDATE jw_dev.ocr_jobs_v112
                       SET state='needs_review',result_key=%s,lease_token=NULL,
                           lease_until=NULL,completed_at=clock_timestamp()
                       WHERE id=%s AND org_id=%s AND state='running'
                         AND lease_token=%s AND lease_until>clock_timestamp()
                       RETURNING id''',(result_key,claim.id,claim.org_id,claim.lease_token))
                    return cur.fetchone() is not None

    def fail(self, claim: Claim, *, error_code: str) -> bool:
        if not isinstance(claim,Claim) or error_code not in {
                'SCAN_REJECTED','MALFORMED_DOCUMENT','OCR_TIMEOUT',
                'OBJECT_NOT_FOUND','HASH_MISMATCH','PROCESSOR_FAILED'}:
            raise ValueError('Invalid failure record')
        with self._connect() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute('''UPDATE jw_dev.ocr_jobs_v112
                       SET state=CASE WHEN attempts>=max_attempts THEN 'failed' ELSE 'queued' END,
                           available_at=clock_timestamp()+
                             make_interval(secs=>LEAST(300,10*(2^LEAST(attempts,5))::int)),
                           lease_token=NULL,lease_until=NULL,last_error_code=%s
                       WHERE id=%s AND org_id=%s AND state='running'
                         AND lease_token=%s AND lease_until>clock_timestamp()
                       RETURNING id''',(error_code,claim.id,claim.org_id,claim.lease_token))
                    return cur.fetchone() is not None


def process_one(queue: PgOcrQueue, store: Any,
                parser: Callable[[str,bytes],dict]) -> str:
    """A worker-stage adapter. No autoapproval, invoice or payment side effects."""
    job=queue.claim()
    if job is None:
        return 'IDLE'
    code='PROCESSOR_FAILED'
    try:
        raw=store.read(job.org_id,job.object_key)
        if not isinstance(raw,bytes) or not 0<len(raw)<=5*1024*1024:
            code='MALFORMED_DOCUMENT'
            raise ValueError('Invalid private object size')
        if hashlib.sha256(raw).hexdigest()!=job.sha256:
            code='HASH_MISMATCH'
            raise ValueError('Private object hash mismatch')
        # parser should be the existing sandboxed/scanned protected_parse.
        document=parser(job.filename,raw)
        if type(document) is not dict:
            code='MALFORMED_DOCUMENT'
            raise ValueError('Invalid OCR proposal')
        result_key=f'tenant/{job.org_id}/ocr-result/{job.id}'
        store.write_proposal(job.org_id,result_key,document)
        return 'NEEDS_REVIEW' if queue.complete(job,result_key=result_key) else 'LEASE_LOST'
    except Exception:
        # No OCR/user data or raw exception text in failure records.
        return 'RETRY_OR_FAILED' if queue.fail(job,error_code=code) else 'LEASE_LOST'

