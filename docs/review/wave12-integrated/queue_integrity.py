"""Candidate extension: bind exact stored proposal bytes to a fenced DB commit.
Only synthetic queue roles and private fixture store. DB and store are not a distributed transaction.
Uncommitted output remains inaccessible; no deletion or automatic financial posting.
"""
import hashlib,hmac,json,re
from review_gates import need,digest,Blocked
from local_queue_store import filename,read_file

def encode(result):
    need(type(result) is dict and result.get('posting_authorized') is False and result.get('recognition_authorized') is False and result.get('requires_human_review') is True and digest(result.get('source_sha256')) and digest(result.get('review_sha256')) and result.get('status') in ('ORIGINAL_REVIEW_REQUIRED','MANUAL_CORRECTION_REQUIRED'),'QUEUE_RESULT_INVALID')
    try:raw=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
    except (TypeError,ValueError,RecursionError):raise Blocked('QUEUE_RESULT_INVALID') from None
    need(0<len(raw)<=65536,'QUEUE_RESULT_SIZE');return raw

def sha(raw):return hashlib.sha256(raw).hexdigest()

def scope(tenant,job,key):
    need(type(tenant) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}',tenant) and type(job) is str and re.fullmatch(r'[0-9a-f]{32}',job) and type(key) is str and re.fullmatch(r'tenant/'+re.escape(tenant)+r'/ocr-result/'+job+r'/[0-9a-f]{64}',key),'QUEUE_RESULT_SCOPE')

class BoundStore:
    """One instance per job invocation. Pin is computed from parser output, not reread bytes."""
    def __init__(self,store):self.store=store;self.binding=None
    def read_bounded(self,*a):return self.store.read_bounded(*a)
    def write_proposal(self,tenant,key,result):
        need(self.binding is None,'QUEUE_RESULT_ALREADY_BOUND')
        raw=encode(result);pin=sha(raw)
        self.store.write_proposal(tenant,key,result)
        stored=read_file(self.store.fd,filename(tenant,key,True),65536)
        need(hmac.compare_digest(sha(stored),pin),'QUEUE_RESULT_STORAGE_CHANGED')
        self.binding=(tenant,key,pin,result['source_sha256'])

class BoundQueue:
    def __init__(self,queue,connect,store):self.queue=queue;self.connect=connect;self.store=store
    def claim(self):return self.queue.claim()
    def fail(self,*a,**kw):return self.queue.fail(*a,**kw)
    def complete(self,claim,*,result_key):
        scope(claim.org_id,claim.id,result_key)
        need(digest(claim.lease_token) and result_key.endswith('/'+claim.lease_token),'QUEUE_RESULT_LEASE')
        b=self.store.binding
        need(type(b) is tuple and b[:2]==(claim.org_id,result_key) and b[3]==claim.sha256 and digest(b[2]),'QUEUE_RESULT_NOT_BOUND')
        # Recheck immediately before commit. Later tampering is rejected by read_bound.
        actual=read_file(self.store.store.fd,filename(claim.org_id,result_key,True),65536)
        need(hmac.compare_digest(sha(actual),b[2]),'QUEUE_RESULT_STORAGE_CHANGED')
        with self.connect() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute("""UPDATE jw_dev.ocr_jobs_v112 SET state='needs_review',result_key=%s,
                      result_sha256=%s,lease_token=NULL,lease_until=NULL,completed_at=clock_timestamp()
                      WHERE id=%s AND org_id=%s AND file_sha256=%s AND state='running'
                      AND lease_token=%s AND lease_until>clock_timestamp() RETURNING id""",(result_key,b[2],claim.id,claim.org_id,claim.sha256,claim.lease_token))
                    row=cur.fetchone()
                    need(row is None or row==(claim.id,),'QUEUE_RESULT_COMMIT_SHAPE')
                    return row is not None

def read_bound(cur,store,*,tenant,job_id):
    need(type(tenant) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}',tenant) and type(job_id) is str and re.fullmatch(r'[0-9a-f]{32}',job_id),'QUEUE_RESULT_SCOPE')
    cur.execute('SELECT state,result_key,file_sha256,result_sha256 FROM jw_dev.ocr_jobs_v112 WHERE org_id=%s AND id=%s',(tenant,job_id))
    row=cur.fetchone();need(type(row) in (tuple,list) and len(row)==4 and row[0]=='needs_review' and digest(row[2]) and digest(row[3]),'QUEUE_RESULT_NOT_COMMITTED')
    scope(tenant,job_id,row[1])
    raw=read_file(store.fd,filename(tenant,row[1],True),65536)
    need(hmac.compare_digest(sha(raw),row[3]),'QUEUE_RESULT_STORAGE_CHANGED')
    try:r=json.loads(raw)
    except (ValueError,UnicodeError,RecursionError):raise Blocked('QUEUE_RESULT_INVALID') from None
    need(encode(r)==raw and r['source_sha256']==row[2],'QUEUE_RESULT_INVALID')
    return r
