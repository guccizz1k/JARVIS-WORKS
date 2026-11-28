"""Read only the committed lease-specific proposal through a tenant-restricted DB cursor.
No deletion of stale/orphan files and no exposure of an object path to HTTP clients.
Caller must authenticate tenant and authorize cursor; fixture store only.
"""
import json,re
from review_gates import need,digest
from local_queue_store import filename,read_file

def read_committed(cur,store,*,tenant,job_id):
    need(type(tenant) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}',tenant) and type(job_id) is str and re.fullmatch(r'[0-9a-f]{32}',job_id),'QUEUE_RESULT_SCOPE')
    cur.execute('SELECT state,result_key,file_sha256 FROM jw_dev.ocr_jobs_v112 WHERE org_id=%s AND id=%s',(tenant,job_id))
    row=cur.fetchone()
    need(type(row) in (tuple,list) and len(row)==3 and row[0]=='needs_review' and digest(row[2]),'QUEUE_RESULT_NOT_COMMITTED')
    key=row[1]
    need(type(key) is str and re.fullmatch(r'tenant/'+re.escape(tenant)+r'/ocr-result/'+job_id+r'/[0-9a-f]{64}',key),'QUEUE_RESULT_SCOPE')
    raw=read_file(store.fd,filename(tenant,key,True),65536)
    def unique(pairs):
        result={}
        for k,v in pairs:
            need(k not in result,'QUEUE_RESULT_DUPLICATE');result[k]=v
        return result
    r=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:need(False,'QUEUE_RESULT_CONSTANT'))
    need(type(r) is dict and r.get('source_sha256')==row[2] and digest(r.get('review_sha256')) and r.get('status') in ('ORIGINAL_REVIEW_REQUIRED','MANUAL_CORRECTION_REQUIRED') and r.get('posting_authorized') is False and r.get('recognition_authorized') is False and r.get('requires_human_review') is True,'QUEUE_RESULT_INVALID')
    return r
