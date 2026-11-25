"""V6.4 tenant-scoped, human-reviewed evidence ledger; separate from official accounting.

Photo OCR / PDFs / XLSX are candidate extraction only. No confirmed business
records are made until a person cross-checks the original and approves values.
"""
from __future__ import annotations
import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
from datetime import date,datetime,timedelta
from pathlib import Path
from typing import Literal
from fastapi import Depends,File,UploadFile
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel,ConfigDict,Field
from .security_hardening import lock_file_scan,sealed_json,unseal_json
from .evidence_v64_worker import MAX_BYTES

TYPES=('sales','purchase','expense','inventory_snapshot')
MAX_PENDING_PER_ORG=100

class Approval(BaseModel):
 model_config=ConfigDict(extra='forbid',str_strip_whitespace=True)
 preview_digest:str=Field(min_length=64,max_length=64,pattern=r'^[0-9a-f]{64}$')
 record_type:Literal['sales','purchase','expense','inventory_snapshot']
 document_kind:Literal['receipt','sales_slip','purchase_slip','trade_statement','inventory_sheet']
 counterparty:str=Field(min_length=1,max_length=120)
 document_date:date
 gross_amount:int|None=Field(default=None,strict=True,ge=1,le=1_000_000_000)
 reference_number:str=Field(default='',max_length=80)
 sku:str=Field(default='',max_length=80)
 quantity:int|None=Field(default=None,strict=True,ge=1,le=10_000_000)
 unit:str=Field(default='',max_length=20)
 original_checked:Literal[True]


def install_schema(conn):
 with conn() as c:
  c.executescript('''
   CREATE TABLE IF NOT EXISTS evidence_previews_v64(
    id TEXT PRIMARY KEY,org_id TEXT NOT NULL REFERENCES organizations(id),
    uploaded_by TEXT NOT NULL REFERENCES users(id),file_sha256 TEXT NOT NULL,
    filename TEXT NOT NULL, proposed_json TEXT NOT NULL,digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending','confirmed')),
    created_at TEXT NOT NULL,confirmed_at TEXT,
    record_id TEXT UNIQUE);
   CREATE INDEX IF NOT EXISTS idx_evidence_queue_v64 ON evidence_previews_v64(org_id,created_at);
   CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_file_v64 ON evidence_previews_v64(org_id,file_sha256)
     WHERE status='confirmed';
   CREATE TABLE IF NOT EXISTS evidence_records_v64(
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id),
    preview_id TEXT NOT NULL UNIQUE REFERENCES evidence_previews_v64(id),
    kind TEXT NOT NULL CHECK(kind IN ('sales','purchase','expense','inventory_snapshot')),
    source_kind TEXT NOT NULL,
    counterparty TEXT NOT NULL,document_date TEXT NOT NULL,
    gross_amount INTEGER CHECK(gross_amount IS NULL OR gross_amount>0),
    reference_number TEXT NOT NULL DEFAULT '',
    sku TEXT NOT NULL DEFAULT '',quantity INTEGER CHECK(quantity IS NULL OR quantity>0),
    unit TEXT NOT NULL DEFAULT '',source_sha256 TEXT NOT NULL,
    reviewed_by TEXT NOT NULL REFERENCES users(id),created_at TEXT NOT NULL,
    corrected_fields TEXT NOT NULL DEFAULT '[]');
   CREATE INDEX IF NOT EXISTS idx_evidence_records_v64 ON evidence_records_v64(org_id,kind,document_date);
   CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_reference_v64 ON evidence_records_v64(org_id,source_kind,counterparty,reference_number) WHERE reference_number!='';
   CREATE TRIGGER IF NOT EXISTS trg_evidence_preview_org_v64 BEFORE INSERT ON evidence_previews_v64
    FOR EACH ROW WHEN (SELECT org_id FROM users WHERE id=NEW.uploaded_by) IS NOT NEW.org_id
    BEGIN SELECT RAISE(ABORT,'evidence uploader organization mismatch'); END;
   CREATE TRIGGER IF NOT EXISTS trg_evidence_preview_org_up_v64 BEFORE UPDATE OF org_id,uploaded_by ON evidence_previews_v64
    FOR EACH ROW WHEN (SELECT org_id FROM users WHERE id=NEW.uploaded_by) IS NOT NEW.org_id
    BEGIN SELECT RAISE(ABORT,'evidence uploader organization mismatch'); END;
   CREATE TRIGGER IF NOT EXISTS trg_evidence_record_org_v64 BEFORE INSERT ON evidence_records_v64
    FOR EACH ROW WHEN (SELECT org_id FROM evidence_previews_v64 WHERE id=NEW.preview_id) IS NOT NEW.org_id
      OR (SELECT org_id FROM users WHERE id=NEW.reviewed_by) IS NOT NEW.org_id
    BEGIN SELECT RAISE(ABORT,'evidence record organization mismatch'); END;
   CREATE TRIGGER IF NOT EXISTS trg_evidence_record_org_up_v64 BEFORE UPDATE OF org_id,preview_id,reviewed_by ON evidence_records_v64
    FOR EACH ROW WHEN (SELECT org_id FROM evidence_previews_v64 WHERE id=NEW.preview_id) IS NOT NEW.org_id
      OR (SELECT org_id FROM users WHERE id=NEW.reviewed_by) IS NOT NEW.org_id
    BEGIN SELECT RAISE(ABORT,'evidence record organization mismatch'); END;
  ''')

def protected_parse(filename,raw):
 if not 0<len(raw)<=MAX_BYTES:raise ValueError('파일 크기는 5MB 이하이어야 합니다')
 lock_file_scan(raw)
 payload=json.dumps({'filename':filename,'base64':base64.b64encode(raw).decode('ascii')}).encode()
 try:
  p=subprocess.run([sys.executable,'-m','app.evidence_v64_worker'],
   cwd=str(Path(__file__).resolve().parent.parent),input=payload,
   capture_output=True,timeout=50,check=False,
   env={k:v for k,v in os.environ.items() if k in ('PATH','PYTHONPATH','LANG','LC_ALL','HOME','VIRTUAL_ENV','TESSDATA_PREFIX')})
 except subprocess.TimeoutExpired as exc:raise ValueError('문서 분석 시간 초과') from exc
 if p.returncode!=0 or len(p.stdout)>200_000:raise ValueError('문서 분석에 실패했습니다')
 try:doc=json.loads(p.stdout)
 except ValueError as exc:raise ValueError('문서 분석 응답 형식 오류') from exc
 if doc.get('error'):raise ValueError(doc['error'])
 if not isinstance(doc.get('result'),dict):raise ValueError('분석 결과가 올바르지 않습니다')
 return doc['result']

def digest_doc(doc):
 return hashlib.sha256(json.dumps(doc,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def summary(c,org):
 rows=c.execute('''SELECT kind,count(*) AS cnt,coalesce(sum(gross_amount),0) AS money
                FROM evidence_records_v64 WHERE org_id=? GROUP BY kind''',(org,)).fetchall()
 types={name:{'count':0,'amount':0} for name in TYPES}
 for x in rows:types[x['kind']]={'count':x['cnt'],'amount':x['money']}
 pending=c.execute("SELECT count(*) FROM evidence_previews_v64 WHERE org_id=? AND status='pending'",(org,)).fetchone()[0]
 return {'by_type':types,'pending_review':pending,
  'total_confirmed':sum(x['count'] for x in types.values()),
  'inventory_count_only':True,
  'warning':'별도 증빙 관리 기록입니다. 공식 회계전표·세금계산서·입금·실재고 자동 확정이 아닙니다.'}

def register_routes(app,*,conn,transaction,current_user,get_row,ident,now,audit,fail):
 # OCR, PDF parsing and malware scans are expensive synchronous workloads.
 # The concurrency ceiling is per application worker; production must use an
 # isolated job queue with an independent global limit and network isolation.
 ocr_slots = asyncio.Semaphore(2)
 @app.post('/api/evidence/preview',status_code=201)
 async def preview(file:UploadFile=File(...),user=Depends(current_user)):
  filename=Path(file.filename or '').name[:150]
  if not filename or Path(filename).suffix.lower() not in ('.png','.jpg','.jpeg','.webp','.pdf','.xlsx'):
   fail('PNG/JPEG/WEBP/PDF/XLSX만 지원합니다',422)
  try:raw=await file.read(MAX_BYTES+1)
  finally:await file.close()
  if not raw or len(raw)>MAX_BYTES:fail('파일당 최대 5MB입니다',413)
  sha=hashlib.sha256(raw).hexdigest()
  # Fast rejection protects OCR worker capacity and avoids unbounded review queues.
  with conn() as c:
   existing=c.execute('SELECT status FROM evidence_previews_v64 WHERE org_id=? AND file_sha256=? LIMIT 1',
      (user['org_id'],sha)).fetchone()
   if existing:fail('이미 접수된 동일 파일입니다',409)
   if c.execute("SELECT count(*) FROM evidence_previews_v64 WHERE org_id=? AND status='pending'",
      (user['org_id'],)).fetchone()[0]>=MAX_PENDING_PER_ORG:
    fail('미검토 문서가 너무 많습니다. 기존 문서를 검토한 뒤 다시 업로드하세요',429)
  try:
   await asyncio.wait_for(ocr_slots.acquire(),timeout=4)
  except asyncio.TimeoutError:
   fail('문서 분석 요청이 많습니다. 잠시 후 다시 시도하세요',429)
  try:
   # Never occupy the event loop while scanner/OCR/subprocess execution runs.
   try:doc=await run_in_threadpool(protected_parse,filename,raw)
   except ValueError as exc:fail(str(exc),422)
   except RuntimeError:fail('파일 보안 검증 실패: 업로드를 차단했습니다',503)
  finally:
   ocr_slots.release()
  # Size is integrity-bound inside the existing *encrypted* proposed document.
  # No schema drift, no raw source retention, and no invented 0-byte values.
  doc=dict(doc)
  doc['source_size_bytes']=len(raw)
  digest=digest_doc(doc)
  with transaction() as c:
   if c.execute("SELECT 1 FROM evidence_previews_v64 WHERE org_id=? AND file_sha256=?",(user['org_id'],sha)).fetchone():
    fail('이미 접수된 동일 파일입니다',409)
   if c.execute("SELECT count(*) FROM evidence_previews_v64 WHERE org_id=? AND status='pending'",
      (user['org_id'],)).fetchone()[0]>=MAX_PENDING_PER_ORG:
    fail('미검토 문서가 너무 많습니다. 기존 문서를 검토한 뒤 다시 업로드하세요',429)
   f=doc.get('fields',{})
   if doc.get('document_kind') and f.get('counterparty') and f.get('reference_number'):
    if c.execute("SELECT 1 FROM evidence_records_v64 WHERE org_id=? AND source_kind=? AND counterparty=? AND reference_number=? LIMIT 1",
      (user['org_id'],doc['document_kind'],f['counterparty'],f['reference_number'])).fetchone():
     fail('이미 확인된 동일 거래처·문서번호 증빙입니다',409)
   eid=ident()
   c.execute('''INSERT INTO evidence_previews_v64
       (id,org_id,uploaded_by,file_sha256,filename,proposed_json,digest,status,created_at)
       VALUES(?,?,?,?,?,?,?,?,?)''',
       (eid,user['org_id'],user['id'],sha,filename,sealed_json(doc),digest,'pending',now()))
   audit(c,user,'document_evidence',eid,'evidence_preview',{'method':doc['method'],'kind':doc['document_kind']})
  return {'id':eid,'digest':digest,'status':'pending','document':doc,'source_file_sha256':sha,'original_file_stored':False,'source_size_bytes':len(raw),'confirmation_required':True}

 @app.get('/api/evidence/queue')
 def queue(user=Depends(current_user)):
  with conn() as c:
   params=(user['org_id'],) if user['role']=='admin' else (user['org_id'],user['id'])
   clause='' if user['role']=='admin' else ' AND uploaded_by=?'
   rows=c.execute('''SELECT id,filename,created_at,status,proposed_json,digest,record_id
       FROM evidence_previews_v64 WHERE org_id=?'''+clause+' ORDER BY created_at DESC,rowid DESC LIMIT 100',params).fetchall()
   return {'items':[{'id':x['id'],'filename':x['filename'],'created_at':x['created_at'],
     'status':x['status'],'document_kind':unseal_json(x['proposed_json'])['document_kind'],
     'record_id':x['record_id'],'source_size_bytes':unseal_json(x['proposed_json']).get('source_size_bytes')} for x in rows]}

 @app.get('/api/evidence/preview/{eid}')
 def read_preview(eid:str,user=Depends(current_user)):
  with conn() as c:
   row=get_row(c,'evidence_previews_v64',eid,user['org_id'])
   if row['uploaded_by']!=user['id'] and user['role']!='admin':fail('업로더 또는 관리자만 조회할 수 있습니다',403)
   return {'id':eid,'digest':row['digest'],'status':row['status'],
           'document':unseal_json(row['proposed_json']),'record_id':row['record_id'],
           'source_file_sha256':row['file_sha256'],'original_file_stored':False,'source_size_bytes':unseal_json(row['proposed_json']).get('source_size_bytes')}

 @app.post('/api/evidence/preview/{eid}/confirm',status_code=201)
 def confirm(eid:str,body:Approval,user=Depends(current_user)):
  with transaction() as c:
   row=get_row(c,'evidence_previews_v64',eid,user['org_id'])
   if row['uploaded_by']!=user['id'] and user['role']!='admin':fail('업로더 또는 관리자만 승인할 수 있습니다',403)
   if row['status']!='pending':fail('이미 처리된 증빙입니다',409)
   if (datetime.fromisoformat(now())-datetime.fromisoformat(row['created_at'])).total_seconds()>24*3600:
    fail('24시간 검토 기한 만료. 새로 업로드하세요',409)
   if not hmac.compare_digest(row['digest'],body.preview_digest):fail('문서가 변경되었습니다. 다시 확인하세요',409)
   doc=unseal_json(row['proposed_json'])
   # An unsupported OCR document must not be rebranded as a receipt
   # by manually entering financial fields. Keep the preview pending.
   if doc.get('document_kind') is None or doc.get('kind_inference') in ('ambiguous','unknown','unsupported'):
    fail('원본의 증빙 문서 유형을 판별하지 못했습니다. 다른 유형으로 등록할 수 없습니다',409)
   if doc['document_kind']!=body.document_kind:
    fail('원본문서 유형이 다릅니다. 잘못된 파일을 등록하지 마세요',409)
   allowed={
    'receipt':('sales','purchase','expense'),
    'sales_slip':('sales',),
    'purchase_slip':('purchase',),
    'trade_statement':('sales','purchase'),
    'inventory_sheet':('inventory_snapshot',),
   }
   if body.record_type not in allowed[body.document_kind]:
    fail('원본문서 종류에 맞지 않는 업무 기록입니다. 원본을 다시 확인하세요',422)
   if body.record_type=='inventory_snapshot':
    if body.document_kind!='inventory_sheet' or not body.sku or not body.quantity:
     fail('재고 실사에는 품목코드와 재고수량이 필요합니다',422)
    if body.gross_amount is not None:fail('재고 실사에 금액을 입력하지 마세요',422)
   elif body.gross_amount is None:fail('매출·매입·경비에는 금액이 필요합니다',422)
   if any(ord(x)<32 for x in body.counterparty+body.reference_number+body.sku+body.unit):fail('제어문자를 허용하지 않습니다',422)
   # Evidence field corrections are allowed only after explicit source-check acknowledgment.
   original=doc.get('fields',{})
   submitted={'counterparty':body.counterparty,'document_date':body.document_date.isoformat(),
    'gross_amount':body.gross_amount,'reference_number':body.reference_number,
    'sku':body.sku,'quantity':body.quantity,'unit':body.unit}
   corrected=[k for k,value in submitted.items() if original.get(k) not in (None,'') and original[k]!=value]
   if doc['document_kind']!=body.document_kind:corrected.append('document_kind')
   if body.reference_number and c.execute("SELECT 1 FROM evidence_records_v64 WHERE org_id=? AND source_kind=? AND counterparty=? AND reference_number=?",
       (user['org_id'],body.document_kind,body.counterparty,body.reference_number)).fetchone():
    fail('이미 등록된 원본 참조번호입니다',409)
   record_id=ident()
   try:
    c.execute('''INSERT INTO evidence_records_v64(id,org_id,preview_id,kind,source_kind,
       counterparty,document_date,gross_amount,reference_number,sku,quantity,unit,
       source_sha256,reviewed_by,created_at,corrected_fields)
       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
       (record_id,user['org_id'],eid,body.record_type,body.document_kind,body.counterparty,
        body.document_date.isoformat(),body.gross_amount,body.reference_number,body.sku,
        body.quantity,body.unit,row['file_sha256'],user['id'],now(),json.dumps(sorted(corrected))))
    c.execute("UPDATE evidence_previews_v64 SET status='confirmed',confirmed_at=?,record_id=? WHERE id=? AND org_id=?",
      (now(),record_id,eid,user['org_id']))
   except Exception:
    raise
   audit(c,user,'document_evidence',record_id,'evidence_confirm',
         {'type':body.record_type,'kind':body.document_kind,'corrected_fields':sorted(corrected),
          'original_checked':True,'no_official_accounting_posting':True})
  return {'id':record_id,'record_type':body.record_type,'corrected_fields':sorted(corrected),
          'accounting_posted':False,'payment_created':False,'inventory_stock_changed':False}

 @app.get('/api/evidence/records')
 def records(user=Depends(current_user)):
  with conn() as c:
   return [dict(r) for r in c.execute('''SELECT id,kind,source_kind,counterparty,document_date,
      gross_amount,reference_number,sku,quantity,unit,created_at FROM evidence_records_v64
      WHERE org_id=? ORDER BY created_at DESC,rowid DESC LIMIT 100''',(user['org_id'],))]

 @app.get('/api/evidence/dashboard')
 def dashboard(user=Depends(current_user)):
  with conn() as c:return summary(c,user['org_id'])
