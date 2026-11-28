"""Bounded one-shot Linux PDF review worker. Not a network/security sandbox.
Only locally trusted test fixtures until an independent no-network worker is provided.
"""
import hashlib, json, os, subprocess, sys, tempfile
from pathlib import Path
from review_gates import Blocked, need, digest
ROOT=Path(__file__).resolve().parent
MAX_INPUT=1024*1024
MAX_OUTPUT=64*1024

def pdf_review(*,raw,registered,tenant,timeout=8):
    need(type(raw) is bytes and 0<len(raw)<=MAX_INPUT and digest(registered),'PDF_WORKER_INPUT')
    need(hashlib.sha256(raw).hexdigest()==registered,'DOC_SOURCE_CHANGED')
    need(type(tenant) is str and 1<=len(tenant)<=128,'PDF_WORKER_TENANT')
    need(type(timeout) is int and 1<=timeout<=15,'PDF_WORKER_TIMEOUT')
    need(sys.platform=='linux','PDF_WORKER_PLATFORM')
    with tempfile.TemporaryDirectory(prefix='naruv-pdf-') as d:
        p=Path(d); inp=p/'input.pdf'; out=p/'result.json'; inp.write_bytes(raw)
        env={'PATH':os.defpath,'LANG':'C.UTF-8','HOME':d,'TMPDIR':d}
        try:
            with out.open('xb') as f:
                cp=subprocess.run([sys.executable,'-I',str(ROOT/'pdf_worker.py'),str(inp),registered,tenant],cwd=d,env=env,stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.DEVNULL,timeout=timeout,check=False)
        except subprocess.TimeoutExpired:raise Blocked('PDF_WORKER_DEADLINE') from None
        if cp.returncode!=0 or out.stat().st_size>MAX_OUTPUT:raise Blocked('PDF_WORKER_FAILED')
        try:r=json.loads(out.read_bytes())
        except (ValueError,UnicodeError):raise Blocked('PDF_WORKER_OUTPUT') from None
        if type(r) is not dict:raise Blocked('PDF_WORKER_OUTPUT')
        if r.get('status')=='BLOCKED':raise Blocked(r.get('code','PDF_WORKER_FAILED'))
        need(r.get('source_sha256')==registered and digest(r.get('review_sha256')) and r.get('requires_human_review') is True and r.get('posting_authorized') is False and r.get('confidence') is None and r.get('status') in ('ORIGINAL_REVIEW_REQUIRED','MANUAL_CORRECTION_REQUIRED'),'PDF_WORKER_OUTPUT')
        return r
