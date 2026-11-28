"""One-shot synthetic/review document worker with socket fence and resource limits."""
import hashlib,json,os,signal,subprocess,sys,tempfile
from pathlib import Path
from review_gates import Blocked,need,digest
ROOT=Path(__file__).resolve().parent

def review(*,raw,registered,tenant,format,timeout=20):
    need(type(raw) is bytes and 0<len(raw)<=2*1024*1024 and digest(registered),'OCR_INPUT')
    need(hashlib.sha256(raw).hexdigest()==registered,'DOC_SOURCE_CHANGED')
    need(type(tenant) is str and 1<=len(tenant)<=128 and format in ('pdf','png','jpeg'),'OCR_SCOPE')
    need(type(timeout) is int and 1<=timeout<=30,'OCR_DEADLINE')
    with tempfile.TemporaryDirectory(prefix='naruv-isolated-') as d:
        p=Path(d);inp=p/'input';out=p/'out';inp.write_bytes(raw)
        env={'PATH':os.defpath,'LANG':'C.UTF-8','HOME':d,'TMPDIR':d,'OMP_THREAD_LIMIT':'1'}
        try:
            with out.open('xb') as f:
                r=subprocess.Popen([sys.executable,'-I',str(ROOT/'isolated_worker.py'),str(inp),registered,tenant,format],cwd=d,env=env,stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.DEVNULL,close_fds=True,start_new_session=True)
                try:r.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    # Kill the complete worker process group, including OCR descendants.
                    try:os.killpg(r.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    r.wait(timeout=5)
                    raise Blocked('OCR_WORKER_TIMEOUT') from None
        except OSError:raise Blocked('OCR_WORKER_START') from None
        need(r.returncode==0 and 0<out.stat().st_size<=65536,'OCR_WORKER_FAILED')
        try:result=json.loads(out.read_bytes())
        except (ValueError,UnicodeError):raise Blocked('OCR_WORKER_OUTPUT') from None
        need(type(result) is dict,'OCR_WORKER_OUTPUT')
        if result.get('status')=='BLOCKED':raise Blocked(result.get('code','OCR_WORKER_FAILED'))
        need(result.get('network_fence')=='SOCKET_SYSCALL_DENIAL_ONLY' and result.get('source_sha256')==registered and digest(result.get('review_sha256')) and result.get('posting_authorized') is False and result.get('requires_human_review') is True and result.get('confidence') is None and result.get('status') in ('ORIGINAL_REVIEW_REQUIRED','MANUAL_CORRECTION_REQUIRED'),'OCR_WORKER_OUTPUT')
        need(result.get('recognition_authorized') is False,'OCR_WORKER_OUTPUT')
        if 'id_preview' in result:
            v=result['id_preview']
            need(type(v) is dict and set(v)=={'review_sha256','field_count','issues','two_view_candidate_count','requires_human_review','posting_authorized'} and digest(v['review_sha256']) and type(v['field_count']) is int and 0<=v['field_count']<=7 and type(v['issues']) is list and all(type(x) is str and len(x)<=128 for x in v['issues']) and type(v['two_view_candidate_count']) is int and 1<=v['two_view_candidate_count']<=6 and v['requires_human_review'] is True and v['posting_authorized'] is False,'OCR_WORKER_OUTPUT')
        return result
