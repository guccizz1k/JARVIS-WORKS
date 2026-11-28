"""Synthetic-only bounded process entry point. Does not accept customer uploads."""
import hashlib,json,os,signal,subprocess,sys,tempfile
from pathlib import Path
from review_gates import need,digest,Blocked
ROOT=Path(__file__).resolve().parent

def review(raw,*,template,expected_pin,registered,tenant,ack,timeout=30):
    need(ack=='SYNTHETIC_REVIEW_ONLY' and sys.platform=='linux','GRID_DISABLED')
    need(type(raw) is bytes and 0<len(raw)<=2*1024*1024 and digest(registered) and hashlib.sha256(raw).hexdigest()==registered,'DOC_SOURCE_CHANGED')
    need(type(timeout) is int and 1<=timeout<=45 and type(tenant) is str and 1<=len(tenant)<=128 and digest(expected_pin),'GRID_SCOPE')
    cfg=json.dumps(dict(template=template,expected_pin=expected_pin,registered=registered,tenant=tenant),allow_nan=False);need(len(cfg)<=4096,'GRID_CONFIG_LIMIT')
    with tempfile.TemporaryDirectory(prefix='naruv-grid-') as d:
        p=Path(d);(p/'input').write_bytes(raw);(p/'config').write_text(cfg)
        with (p/'out').open('xb') as f:
            proc=subprocess.Popen([sys.executable,'-I',str(ROOT/'grid_worker.py'),str(p/'input'),str(p/'config')],cwd=p,env={'PATH':os.defpath,'LANG':'C.UTF-8','HOME':d,'TMPDIR':d,'OMP_THREAD_LIMIT':'1'},stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True)
            try:proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                proc.wait(timeout=5);raise Blocked('GRID_TIMEOUT') from None
        need(proc.returncode==0 and 0<(p/'out').stat().st_size<=65536,'GRID_WORKER_FAILED')
        result=json.loads((p/'out').read_bytes());need(type(result) is dict,'GRID_WORKER_OUTPUT')
        if result.get('status')=='BLOCKED':raise Blocked(result.get('code','GRID_WORKER_FAILED'))
        need(result.get('source_sha256')==registered and result.get('template_sha256')==expected_pin and digest(result.get('review_sha256')) and result.get('requires_human_review') is True and all(result.get(k) is False for k in ('posting_authorized','recognition_authorized','production_authorized')) and result.get('network_fence')=='SOCKET_SYSCALL_DENIAL_ONLY','GRID_WORKER_OUTPUT')
        return result
