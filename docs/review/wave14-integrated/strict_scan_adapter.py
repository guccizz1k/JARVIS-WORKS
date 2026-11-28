"""Trusted fixture-only adapter for the modern libclamav helper and CLI.
The exact compiled helper and ClamAV binary must be independently pinned.
No fallback, no service installation, no download. Actual engine test remains required.
"""
import os,sys,signal,subprocess,stat,tempfile,hashlib
from pathlib import Path
from review_gates import need,digest,Blocked
ROOT=Path(__file__).resolve().parent

def check_binary(path,pin):
    p=Path(path);need(p.is_absolute() and not p.is_symlink() and digest(pin),'CVD_BINARY_PIN')
    try:
        st=p.stat();need(stat.S_ISREG(st.st_mode) and st.st_mode&0o111 and not st.st_mode&0o022,'CVD_BINARY_MODE')
        with p.open('rb') as f:need(hashlib.file_digest(f,'sha256').hexdigest()==pin,'CVD_BINARY_PIN')
    except OSError:raise Blocked('CVD_BINARY_MISSING') from None
    return str(p)

def execute(argv):
    try:
        with tempfile.TemporaryDirectory(prefix='naruv-clam-worker-') as t:
            p=subprocess.Popen([sys.executable,'-I',str(ROOT/'strict_scan_worker.py'),*argv],cwd=t,env={'PATH':os.defpath,'LANG':'C','HOME':t},stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True,start_new_session=True)
            try:return p.wait(timeout=100)
            except subprocess.TimeoutExpired:
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                p.wait(timeout=5);raise Blocked('CVD_PROCESS_TIMEOUT') from None
    except OSError:raise Blocked('CVD_PROCESS_UNAVAILABLE') from None

def adapters(*,helper,helper_pin,scanner,scanner_pin):
    # Recheck the pinned trusted binaries before each execution. This does not
    # attest library/loader integrity or protect a malicious host administrator.
    def verify(db,cert):
        exe=check_binary(helper,helper_pin)
        return execute([exe,str(db),str(cert)])==0
    def run(db,cert,sample):
        exe=check_binary(scanner,scanner_pin)
        return execute([exe,'--fips-limits','--official-db-only=yes','--cvdcertsdir='+str(cert),'--alert-encrypted=yes','--alert-exceeds-max=yes','--heuristic-alerts=yes','--max-filesize=2M','--max-scansize=32M','--database='+str(db),'--no-summary',str(sample)])
    return verify,run
