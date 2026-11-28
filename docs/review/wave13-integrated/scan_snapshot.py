"""Stage an independently approved, current CVD set in a private directory.
No downloads or updates; no claim of real malware coverage without actual engine.
Caller must supply an independently obtained expected manifest digest and trusted
vendor-verification adapter; staged CVD bytes, not mutable original paths, are scanned.
"""
import hashlib,json,os,stat,tempfile,subprocess,sys
from datetime import datetime,timedelta,timezone
from pathlib import Path
from review_gates import need,digest,utc,Blocked
NAMES=('main.cvd','daily.cvd','bytecode.cvd')
MAX_DB=512*1024*1024

def sha(x):return hashlib.sha256(x).hexdigest()
def file_sha(path):
    with path.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')

def manifest_check(m,pin,now):
    need(type(m) is dict and set(m)=={'schema','observed_at','daily_build_at','files'} and m['schema']=='NARUV_CVD_SNAPSHOT_V1' and digest(pin) and sha(canonical(m))==pin,'CVD_MANIFEST_PIN')
    try:a,b=(datetime.fromisoformat(m[k]) for k in ('observed_at','daily_build_at'))
    except (ValueError,TypeError):raise Blocked('CVD_TIME') from None
    need(utc(now) and utc(a) and utc(b) and timedelta(0)<=now-a<=timedelta(hours=24) and timedelta(0)<=a-b<=timedelta(hours=48) and timedelta(0)<=now-b<=timedelta(hours=48),'CVD_STALE')
    need(type(m['files']) is dict and set(m['files'])==set(NAMES),'CVD_SET')
    for x in m['files'].values():need(type(x) is dict and set(x)=={'sha256','bytes'} and digest(x['sha256']) and type(x['bytes']) is int and 512<=x['bytes']<=MAX_DB,'CVD_ENTRY')

def stage(fd,dst,m):
    # Open pinned basename relative to trusted directory FD. Never follow symlinks.
    need(set(os.listdir(fd))==set(NAMES),'CVD_SET')
    for name in NAMES:
        meta=m['files'][name]; f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
        with os.fdopen(f,'rb') as src, (dst/name).open('xb') as out:
            st=os.fstat(src.fileno());need(stat.S_ISREG(st.st_mode) and st.st_size==meta['bytes'] and st.st_nlink==1,'CVD_FILE')
            h=hashlib.sha256();n=0
            while True:
                chunk=src.read(1024*1024)
                if not chunk:break
                n+=len(chunk);need(n<=meta['bytes'],'CVD_SIZE');h.update(chunk);out.write(chunk)
            need(n==meta['bytes'] and h.hexdigest()==meta['sha256'],'CVD_HASH')
            out.flush();os.fsync(out.fileno())
        (dst/name).chmod(0o400)

def daily_header_check(path,manifest):
    # CVD header is 512 bytes and has colon-separated epoch timestamp at index 8.
    # Trust header only in conjunction with actual vendor verification of this file.
    try:
        with path.open('rb') as f:header=f.read(512).decode('ascii').rstrip(' \x00\n')
        fields=header.rsplit(':',7);need(len(fields)==8 and fields[0].startswith('ClamAV-VDB:') and fields[1].isdigit() and int(fields[1])>0 and fields[2].isdigit() and int(fields[2])>0 and fields[-1].isdigit(),'CVD_HEADER')
        when=datetime.fromtimestamp(int(fields[-1]),timezone.utc)
        need(when==datetime.fromisoformat(manifest['daily_build_at']),'CVD_BUILD_TIME_MISMATCH')
    except Blocked:raise
    except (ValueError,OverflowError,OSError):raise Blocked('CVD_HEADER') from None

def vendor_cvd_verify(path):
    try:
        return subprocess.run([sys.executable,'-I',str(Path(__file__).resolve().with_name('cvd_verify_worker.py')),str(path)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90,check=False,env={'PATH':os.defpath,'LANG':'C','HOME':str(path.parent)},cwd=path.parent).returncode==0
    except (OSError,subprocess.TimeoutExpired):return False

def engine_scan(db,sample):
    # Runtime option compatibility, official DB signatures and detection still need real CI.
    return subprocess.run(['/usr/bin/clamscan','--official-db-only=yes','--alert-encrypted=yes','--alert-exceeds-max=yes','--heuristic-alerts=yes','--max-filesize=2M','--max-scansize=32M','--database='+str(db),'--no-summary',str(sample)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90,check=False,env={'PATH':os.defpath,'LANG':'C','HOME':str(db.parent)},cwd=db.parent).returncode

def review(raw,*,fd,manifest,expected_pin,vendor_verify=vendor_cvd_verify,run=engine_scan):
    """Only a review result. A caller-supplied adapter is not independent attestation."""
    need(type(raw) is bytes and 0<len(raw)<=2*1024*1024,'CVD_INPUT')
    # Snapshot mutable input; validate pin before any file operation.
    m=json.loads(canonical(manifest));manifest_check(m,expected_pin,datetime.now(timezone.utc))
    try:
        with tempfile.TemporaryDirectory(prefix='naruv-cvd-') as root:
            p=Path(root);db=p/'db';db.mkdir(mode=0o700);stage(fd,db,m)
            daily_header_check(db/'daily.cvd',m)
            for name in NAMES:need(vendor_verify(db/name) is True,'CVD_VENDOR_VERIFY')
            sample=p/'sample';sample.write_bytes(raw);sample.chmod(0o400)
            # Recheck bytes after vendor verification, not merely the original path.
            for name in NAMES:need(file_sha(db/name)==m['files'][name]['sha256'],'CVD_STAGED_CHANGED')
            rc=run(db,sample)
            need(type(rc) is int and rc in (0,1),'CVD_ENGINE_ERROR')
            need(sha(sample.read_bytes())==sha(raw) and all(file_sha(db/n)==m['files'][n]['sha256'] for n in NAMES),'CVD_STAGED_CHANGED')
            manifest_check(m,expected_pin,datetime.now(timezone.utc))
            return dict(status='NO_DETECTION_REVIEW_ONLY' if rc==0 else 'DETECTED_REVIEW_ONLY',input_sha256=sha(raw),manifest_sha256=expected_pin,engine_exit=rc,production_authorized=False,malware_free_guaranteed=False,adapter_independence_attested=False)
    except (OSError,subprocess.TimeoutExpired):raise Blocked('CVD_ENGINE_OR_STORAGE_UNAVAILABLE') from None
