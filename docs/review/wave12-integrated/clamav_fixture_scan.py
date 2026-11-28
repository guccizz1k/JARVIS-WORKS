"""Actual ClamAV engine smoke, custom synthetic database only.
Not a production malware scanner. Never accepts missing/unpinned signatures.
No external updates, no real customer documents, no network requests here.
"""
import hashlib,subprocess,tempfile
from pathlib import Path

def scan_fixture(raw,*,database,pin):
    if type(raw) is not bytes or not 0<len(raw)<=2*1024*1024:return False
    try:
        db=Path(database)
        if not db.is_file() or db.is_symlink() or db.stat().st_size>65536:return False
        if hashlib.sha256(db.read_bytes()).hexdigest()!=pin:return False
        with tempfile.TemporaryDirectory(prefix='wave12-scan-') as d:
            src=Path(d)/'sample';src.write_bytes(raw)
            p=subprocess.run(['/usr/bin/clamscan','--database='+str(db.resolve()),'--no-summary',str(src)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10,check=False)
            return p.returncode==0
    except (OSError,ValueError,subprocess.TimeoutExpired):return False
