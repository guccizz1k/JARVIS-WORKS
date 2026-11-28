"""One public vendor acquisition in disposable CI. No fallback or threshold relaxation.
The package CA files and lab pins do not substitute for independently approved operational trust.
"""
import ctypes,ctypes.util,hashlib,json,os,re,shutil,subprocess,tempfile
from datetime import datetime,timezone
from pathlib import Path
from cvd_diagnostics import NAMES,PAIR_NAMES,diagnose,check_pairs
from cvd_pair_snapshot import review,pin,sha
from strict_scan_adapter import adapters
from review_gates import Blocked

def report(tag,**data):
    print('WAVE14_'+tag+' '+json.dumps(data,sort_keys=True),flush=True)

def main(helper):
    helper=Path(helper).resolve()
    scanner=Path('/usr/bin/clamscan').resolve()
    verify,run=adapters(helper=helper,helper_pin=sha(helper),scanner=scanner,scanner_pin=sha(scanner))
    with tempfile.TemporaryDirectory(prefix='wave14-official-') as d:
        root=Path(d);db=root/'download';db.mkdir(mode=0o700);cert=root/'cert';cert.mkdir(mode=0o700)
        # Only files shipped by Ubuntu ClamAV packages. Never trust downloaded CVD as a CA.
        found=[]
        for pkg in ('clamav','clamav-base','libclamav12','clamav-freshclam'):
            r=subprocess.run(['dpkg','-L',pkg],capture_output=True,text=True,check=False)
            found.extend(Path(x) for x in r.stdout.splitlines() if '/certs/' in x and x.endswith(('.crt','.pem','.cer')))
        for p in sorted(set(found)):
            if p.is_file() and not p.is_symlink() and 1<=p.stat().st_size<=65536:
                dst=cert/p.name
                if dst.exists() and sha(dst)!=sha(p):raise RuntimeError('CERT_NAME_COLLISION')
                if not dst.exists():shutil.copyfile(p,dst)
        # Negative control on actual modern helper. Return 1 is distinct from init failure.
        fake=root/'forged.cvd';fake.write_bytes(b'not-a-valid-database')
        rc=subprocess.run([str(helper),str(fake),str(cert)],capture_output=True,timeout=15,check=False)
        assert rc.returncode==1 and b'CVD_VENDOR_VERIFY_FAILED' in rc.stderr
        report('MODERN_LIBCLAMAV_FORGERY_REJECTED',cert_files=len(list(cert.iterdir())))
        config=root/'freshclam.conf'
        config.write_text('DatabaseMirror database.clamav.net\nDatabaseDirectory '+str(db)+'\nScriptedUpdates no\nMaxAttempts 1\nConnectTimeout 10\nReceiveTimeout 35\n')
        try:
            cp=subprocess.run(['/usr/bin/freshclam','--config-file='+str(config),'--stdout'],capture_output=True,text=True,timeout=100,check=False)
        except (OSError,subprocess.TimeoutExpired):
            report('OFFICIAL_BLOCKED',reason='ACQUISITION_UNAVAILABLE');return
        # Only print relevant vendor version evidence, not arbitrary environment output.
        for line in cp.stdout.splitlines():
            if 'database available for download' in line or '.cvd updated' in line or 'Database test passed' in line: print(line[:300])
        if cp.returncode:
            report('OFFICIAL_BLOCKED',reason='ACQUISITION_EXIT',exit=cp.returncode);return
        if not (db/'daily.cvd').is_file():
            report('OFFICIAL_BLOCKED',reason='DAILY_MISSING');return
        matches=re.findall(r'daily database available for download \(remote version: (\d+)\)',cp.stdout)
        advertised=int(matches[0]) if len(matches)==1 else None
        with (db/'daily.cvd').open('rb') as f:header=f.read(512)
        lib=ctypes.CDLL(ctypes.util.find_library('clamav'));lib.cl_retflevel.restype=ctypes.c_uint
        level=lib.cl_retflevel()
        observed=datetime.now(timezone.utc)
        result=diagnose(header=header,now=observed,observed_at=observed,advertised_version=advertised,previous_verified_version=28194,engine_level=level)
        # 28194 is a previous FreshClam-tested version, not an independent modern trust pin.
        report('OFFICIAL_HEADER_DIAGNOSTIC',**result)
        absent=[n for n in PAIR_NAMES if not (db/n).is_file() or (db/n).is_symlink()]
        if absent or not list(cert.iterdir()):
            report('OFFICIAL_BLOCKED',reason='DETACHED_PAIRS_OR_PACKAGE_CA_MISSING',missing=absent,cert_count=len(list(cert.iterdir())));return
        if advertised is None or level<=0:
            report('OFFICIAL_BLOCKED',reason='VERSION_REFERENCE_MISSING');return
        source=root/'pinned';source.mkdir(mode=0o700)
        for name in PAIR_NAMES:shutil.copyfile(db/name,source/name)
        m={n:dict(sha256=sha(source/n),bytes=(source/n).stat().st_size) for n in PAIR_NAMES}
        certs={p.name:dict(sha256=sha(p),bytes=p.stat().st_size) for p in cert.iterdir()}
        # Signature verification itself is useful even if stale. Never scan stale databases.
        checks={n:verify(source/n,cert) for n in NAMES}
        report('OFFICIAL_DETACHED_SIGNATURE_CHECKS',checks=checks,independent_production_pin_verified=False)
        if not all(checks.values()) or result['status']!='HEADER_MATCH_ONLY':
            report('OFFICIAL_BLOCKED',reason='SIGNATURE_OR_FRESHNESS',freshness=result['reasons']);return
        fd=os.open(source,os.O_DIRECTORY|os.O_RDONLY);cf=os.open(cert,os.O_DIRECTORY|os.O_RDONLY)
        try:
            try:
                out=review(b'NARUV synthetic benign text',db_fd=fd,cert_fd=cf,manifest=m,expected_pin=check_pairs(m),certs=certs,expected_cert_pin=pin(certs),observed_at=observed,advertised_version=advertised,previous_verified_version=28194,engine_level=level,verify=verify,run=run)
            except Blocked as e:
                report('OFFICIAL_BLOCKED',reason=str(e));return
            assert out['status']=='NO_DETECTION_REVIEW_ONLY' and not out['production_authorized']
            report('OFFICIAL_STRICT_LAB_SCAN_PASS',**out)
        finally:os.close(fd);os.close(cf)
if __name__=='__main__':
    import sys
    main(sys.argv[1])
