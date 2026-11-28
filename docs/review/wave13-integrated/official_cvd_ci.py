"""One official acquisition attempt in disposable CI; no production DB or credentials.
No alternate mirror, no retry on vendor rate limits, no generated signature substitution.
Acquired manifest is a local test pin, not an independently approved production pin.
"""
import json,os,subprocess,tempfile,shutil
from datetime import datetime,timezone
from pathlib import Path
import scan_snapshot as scan
from review_gates import Blocked

def main():
    with tempfile.TemporaryDirectory(prefix='wave13-official-') as d:
        root=Path(d);download=root/'download';download.mkdir(mode=0o700)
        config=root/'freshclam.conf'
        config.write_text('DatabaseMirror database.clamav.net\nDatabaseDirectory '+str(download)+'\nScriptedUpdates no\nMaxAttempts 1\nConnectTimeout 10\nReceiveTimeout 35\n')
        try:
            cp=subprocess.run(['/usr/bin/freshclam','--config-file='+str(config),'--stdout'],stdin=subprocess.DEVNULL,timeout=100,check=False)
        except (OSError,subprocess.TimeoutExpired):
            print('WAVE13_OFFICIAL_CVD_BLOCKED_ACQUISITION_UNAVAILABLE');return
        if cp.returncode!=0:
            print('WAVE13_OFFICIAL_CVD_BLOCKED_ACQUISITION_EXIT_'+str(cp.returncode));return
        if not all((download/n).is_file() and not (download/n).is_symlink() for n in scan.NAMES):
            print('WAVE13_OFFICIAL_CVD_BLOCKED_INCOMPLETE_CVD_SET');return
        source=root/'pinned';source.mkdir(mode=0o700)
        for n in scan.NAMES:
            if not 512<=(download/n).stat().st_size<=scan.MAX_DB:
                print('WAVE13_OFFICIAL_CVD_BLOCKED_FILE_SIZE');return
            shutil.copyfile(download/n,source/n)
        with (source/'daily.cvd').open('rb') as f:
            header=f.read(512).decode('ascii').rstrip(' \x00\n')
        build=datetime.fromtimestamp(int(header.rsplit(':',1)[-1]),timezone.utc)
        now=datetime.now(timezone.utc)
        m=dict(schema='NARUV_CVD_SNAPSHOT_V1',observed_at=now.isoformat(),daily_build_at=build.isoformat(),files={n:dict(sha256=scan.file_sha(source/n),bytes=(source/n).stat().st_size) for n in scan.NAMES})
        fd=os.open(source,os.O_DIRECTORY|os.O_RDONLY)
        try:
            try:r=scan.review(b'NARUV benign synthetic text fixture',fd=fd,manifest=m,expected_pin=scan.sha(scan.canonical(m)))
            except Blocked as e:
                if str(e)=='CVD_STALE':
                    print('WAVE13_OFFICIAL_CVD_BLOCKED_STALE');return
                raise
            assert r['status']=='NO_DETECTION_REVIEW_ONLY' and r['engine_exit']==0 and r['production_authorized'] is False
            print('WAVE13_OFFICIAL_CVD_ENGINE_REVIEW_PASS '+json.dumps({'daily_build_at':m['daily_build_at'],'files':list(m['files']),'manifest_sha256':r['manifest_sha256'],'independent_production_pin_verified':False,'production_authorized':False}))
        finally:os.close(fd)
if __name__=='__main__':main()
