"""Strict private staging of CVD/sign pairs and separately pinned cert files.
Trusted verifier/runner adapters are mandatory. Results never authorize production.
No network or automatic update. Current acquisition remains a separate task.
"""
import os,stat,hashlib,hmac,json,tempfile,re
from datetime import datetime,timezone
from pathlib import Path
from review_gates import need,digest,Blocked
from cvd_diagnostics import NAMES,check_pairs,diagnose

def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def pin(doc):return hashlib.sha256(json.dumps(doc,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()).hexdigest()

def stage(fd,dest,entries):
    st=os.fstat(fd);need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==0o700,'CVD_STAGE_DIRECTORY')
    need(set(os.listdir(fd))==set(entries),'CVD_STAGE_SET')
    for name,meta in entries.items():
        f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
        with os.fdopen(f,'rb') as src,(dest/name).open('xb') as out:
            s=os.fstat(src.fileno());need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==meta['bytes'],'CVD_STAGE_FILE')
            count=0;h=hashlib.sha256()
            while True:
                b=src.read(1024*1024)
                if not b:break
                count+=len(b);need(count<=meta['bytes'],'CVD_STAGE_SIZE');h.update(b);out.write(b)
            need(count==meta['bytes'] and hmac.compare_digest(h.hexdigest(),meta['sha256']),'CVD_STAGE_HASH')
            out.flush();os.fsync(out.fileno())
        (dest/name).chmod(0o400)

def unchanged(d,entries):
    need(set(p.name for p in d.iterdir())==set(entries),'CVD_STAGE_CHANGED')
    for name,r in entries.items():
        p=d/name;need(not p.is_symlink() and p.is_file() and p.stat().st_size==r['bytes'] and hmac.compare_digest(sha(p),r['sha256']),'CVD_STAGE_CHANGED')

def review(raw,*,db_fd,cert_fd,manifest,expected_pin,certs,expected_cert_pin,observed_at,advertised_version,previous_verified_version,engine_level,verify,run):
    need(type(raw) is bytes and 0<len(raw)<=2*1024*1024,'CVD_INPUT')
    need(all(type(v) is int and 0<v<=2**32-1 for v in (advertised_version,previous_verified_version,engine_level)),'CVD_INDEPENDENT_REFERENCE_REQUIRED')
    # Snapshot manifests before doing IO. Pin versions and trust independently.
    m=json.loads(json.dumps(manifest,allow_nan=False));c=json.loads(json.dumps(certs,allow_nan=False))
    need(digest(expected_pin) and check_pairs(m)==expected_pin,'CVD_PAIR_PIN')
    need(type(c) is dict and 1<=len(c)<=32 and digest(expected_cert_pin) and pin(c)==expected_cert_pin,'CVD_CERT_PIN')
    for n,x in c.items():
        need(type(n) is str and re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}',n) and type(x) is dict and set(x)=={'sha256','bytes'} and digest(x['sha256']) and type(x['bytes']) is int and 1<=x['bytes']<=65536,'CVD_CERT_ENTRY')
    try:
        with tempfile.TemporaryDirectory(prefix='naruv-cvd-v2-') as t:
            p=Path(t);db=p/'db';cert=p/'cert';db.mkdir(mode=0o700);cert.mkdir(mode=0o700)
            stage(db_fd,db,m);stage(cert_fd,cert,c)
            with (db/'daily.cvd').open('rb') as f:header=f.read(512)
            def fresh():
                return diagnose(header=header,now=datetime.now(timezone.utc),observed_at=observed_at,advertised_version=advertised_version,previous_verified_version=previous_verified_version,engine_level=engine_level)
            d=fresh();need(d['status']=='HEADER_MATCH_ONLY','CVD_FRESHNESS:'+','.join(d['reasons']))
            for name in NAMES:
                need(verify(db/name,cert) is True,'CVD_DETACHED_VERIFY_FAILED')
            unchanged(db,m);unchanged(cert,c)
            sample=p/'sample';sample.write_bytes(raw);sample.chmod(0o400)
            rc=run(db,cert,sample);need(type(rc) is int and rc in (0,1),'CVD_ENGINE_ERROR')
            unchanged(db,m);unchanged(cert,c);need(not sample.is_symlink() and sample.is_file() and sha(sample)==hashlib.sha256(raw).hexdigest(),'CVD_SAMPLE_CHANGED')
            d=fresh();need(d['status']=='HEADER_MATCH_ONLY','CVD_FRESHNESS:'+','.join(d['reasons']))
            return dict(status='NO_DETECTION_REVIEW_ONLY' if rc==0 else 'DETECTED_REVIEW_ONLY',version=d['version'],build_at=d['build_at'],input_sha256=hashlib.sha256(raw).hexdigest(),manifest_sha256=expected_pin,cert_manifest_sha256=expected_cert_pin,engine_exit=rc,adapter_independence_attested=False,production_authorized=False,malware_free_guaranteed=False)
    except OSError:raise Blocked('CVD_STORAGE_UNAVAILABLE') from None
