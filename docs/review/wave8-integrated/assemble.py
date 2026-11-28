"""Materialize already tested Wave5/Wave7 overlays, not a release.
Read only from local Git objects; never fetch, checkout, push or activate CI.
Output a detached overlay directory with updated custody manifest; no input changes.
"""
import hashlib, json, subprocess, sys, tempfile
from pathlib import Path
BASE='386077c311f23d313f60678d3e23692b0e070fbf'
W5='61adef8e3c4baeb9cfb2b1969cea712a14e68749'
W7='99c3ba73ae3803cbc7e3f0495cd524c8536ac482'
MANIFEST='docs/NARUV_V223_SOURCE_RECONCILIATION.json'
BASE_MANIFEST='1b45bf5530e074de90605b8f13c320562538246e'
DRAFT_OUTPUT_SHA256='147271a63cf575d4eb839f49a4066855a91e61d70c7495a6844ba0993cad26a1'
BASE_PINS={'app/naruv_kr_payroll_review.py':'975d18358b050aaf0703599bed3a36e9592e3370','app/erp_migration_xlsx.py':'f96b84e4759cdc8274c2e7098691df3488038ec2','app/naruv_draft_review.py':'929dc07c40e181b1e1176924ae9378d8bb2fdf47'}
W5_PINS={'payroll-statement-candidate.py':'ea4199c46f1e4704d19765f9c32124a407dd3ae4','xlsx-candidate.py':'cbf4b43ba75f9d5d52ef1442e68199741728a895','cleanroom-pipe-candidate.py':'a2162cec7e00bffe85cf341e73639423b91a74c4','incident-evidence.py':'cf9d0a0d3fadff0850d4c98e2bc3e59ed5d59ed7'}
W5_OUTPUTS={'payroll-statement-candidate.py':'723641e7c655866ca04fbd5c72fbf33de1ba1fb0328d338bbe4f90b23c40a164','xlsx-candidate.py':'9d73c0ad86f8e55520f98465027fc2d1ff22461aa2b4b20d748797648b894dde','cleanroom-pipe-candidate.py':'f6df01e31b5eb91d21ff82c314532b6441ac7d669b5bec30b1c9098294818d3d','incident-evidence.py':'3503378cb6d7f17efbed71f86fa00c6b1188efa1a34412e146a9f11863830f6e'}

def oid(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def read(repo,ref,path,pin):
    raw=subprocess.check_output(['git','-C',str(repo),'show',f'{ref}:{path}'])
    if oid(raw)!=pin:raise ValueError('PIN_MISMATCH: '+path)
    return raw

def update_inventory(raw,changes,original_pins=BASE_PINS):
    data=json.loads(raw);old=data['expected_blob_inventory']
    if data['status']!='UNVERIFIED_DETACHED_SOURCE_CANDIDATE_NOT_RELEASE' or set(changes)!=set(original_pins):raise ValueError('MANIFEST_SCOPE')
    for p,pin in original_pins.items():
        if old.get(p,{}).get('sha')!=pin or old[p].get('mode')!='100644':raise ValueError('MANIFEST_PIN: '+p)
        old[p]['sha']=oid(changes[p])
    return (json.dumps(data,indent=2,ensure_ascii=True)+'\n').encode()

def build(repo,out):
    repo=Path(repo).resolve();out=Path(out).resolve()
    if out.is_relative_to(repo) or out.exists():raise ValueError('OUTPUT_MUST_BE_NEW_AND_EXTERNAL')
    manifest=read(repo,BASE,MANIFEST,BASE_MANIFEST)
    inputs={p:read(repo,BASE,p,h) for p,h in BASE_PINS.items()}
    with tempfile.TemporaryDirectory(prefix='naruv-assembly-') as d:
        t=Path(d);s=t/'wave2';s.mkdir();c=t/'generated'
        for p,h in W5_PINS.items():(s/p).write_bytes(read(repo,W5,'docs/review/p0-p3-wave2/'+p,h))
        b=t/'build.py';b.write_bytes(read(repo,W5,'docs/review/p0-p3-wave5/build.py','328cea10578cec4a38a36c7fede355bb4d79c8d6'))
        hr=t/'build_hr_overlay.py';hr.write_bytes(read(repo,W7,'docs/review/wave7-integrated/build_hr_overlay.py','9e765f3b0149701cbc02a76a60a31c16d9ff866c'))
        subprocess.run([sys.executable,'-I',str(b),str(s),str(c)],check=True,timeout=30)
        for p,h in W5_OUTPUTS.items():
            if hashlib.sha256((c/p).read_bytes()).hexdigest()!=h:raise ValueError('TESTED_OUTPUT_MISMATCH: '+p)
        orig=t/'original.py';orig.write_bytes(inputs['app/naruv_draft_review.py']);dst=t/'draft.py'
        subprocess.run([sys.executable,'-I',str(hr),str(orig),str(dst)],check=True,timeout=30)
        if hashlib.sha256(dst.read_bytes()).hexdigest()!=DRAFT_OUTPUT_SHA256:raise ValueError('HR_TESTED_OUTPUT_MISMATCH')
        changes={'app/naruv_kr_payroll_review.py':(c/'payroll-statement-candidate.py').read_bytes(),'app/erp_migration_xlsx.py':(c/'xlsx-candidate.py').read_bytes(),'app/naruv_draft_review.py':dst.read_bytes()}
    for p,raw in changes.items():compile(raw,p,'exec')
    changes[MANIFEST]=update_inventory(manifest,changes)
    out.mkdir(parents=True,exist_ok=False)
    for p,raw in changes.items():
        target=out/p;target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as f:f.write(raw)
    receipt={'status':'OVERLAYS_MATERIALIZED_NOT_RETESTED_OR_RELEASED','base':BASE,'wave5':W5,'wave7':W7,'files':{p:{'git_blob':oid(b),'sha256':hashlib.sha256(b).hexdigest()} for p,b in changes.items()},'production_authorized':False,'external_recovery_script_excluded':True}
    (out/'assembly-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt
if __name__=='__main__':print(json.dumps(build(*sys.argv[1:]),indent=2))
