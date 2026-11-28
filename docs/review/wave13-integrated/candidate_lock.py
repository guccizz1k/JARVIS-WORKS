"""Exact Wave11+12 review module materialization from local Git objects, no fetch.
Not an application release, no changes to original repo, no execution of copied files.
"""
import hashlib,json,subprocess,sys,tempfile,os
from pathlib import Path,PurePosixPath
BASE='ba6dabce733c8059c08debdc0dcd54ea210d0237'
PINS={
'wave11-integrated/handoff.py':'a278117363ab3d6fc24cb4836d43a4b630865fc3',
'wave11-integrated/id_candidate.py':'b2468a989b90b1c727bf768738e2c1e762812e8f',
'wave11-integrated/isolated_document.py':'69e3eca5f06fb7fedf8e7a34f43e4b80ad3b3263',
'wave11-integrated/isolated_worker.py':'23438d0fddb37f15e93d1257be5a2edd17c95a5a',
'wave11-integrated/korean_observations.py':'83a863e61e160d854719b94811fb084df3cc0355',
'wave11-integrated/local_queue_store.py':'2970965fab8d10b93b223b96c0b0a09c25a7b974',
'wave11-integrated/network_fence.py':'36775793baa6e327aa61e0709998d5087a0fde9f',
'wave11-integrated/ocr_id_views.py':'a10225db246953ec2ead9da85b36e103c06e3fce',
'wave11-integrated/payroll_receipts_ci.sql':'a3d6175ef7bc40dd3d15fe7f1d4721394b05be00',
'wave11-integrated/pg_receipt_adapter.py':'d64f2ba63b98574ea458316ca06761e686208c43',
'wave11-integrated/pinned/naruv_document_review.py':'8b1701e62235752c1130ee27bca869f50002d4f2',
'wave11-integrated/pinned/naruv_recovery_custody_review.py':'6aafed77f21a775cf9b478035d3b77ed2a8b31bd',
'wave11-integrated/queue_bridge.py':'0912d70dd2ce40b7117156e7b3abcfc602968244',
'wave11-integrated/queue_result.py':'f161f7fb101db98284081f1cbcc5592d00dd47f4',
'wave11-integrated/queue_schema_ci.sql':'80acdc7930a4020840b32f06b33d73ed40114e13',
'wave11-integrated/review_gates.py':'293217dffcf17bffd2ca26ecec8922edf6a391bd',
'wave11-integrated/test_wave11_db.py':'d928cf2464f333691ef96adf7e7b8b155c8c28f5',
'wave12-integrated/clamav_fixture_scan.py':'f5ba9c3df2e6c455434c7a830a39a19938c978ae',
'wave12-integrated/combined_recovery.py':'1b4ed1d60ccf049a0b7e39a627a04c74aa4bc108',
'wave12-integrated/load_evidence.py':'e46c1c2cd44f6a27c740ce010b086af348a25f6b',
'wave12-integrated/policy_approval.py':'537bc61dbba433f8a6f856c20734b0791a1600ed',
'wave12-integrated/prospective_acl.py':'c66917848c022a305492dd1bcf5bd5f1abd56a28',
'wave12-integrated/queue_integrity.py':'faf84065232a2f16936d4875448313d36243bd5f',
'wave12-integrated/queue_result_digest_ci.sql':'67cc625fc7f2ac141f3e1c76d4992f43787a64a9',
'wave12-integrated/receipt_api.py':'430d31304741b6c7da88aa050fa00e4f3537e6be',
'wave12-integrated/test_wave12_real.py':'256c8001963652fb32e8966b645642461fd9614a'}

def oid(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def build(repo,out,*,ref=BASE,pins=None):
    repo=Path(repo).resolve();out=Path(out).resolve();pins=PINS if pins is None else pins
    if out.exists() or out.is_relative_to(repo) or repo.is_relative_to(out):raise ValueError('OUTPUT_SCOPE')
    if not out.parent.is_dir():raise ValueError('OUTPUT_PARENT')
    def git(*args):return subprocess.check_output(['git','-C',str(repo),*args],timeout=10,stderr=subprocess.DEVNULL)
    if git('rev-parse',ref+'^{commit}').decode().strip()!=ref:raise ValueError('COMMIT_PIN')
    prefix='docs/review/';data={};receipt={}
    for rel,h in pins.items():
        path=PurePosixPath(rel)
        if path.is_absolute() or '..' in path.parts or str(path)!=rel or not rel.startswith(('wave11-integrated/','wave12-integrated/')):raise ValueError('PATH_SCOPE')
        full=prefix+rel
        entry=git('ls-tree',ref,'--',full).decode().strip().split('\t')
        if entry!=['100644 blob '+h,full]:raise ValueError('TREE_PIN:'+rel)
        b=git('show',ref+':'+full)
        if oid(b)!=h:raise ValueError('BLOB_PIN:'+rel)
        if rel.endswith('.py'):compile(b,rel,'exec')
        data[rel]=b;receipt[rel]={'git_blob':h,'sha256':hashlib.sha256(b).hexdigest()}
    # Check all bytes before publishing anything. No partial external tree on pin failure.
    with tempfile.TemporaryDirectory(dir=out.parent,prefix='naruv-lock-') as t:
        stage=Path(t)/'bundle';stage.mkdir()
        for rel,b in data.items():
            dest=stage/rel;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(b)
        result=dict(status='PINNED_REVIEW_BUNDLE_ONLY',commit=ref,files=receipt,production_authorized=False)
        (stage/'receipt.json').write_text(json.dumps(result,indent=2)+'\n')
        # Atomic publication to a new output; parent must be trusted, exclusive caller.
        if out.exists():raise ValueError('OUTPUT_EXISTS')
        os.rename(stage,out)
    return result
if __name__=='__main__':print(json.dumps(build(*sys.argv[1:]),indent=2))
