"""One-shot upload orchestration for disposable transport tests only.
No provider credentials or production adapter are accepted by this module.
Historical backup scripts remain immutable; do not run them for new batches.
"""
import hashlib, json, os, re
from pathlib import Path
from .naruv_b2_upload_policy import upload_policy_plan, verify_uploaded_metadata
from .naruv_b2_retention_journal import need

class DisposableB2:
    """In-memory provider model, never network IO."""
    def __init__(self,bucket_id,clock):
        self.bucket_id=bucket_id;self.clock=clock;self.files={};self.calls=0
    def upload(self,name,raw,until):
        self.calls+=1
        need(name not in self.files,"DUPLICATE_UPLOAD")
        fid="fixture-"+hashlib.sha256(name.encode()).hexdigest()
        info=dict(bucketId=self.bucket_id,fileName=name,fileId=fid,contentLength=len(raw),
            contentSha1=hashlib.sha1(raw).hexdigest(),action="upload",uploadTimestamp=self.clock(),
            fileRetention={"isClientAuthorizedToRead":True,"value":{"mode":"compliance","retainUntilTimestamp":until}},
            serverSideEncryption={"mode":"SSE-B2","algorithm":"AES256"})
        self.files[name]=(info,raw)
        return dict(info)
    def read_info(self,name):
        import copy
        return copy.deepcopy(self.files[name][0])
    def read_bytes(self,name):
        return self.files[name][1]

def execute_fixture_upload(*,provider,clock,journal,scope,raw,expected_sha256,
        max_upload_ms,max_clock_skew_ms,approved_until_ms):
    """Exercise the full upload/ack/readback protocol with durable no-retry receipt.
    Any failure after attempt is ambiguous; retain the journal for reconciliation.
    No live provider can be passed through this entry point.
    """
    need(type(provider) is DisposableB2,"DISPOSABLE_PROVIDER_ONLY")
    need(type(scope) is dict and set(scope)=={"bucket_id","name"}
        and scope["bucket_id"]==provider.bucket_id and type(scope["bucket_id"]) is str
        and type(scope["name"]) is str and re.fullmatch(r"synthetic/[a-zA-Z0-9_-]{1,80}\.jwpgbk",scope["name"]),"FIXTURE_SCOPE")
    need(type(raw) is bytes and 0<len(raw)<=1024*1024 and type(expected_sha256) is str
        and hashlib.sha256(raw).hexdigest()==expected_sha256,"FIXTURE_DIGEST")
    name=scope["name"]
    need(name not in provider.files,"EXISTING_VERSION_NO_RETRY")
    plan=upload_policy_plan(planned_at_ms=clock(),max_upload_ms=max_upload_ms,
        max_clock_skew_ms=max_clock_skew_ms,approved_until_ms=approved_until_ms)
    path=Path(journal)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"w") as f:
        def record(stage,**data):
            f.write(json.dumps(dict(stage=stage,**data),sort_keys=True)+"\n");f.flush();os.fsync(f.fileno())
        record("attempt",scope=scope,sha256=expected_sha256,plan=plan)
        d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(d)
        finally:os.close(d)
        ack=provider.upload(name,raw,plan["retain_until_ms"])
        fid=ack.get("fileId")
        expected=dict(bucketId=scope["bucket_id"],fileName=name,fileId=fid,
            contentLength=len(raw),contentSha1=hashlib.sha1(raw).hexdigest())
        need(type(fid) is str and bool(fid) and all(ack.get(k)==v for k,v in expected.items()),"UPLOAD_ACK")
        record("ack",file_id=fid)
        info=provider.read_info(name)
        review=verify_uploaded_metadata(plan=plan,expected=expected,info=info,now_ms=clock())
        got=provider.read_bytes(name)
        need(type(got) is bytes and got==raw and hashlib.sha256(got).hexdigest()==expected_sha256,"READBACK_MISMATCH")
        record("verified",file_id=fid,sha256=expected_sha256,retain_until_ms=plan["retain_until_ms"])
        record("complete",verified=1)
    return dict(review,status="DISPOSABLE_UPLOAD_READBACK_PASS",fixture_ciphertext_verified=True,
        remote_write=False,production_authorized=False)
