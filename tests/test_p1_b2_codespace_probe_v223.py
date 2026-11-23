"""No-network B2 v4 native preflight; no owner credentials in CI."""
from copy import deepcopy
from scripts import p1_b2_codespace_probe_v223 as b2

NOW=1795438800000
BUCKET_ID="26ebc8d9725e088ca72e081f"
BUCKET_NAME="naruv-jw-backup-worm-2026"
REGION=b2.EXPECTED_REGION
URL="https://api001.backblazeb2.com"


def env():
    return {"CODESPACES":"true",
            "JW_B2_AUDIT_KEY_ID":"synthetic-id-not-real",
            "JW_B2_AUDIT_APPLICATION_KEY":"synthetic-password-not-real"}


class Native:
    def __init__(self):
        self.calls=[]
        self.authorized = {
            "accountId":"synthetic-account",
            "authorizationToken":"synthetic-transient-token",
            "applicationKeyExpirationTimestamp":NOW+30*86400*1000,
            "apiInfo":{"storageApi":{
                "apiUrl":URL,"s3ApiUrl":REGION,
                "allowed":{"buckets":[{"id":BUCKET_ID,"name":BUCKET_NAME}],
                           "namePrefix":None,
                           "capabilities": sorted(b2.REQUIRED|{"shareFiles"})}}}}
        self.bucket={"buckets":[{
            "bucketId":BUCKET_ID,"bucketName":BUCKET_NAME,
            "bucketType":"allPrivate",
            "fileLockConfiguration":{"isClientAuthorizedToRead":True,
                "value":{"isFileLockEnabled":True,"defaultRetention":{
                    "mode":None,"period":None}}},
            "defaultServerSideEncryption":{"isClientAuthorizedToRead":True,
                "value":{"algorithm":"AES256","mode":"SSE-B2"}},
            "lifecycleRules":[],
        }]}
        self.versions={"files":[],"nextFileName":None,"nextFileId":None}

    def __call__(self,url,headers,body=None):
        self.calls.append(url)
        if url==b2.AUTH:
            assert headers["Authorization"].startswith("Basic ")
            assert "synthetic-password-not-real" not in headers["Authorization"]
            assert body is None
            return deepcopy(self.authorized)
        assert headers["Authorization"]=="synthetic-transient-token"
        if url==URL+"/b2api/v4/b2_list_buckets":
            assert body=={"accountId":"synthetic-account","bucketId":BUCKET_ID}
            return deepcopy(self.bucket)
        if url==URL+"/b2api/v4/b2_list_file_versions":
            assert body=={"bucketId":BUCKET_ID,"maxFileCount":2}
            return deepcopy(self.versions)
        raise AssertionError("unexpected network destination")

def run(e=None,n=None):
    n = n or Native()
    return b2.verify(env=e or env(),fetch=n,now_ms=NOW)

def test_exact_readonly_bucket_and_full_empty_versions():
    native=Native()
    result=run(n=native)
    assert result["b2_owner_bucket_readonly"]=="PASS_REAL_B2_EMPTY_LOCK_ENABLED"
    for name in ("bucket_scope_exactly_one","key_has_no_write_or_delete",
                 "key_expiry_checked","bucket_private","object_lock_enabled",
                 "encryption_sse_b2","keep_all_versions","file_versions_empty"):
        assert result[name] is True, name
    assert result["provider_calls"]==3
    assert result["real_backup_uploads"]==0
    assert result["overall_release"]=="BLOCKED"
    assert result["real_object_retention_proof"]=="NOT_RUN"
    assert result["independent_key_custody"]=="NOT_ATTESTED"
    assert native.calls==[
        b2.AUTH,URL+"/b2api/v4/b2_list_buckets",
        URL+"/b2api/v4/b2_list_file_versions"]
    assert "synthetic-password" not in str(result)
    assert BUCKET_NAME not in str(result) and BUCKET_ID not in str(result)


import pytest


@pytest.mark.parametrize(("field","value","reason"),[
    ("CODESPACES","false","OWNER_CODESPACE_REQUIRED"),
    ("JW_B2_AUDIT_KEY_ID","","CODESPACE_SECRETS_NOT_VISIBLE_RESTART_REQUIRED"),
    ("JW_B2_AUDIT_APPLICATION_KEY","","CODESPACE_SECRETS_NOT_VISIBLE_RESTART_REQUIRED"),
    ("JW_PG_BACKUP_KEY","very_secret","SOURCE_OR_BACKUP_CREDENTIALS_MUST_BE_ISOLATED"),
    ("DATABASE_URL","postgres://secret","SOURCE_OR_BACKUP_CREDENTIALS_MUST_BE_ISOLATED"),
    ("AWS_CA_BUNDLE","/tmp/untrusted-ca.pem","SOURCE_OR_BACKUP_CREDENTIALS_MUST_BE_ISOLATED"),
])
def test_environment_guard_prevents_network(field,value,reason):
    e=env()
    e[field]=value
    n=Native()
    result=run(e=e,n=n)
    assert result["blocker"]==reason
    assert n.calls==[]


@pytest.mark.parametrize(("fault","reason"),[
    ("bad_region","UNEXPECTED_B2_REGION"),
    ("foreign_endpoint","B2_PROVIDER_API_URL_NOT_TRUSTED"),
    ("two_buckets","B2_KEY_MUST_BE_ONE_BUCKET_ONLY"),
    ("full_account","B2_KEY_MUST_BE_ONE_BUCKET_ONLY"),
    ("wrong_name","B2_KEY_BUCKET_IDENTITY_MISMATCH"),
    ("wrong_id","B2_KEY_BUCKET_IDENTITY_MISMATCH"),
    ("prefix","B2_KEY_FILE_PREFIX_UNEXPECTED"),
    ("read_capability_missing","B2_KEY_MISSING_REQUIRED_READ_CAPABILITY"),
    ("write","B2_KEY_EXCESSIVE_PRIVILEGES"),
    ("delete","B2_KEY_EXCESSIVE_PRIVILEGES"),
    ("bypass","B2_KEY_EXCESSIVE_PRIVILEGES"),
    ("list_all","B2_KEY_EXCESSIVE_PRIVILEGES"),
    ("permanent_key","B2_KEY_EXPIRY_NOT_PROVEN_SHORT_LIVED"),
    ("expired_key","B2_KEY_EXPIRY_NOT_PROVEN_SHORT_LIVED"),
])
def test_invalid_key_scope_not_allowed_to_query_bucket(fault,reason):
    n=Native()
    a=n.authorized
    storage=a["apiInfo"]["storageApi"]
    allowed=storage["allowed"]
    if fault=="bad_region":storage["s3ApiUrl"]="https://s3.us-west-004.backblazeb2.com"
    elif fault=="foreign_endpoint":storage["apiUrl"]="https://evil.invalid"
    elif fault=="two_buckets":allowed["buckets"].append({"id":"b"*24,"name":"other"})
    elif fault=="full_account":allowed["buckets"]=[]
    elif fault=="wrong_name":allowed["buckets"][0]["name"]="other-bucket"
    elif fault=="wrong_id":allowed["buckets"][0]["id"]="wrong"
    elif fault=="prefix":allowed["namePrefix"]="only-some-files"
    elif fault=="read_capability_missing":allowed["capabilities"].remove("readBucketRetentions")
    elif fault=="write":allowed["capabilities"].append("writeFiles")
    elif fault=="delete":allowed["capabilities"].append("deleteFiles")
    elif fault=="bypass":allowed["capabilities"].append("bypassGovernance")
    elif fault=="list_all":allowed["capabilities"].append("listAllBucketNames")
    elif fault=="permanent_key":a["applicationKeyExpirationTimestamp"]=None
    elif fault=="expired_key":a["applicationKeyExpirationTimestamp"]=NOW-2000
    r=run(n=n)
    assert r["blocker"]==reason
    assert n.calls==[b2.AUTH]
    assert r["overall_release"]=="BLOCKED"


@pytest.mark.parametrize(("fault","reason"),[
    ("public","B2_BUCKET_IS_NOT_EXPECTED_PRIVATE_BUCKET"),
    ("wrong_id","B2_BUCKET_IS_NOT_EXPECTED_PRIVATE_BUCKET"),
    ("no_lock","B2_OBJECT_LOCK_NOT_ENABLED_OR_UNREADABLE"),
    ("no_lock_right","B2_OBJECT_LOCK_NOT_ENABLED_OR_UNREADABLE"),
    ("default_governance","B2_UNAPPROVED_DEFAULT_RETENTION"),
    ("default_compliance","B2_UNAPPROVED_DEFAULT_RETENTION"),
    ("no_encryption","B2_DEFAULT_ENCRYPTION_NOT_VERIFIED"),
    ("no_encryption_right","B2_DEFAULT_ENCRYPTION_NOT_VERIFIED"),
    ("auto_delete","B2_UNEXPECTED_DELETION_LIFECYCLE"),
])
def test_actual_bucket_settings_fail_closed(fault,reason):
    n=Native()
    v=n.bucket["buckets"][0]
    if fault=="public":v["bucketType"]="allPublic"
    elif fault=="wrong_id":v["bucketId"]="f"*24
    elif fault=="no_lock":v["fileLockConfiguration"]["value"]["isFileLockEnabled"]=False
    elif fault=="no_lock_right":v["fileLockConfiguration"]["isClientAuthorizedToRead"]=False
    elif fault.startswith("default_"):
        v["fileLockConfiguration"]["value"]["defaultRetention"]={"mode":fault.split("_")[1],"period":{"duration":30,"unit":"days"}}
    elif fault=="no_encryption":v["defaultServerSideEncryption"]["value"]["mode"]="none"
    elif fault=="no_encryption_right":v["defaultServerSideEncryption"]["isClientAuthorizedToRead"]=False
    else:v["lifecycleRules"]=[{"daysFromHidingToDeleting":1}]
    r=run(n=n)
    assert r["blocker"]==reason
    assert len(n.calls)==2
    assert r["file_versions_empty"] is False


@pytest.mark.parametrize("fault",["existing_version","hidden_version","truncated_inventory"])
def test_versions_not_empty_or_unverifiable(fault):
    n=Native()
    if fault=="existing_version":n.versions["files"]=[{"action":"upload"}]
    elif fault=="hidden_version":n.versions["files"]=[{"action":"hide"}]
    else:n.versions["nextFileName"]="a-subsequent-file"
    r=run(n=n)
    assert r["blocker"]=="B2_BUCKET_VERSION_INVENTORY_NOT_EMPTY"
    assert r["file_versions_empty"] is False
    assert len(n.calls)==3


def test_no_credentials_in_sanitized_failure():
    def thrower(*a,**kw):
        raise RuntimeError("synthetic-password-not-real leaked")
    r=b2.verify(env=env(),fetch=thrower,now_ms=NOW)
    assert r["blocker"]=="B2_PROVIDER_READ_FAILED_WITHOUT_SECRET_DISCLOSURE"
    assert "synthetic-password" not in str(r)


def test_cli_rejects_write_requests_without_checking_secrets(capsys):
    assert b2.main(["upload"])==2
    assert "USAGE" in capsys.readouterr().err


def test_stdout_never_prints_secrets_on_failed_preflight(monkeypatch,capsys):
    monkeypatch.delenv("JW_B2_AUDIT_KEY_ID",raising=False)
    monkeypatch.delenv("JW_B2_AUDIT_APPLICATION_KEY",raising=False)
    monkeypatch.setenv("CODESPACES","true")
    assert b2.main(["verify-readonly"])==1
    assert "CODESPACE_SECRETS_NOT_VISIBLE_RESTART_REQUIRED" in capsys.readouterr().out
