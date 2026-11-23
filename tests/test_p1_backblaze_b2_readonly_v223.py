"""Offline provider-contract tests: no real Backblaze credentials or network."""
from __future__ import annotations
from copy import deepcopy
from types import SimpleNamespace
import pytest
from scripts import p1_backblaze_b2_readonly_v223 as b2

NOW = 1795438800000
BUCKET = "fake-b2-private-audit-2026"
BUCKET_ID = "4a48fe8875c6214145260818"
EP = "https://s3.us-east-005.backblazeb2.com"
API = "https://api001.backblazeb2.com"
CAPS = sorted(b2.REQUIRED_READ | {"shareFiles"})


class FakeS3:
    def __init__(self):
        self.meta = SimpleNamespace(endpoint_url=EP)
        self.calls = []
        self.version = "Enabled"
        self.lock = "Enabled"
        self.default_lock = None
        self.objects = []
        self.delete_markers = []
        self.truncated = False

    def get_bucket_versioning(self, **kwargs):
        self.calls.append("get_bucket_versioning")
        return {"Status": self.version}

    def get_object_lock_configuration(self, **kwargs):
        self.calls.append("get_object_lock_configuration")
        rule = {"DefaultRetention": {"Mode": self.default_lock, "Days":30}} if self.default_lock else None
        return {"ObjectLockConfiguration": {
            "ObjectLockEnabled": self.lock,
            **({"Rule": rule} if rule else {}),
        }}

    def list_object_versions(self, **kwargs):
        self.calls.append("list_object_versions")
        assert kwargs == {"Bucket":BUCKET,"MaxKeys":2}
        return {"IsTruncated":self.truncated,
                "Versions":self.objects, "DeleteMarkers":self.delete_markers}


class FakeNative:
    def __init__(self):
        self.calls = []
        self.auth = {
            "accountId":"fake_account",
            "authorizationToken":"fake_token",
            "applicationKeyExpirationTimestamp":NOW+30*86400000,
            "apiInfo":{"storageApi":{
                "apiUrl":API,
                "s3ApiUrl":EP,
                "allowed":{"buckets":[{"id":BUCKET_ID,"name":BUCKET}],
                           "capabilities":CAPS,"namePrefix":None},
            }},
        }
        self.bucket = {"buckets":[{
            "bucketId":BUCKET_ID,"bucketName":BUCKET,"bucketType":"allPrivate",
            "fileLockConfiguration":{
                "isClientAuthorizedToRead":True,
                "value":{"isFileLockEnabled":True,
                         "defaultRetention":{"mode":None,"period":None}}},
            "defaultServerSideEncryption":{
                "isClientAuthorizedToRead":True,
                "value":{"mode":"SSE-B2","algorithm":"AES256"}},
            "lifecycleRules":[],
        }]}

    def __call__(self,url,headers,body=None):
        self.calls.append(url)
        assert url in (b2.AUTH_URL,API+"/b2api/v4/b2_list_buckets")
        if url == b2.AUTH_URL:
            assert headers["Authorization"].startswith("Basic ")
            return deepcopy(self.auth)
        assert headers["Authorization"] == "fake_token"
        import json
        assert json.loads(body) == {"accountId":"fake_account","bucketId":BUCKET_ID}
        return deepcopy(self.bucket)


def settings():
    return {"JW_B2_AUDIT_ACK":b2.ACK,
            "JW_B2_AUDIT_KEY_ID":"synthetic_key_id",
            "JW_B2_AUDIT_APPLICATION_KEY":"synthetic_secret",
            "JW_B2_AUDIT_BUCKET":BUCKET,
            "JW_B2_AUDIT_BUCKET_ID":BUCKET_ID,
            "JW_B2_AUDIT_ENDPOINT":EP}


def execute(env=None,native=None,s3=None):
    native = native or FakeNative()
    s3 = s3 or FakeS3()
    return b2.verify(env=env or settings(),transport=native,s3=s3,now_ms=NOW)


def test_exact_bucket_only_readiness_no_provider_mutation():
    native=FakeNative()
    s3=FakeS3()
    r=execute(native=native,s3=s3)
    assert r["b2_readiness"]=="PASS_EMPTY_PRIVATE_B2_BUCKET_READ_ONLY"
    assert r["read_only_scope_attested"] is True
    assert r["provider_private_bucket_attested"] is True
    assert r["object_lock_enabled_attested"] is True
    assert r["sse_b2_enabled_attested"] is True
    assert r["empty_bucket_version_listing_attested"] is True
    assert r["owner_key_short_lived"] is True
    assert r["extra_share_files_capability"] is True
    assert r["actual_11_archives_uploaded"] is False
    assert r["overall"]=="BLOCKED"
    assert r["provider_data_mutated"] is False
    assert r["ciphertext_or_key_exfiltrated"] is False
    assert len(native.calls)==2
    assert s3.calls==["get_bucket_versioning","get_object_lock_configuration",
                     "list_object_versions"]
    assert BUCKET not in str(r) and "synthetic_secret" not in str(r)


@pytest.mark.parametrize(("key","value","reason"),[
    ("JW_B2_AUDIT_ACK","","EXPLICIT_READ_ONLY_APPROVAL_REQUIRED"),
    ("JW_B2_AUDIT_KEY_ID","","B2_READ_ONLY_CREDENTIALS_NOT_CONNECTED"),
    ("JW_B2_AUDIT_APPLICATION_KEY","","B2_READ_ONLY_CREDENTIALS_NOT_CONNECTED"),
    ("JW_B2_AUDIT_BUCKET","wrong/bucket","OWNER_BUCKET_NAME_REQUIRED"),
    ("JW_B2_AUDIT_BUCKET_ID","invalid","OWNER_BUCKET_ID_REQUIRED"),
    ("JW_B2_AUDIT_ENDPOINT","https://s3.amazonaws.com",
     "PINNED_B2_S3_ENDPOINT_REQUIRED"),
    ("AWS_ENDPOINT_URL","https://evil.example","UNTRUSTED_ENDPOINT_OR_CA_OVERRIDE"),
    ("AWS_CA_BUNDLE","/tmp/attacker.pem","UNTRUSTED_ENDPOINT_OR_CA_OVERRIDE"),
    ("JW_PG_BACKUP_KEY","owner-secret","SOURCE_OR_BACKUP_SECRET_NOT_ISOLATED"),
    ("DATABASE_URL","postgres://owner-secret","SOURCE_OR_BACKUP_SECRET_NOT_ISOLATED"),
])
def test_preflight_missing_consent_credentials_scope_or_isolation_no_network(
        key,value,reason):
    env=settings()
    env[key]=value
    native=FakeNative()
    s3=FakeS3()
    r=execute(env=env,native=native,s3=s3)
    assert r["blocker"]==reason
    assert native.calls==[] and s3.calls==[]


@pytest.mark.parametrize(("modify","reason"),[
    ("region","B2_AUTH_REGION_ENDPOINT_MISMATCH"),
    ("api_url","B2_NATIVE_ENDPOINT_UNTRUSTED"),
    ("other_bucket","B2_KEY_WRONG_BUCKET_SCOPE"),
    ("two_buckets","B2_KEY_NOT_RESTRICTED_TO_ONE_BUCKET"),
    ("full_account","B2_KEY_NOT_RESTRICTED_TO_ONE_BUCKET"),
    ("prefix","B2_KEY_HAS_UNEXPECTED_PREFIX"),
    ("too_much_power","B2_KEY_HAS_EXCESSIVE_MUTATION_PERMISSIONS"),
    ("delete_power","B2_KEY_HAS_EXCESSIVE_MUTATION_PERMISSIONS"),
    ("read_retention_missing","B2_REQUIRED_READ_CAPABILITY_MISSING"),
    ("expired","B2_KEY_EXPIRY_NOT_SHORT_LIVED"),
    ("permanent_key","B2_KEY_EXPIRY_NOT_SHORT_LIVED"),
])
def test_native_key_capabilities_fail_closed_before_s3(modify,reason):
    native=FakeNative()
    allowed=native.auth["apiInfo"]["storageApi"]["allowed"]
    if modify=="region":native.auth["apiInfo"]["storageApi"]["s3ApiUrl"]="https://s3.us-west-004.backblazeb2.com"
    elif modify=="api_url":native.auth["apiInfo"]["storageApi"]["apiUrl"]="https://evil.invalid"
    elif modify=="other_bucket":allowed["buckets"][0]["id"]="a"*24
    elif modify=="two_buckets":allowed["buckets"].append({"id":"b"*24,"name":"other"})
    elif modify=="full_account":allowed["buckets"]=[]
    elif modify=="prefix":allowed["namePrefix"]="other-secret-prefix"
    elif modify=="too_much_power":allowed["capabilities"]=CAPS+["writeFiles"]
    elif modify=="delete_power":allowed["capabilities"]=CAPS+["deleteFiles"]
    elif modify=="read_retention_missing":allowed["capabilities"]=[x for x in CAPS if x!="readFileRetentions"]
    elif modify=="expired":native.auth["applicationKeyExpirationTimestamp"]=NOW-1
    else:native.auth["applicationKeyExpirationTimestamp"]=None
    s3=FakeS3()
    r=execute(native=native,s3=s3)
    assert r["blocker"]==reason
    assert s3.calls==[]
    assert r["overall"]=="BLOCKED"


@pytest.mark.parametrize(("change","reason"),[
    ("public","B2_BUCKET_NOT_THE_EXPECTED_PRIVATE_BUCKET"),
    ("wrong_id","B2_BUCKET_NOT_THE_EXPECTED_PRIVATE_BUCKET"),
    ("not_lockable","B2_OBJECT_LOCK_NOT_ENABLED_OR_NOT_READABLE"),
    ("lock_unreadable","B2_OBJECT_LOCK_NOT_ENABLED_OR_NOT_READABLE"),
    ("default_governance","B2_UNAPPROVED_DEFAULT_RETENTION_SETTING"),
    ("encryption_off","B2_DEFAULT_ENCRYPTION_NOT_SSE_B2"),
    ("encryption_unreadable","B2_DEFAULT_ENCRYPTION_NOT_SSE_B2"),
    ("auto_delete","B2_UNEXPECTED_AUTOMATIC_DELETION_RULES"),
])
def test_native_bucket_policy_or_drift_blocks_without_s3(change,reason):
    native=FakeNative()
    bucket=native.bucket["buckets"][0]
    if change=="public":bucket["bucketType"]="allPublic"
    elif change=="wrong_id":bucket["bucketId"]="f"*24
    elif change=="not_lockable":bucket["fileLockConfiguration"]["value"]["isFileLockEnabled"]=False
    elif change=="lock_unreadable":bucket["fileLockConfiguration"]["isClientAuthorizedToRead"]=False
    elif change=="default_governance":bucket["fileLockConfiguration"]["value"]["defaultRetention"]={"mode":"governance","period":{"duration":30,"unit":"days"}}
    elif change=="encryption_off":bucket["defaultServerSideEncryption"]["value"]["mode"]="none"
    elif change=="encryption_unreadable":bucket["defaultServerSideEncryption"]["isClientAuthorizedToRead"]=False
    elif change=="auto_delete":bucket["lifecycleRules"]=[{"daysFromHidingToDeleting":1}]
    s3=FakeS3()
    r=execute(native=native,s3=s3)
    assert r["blocker"]==reason
    assert s3.calls==[]


@pytest.mark.parametrize(("field","value","reason"),[
    ("version","Suspended","B2_S3_VERSIONING_NOT_ENABLED"),
    ("lock","Disabled","B2_S3_OBJECT_LOCK_NOT_ENABLED"),
    ("default_lock","GOVERNANCE","B2_S3_UNAPPROVED_DEFAULT_RETENTION"),
    ("objects",[{"Key":"unverified"}],"B2_BUCKET_NOT_EMPTY_REQUIRES_DIFFERENTIAL_REVIEW"),
    ("delete_markers",[{"Key":"hidden"}],"B2_BUCKET_NOT_EMPTY_REQUIRES_DIFFERENTIAL_REVIEW"),
    ("truncated",True,"B2_S3_OBJECT_VERSION_LIST_INCOMPLETE"),
])
def test_s3_provider_lock_and_empty_versioning_fail_closed(field,value,reason):
    s3=FakeS3()
    setattr(s3,field,value)
    r=execute(s3=s3)
    assert r["blocker"]==reason
    assert r["empty_bucket_version_listing_attested"] is False


def test_fake_s3_endpoint_rejected_without_content_reads():
    s3=FakeS3()
    s3.meta.endpoint_url="https://s3.evil.invalid"
    r=execute(s3=s3)
    assert r["blocker"]=="B2_S3_CLIENT_ENDPOINT_MISMATCH"
    assert s3.calls==[]


def test_native_errors_and_secrets_scrubbed():
    def unsafe_transport(*args,**kwargs):
        raise RuntimeError("fake-secret-should-not-leak")
    r=b2.verify(env=settings(),transport=unsafe_transport,s3=FakeS3(),now_ms=NOW)
    assert r["blocker"]=="B2_EXTERNAL_READ_FAILED"
    assert "fake-secret" not in str(r)


def test_cli_fails_closed_without_live_key(monkeypatch,capsys):
    monkeypatch.delenv("JW_B2_AUDIT_ACK",raising=False)
    assert b2.main([])==2
    assert b2.main(["verify-readonly-empty"])==1
    assert "BLOCKED" in capsys.readouterr().out
