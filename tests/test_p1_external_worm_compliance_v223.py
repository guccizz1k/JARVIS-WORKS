"""Synthetic-only S3 Compliance retention readback and adversarial guard tests."""
import hashlib
import io
import json
import os
import struct
from datetime import datetime,timedelta,timezone
from types import SimpleNamespace
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scripts import p1_external_worm_compliance_v223 as worm

NOW=datetime(2026,11,23,11,0,tzinfo=timezone.utc)
OWNER="123456789012"
BUCKET="isolated-test-only-worm-lock"
PIN="b"*40

class FakeS3:
    def __init__(self, objects):
        self.objects=objects
        self.meta=SimpleNamespace(endpoint_url="https://s3.ap-northeast-2.amazonaws.com")
        self.governance=self.expired=self.changed_latest=self.tampered=None
        self.public_blocked=True
        self.versioning="Enabled"
        self.default_mode="COMPLIANCE"
        self.calls=0

    def _entry(self, keyword):
        self.calls+=1
        for obj in self.objects:
            if (obj["object_key"]==keyword["Key"] and
                    obj["version_id"]==keyword.get("VersionId",obj["version_id"])):
                return obj
        raise KeyError("unknown synthetic object")

    def get_bucket_versioning(self, **kwargs):
        return {"Status":self.versioning}

    def get_object_lock_configuration(self, **kwargs):
        return {"ObjectLockConfiguration":{
            "ObjectLockEnabled":"Enabled",
            "Rule":{"DefaultRetention":{"Mode":self.default_mode,"Days":90}}}}

    def get_public_access_block(self, **kwargs):
        return {"PublicAccessBlockConfiguration":{
            "BlockPublicAcls":True,"IgnorePublicAcls":True,
            "BlockPublicPolicy":True,"RestrictPublicBuckets":self.public_blocked}}

    def get_object_retention(self, **kwargs):
        o=self._entry(kwargs)
        return {"Retention":{
            "Mode":"GOVERNANCE" if o["blob_sha1"]==self.governance else "COMPLIANCE",
            "RetainUntilDate":NOW+timedelta(days=2 if o["blob_sha1"]==self.expired else 90)}}

    def head_object(self, **kwargs):
        o=self._entry(kwargs)
        new_version=o["version_id"]
        if kwargs.get("VersionId") is None and o["blob_sha1"]==self.changed_latest:
            new_version="changed-newer"
        return {"ContentLength":len(o["_bytes"]),"VersionId":new_version}

    def get_object(self, **kwargs):
        o=self._entry(kwargs)
        raw=o["_bytes"]
        if o["blob_sha1"]==self.tampered:
            raw=raw[:-1]+bytes((raw[-1]^1,))
        return {"VersionId":o["version_id"],"ContentLength":len(raw),
                "Body":io.BytesIO(raw)}

class FakeSTS:
    def __init__(self,account=OWNER):
        self.account=account
        self.meta=SimpleNamespace(endpoint_url="https://sts.ap-northeast-2.amazonaws.com")
    def get_caller_identity(self):
        return {"Account":self.account}


def fixture(monkeypatch):
    key=b"Q"*32
    objects=[]
    for i in range(11):
        prefix=(i+1).to_bytes(8,"big")
        payload=b"PGDMP"+bytes([i])*300
        cipher=AESGCM(key).encrypt(prefix+struct.pack(">I",0),payload,
                                    b"JWPGBK2\n"+struct.pack(">QB",0,1))
        raw=b"JWPGBK2\n"+prefix+struct.pack(">I",len(cipher))+cipher
        blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
        objects.append({"blob_sha1":blob,
                        "cipher_sha256":hashlib.sha256(raw).hexdigest(),
                        "object_key":f"v223/archive_{i:02}.jwpgbk",
                        "version_id":f"immutable-version-{i:02}","_bytes":raw})
    monkeypatch.setattr(worm.vault,"_head_tree",lambda _:set(
        o["blob_sha1"] for o in objects))
    # Independently pinned original provider object content, *not* the S3
    # fixture's mutable version. A forged manifest cannot rewrite this view.
    source_objects={o["blob_sha1"]:o["_bytes"] for o in objects}
    def read_pinned_blob(blob,digest):
        original=source_objects[blob]
        if (hashlib.sha1(b"blob "+str(len(original)).encode()+b"\0"+original).hexdigest()!=blob
                or hashlib.sha256(original).hexdigest()!=digest):
            raise worm.vault.Blocked("REMOTE_CIPHER_HASH_MISMATCH")
        return original
    monkeypatch.setattr(worm.vault,"_download",read_pinned_blob)
    env={"JW_WORM_AUDIT_ACK":worm.ACK,
         "JW_WORM_EXPECTED_AWS_ACCOUNT":OWNER,
         "JW_WORM_BUCKET":BUCKET,"JW_WORM_VAULT_SHA":PIN,
         "JW_WORM_MIN_UNTIL":(NOW+timedelta(days=30)).isoformat()}
    manifest={"vault_commit_sha1":PIN,
              "objects":[{k:v for k,v in obj.items() if k!="_bytes"}
                         for obj in objects]}
    return env,objects,manifest,FakeS3(objects)


def audit(env,manifest,s3,sts=None):
    read,write=os.pipe()
    try:
        os.write(write,json.dumps(manifest).encode())
        os.close(write)
        write=-1
        return worm.verify(s3=s3,sts=sts or FakeSTS(),now=NOW,
                           env={**env,"JW_WORM_MANIFEST_FD":str(read)})
    finally:
        os.close(read)
        if write!=-1:os.close(write)


def test_eleven_exact_object_versions_read_and_hash_verified(monkeypatch):
    env,objects,manifest,s3=fixture(monkeypatch)
    r=audit(env,manifest,s3)
    assert r["worm_readonly_audit"]=="PASS_ELEVEN_S3_COMPLIANCE_VERSIONS"
    assert r["compliance_version_count"]==11
    assert r["actual_sha256_readback_count"]==11
    assert r["private_vault_tree_verified"] is True
    assert r["private_vault_cipher_verified_count"]==11
    assert r["decrypted_data_read"] is False
    assert r["ciphertext_or_key_exported"] is False
    assert r["overall"]=="BLOCKED"
    assert r["independent_recovery_key_custody"]=="NOT_ATTESTED"
    assert BUCKET not in str(r)
    assert objects[0]["object_key"] not in str(r)


@pytest.mark.parametrize(("field","reason"),[
    ("governance","OBJECT_VERSION_NOT_IN_COMPLIANCE_MODE"),
    ("expired","OBJECT_VERSION_RETENTION_TOO_SHORT"),
    ("changed_latest","PINNED_OBJECT_VERSION_NOT_CURRENT"),
    ("tampered","S3_CIPHERTEXT_SHA256_OR_MAGIC_MISMATCH"),
])
def test_version_specific_retention_and_tampering_fails_closed(monkeypatch,field,reason):
    env,objects,manifest,s3=fixture(monkeypatch)
    setattr(s3,field,objects[3]["blob_sha1"])
    r=audit(env,manifest,s3)
    assert r["blocker"]==reason
    assert r["actual_sha256_readback_count"]<=3


@pytest.mark.parametrize(("field","value","reason"),[
    ("public_blocked",False,"S3_BUCKET_PUBLIC_ACCESS_NOT_BLOCKED"),
    ("versioning","Suspended","S3_BUCKET_VERSIONING_NOT_ENABLED"),
    ("default_mode","GOVERNANCE","S3_BUCKET_DEFAULT_COMPLIANCE_MISSING"),
])
def test_bucket_wide_protection_required(monkeypatch,field,value,reason):
    env,objects,manifest,s3=fixture(monkeypatch)
    setattr(s3,field,value)
    r=audit(env,manifest,s3)
    assert r["blocker"]==reason
    assert r["actual_sha256_readback_count"]==0


def test_bucket_owner_and_provider_endpoint_cannot_be_spoofed(monkeypatch):
    env,objects,manifest,s3=fixture(monkeypatch)
    assert audit(env,manifest,s3,FakeSTS("999999999999"))["blocker"]=="AWS_CALLER_ACCOUNT_MISMATCH"
    fake_sts=FakeSTS()
    fake_sts.meta.endpoint_url="https://sts.attacker.invalid"
    assert audit(env,manifest,s3,fake_sts)["blocker"]=="AWS_STS_PROVIDER_ENDPOINT_UNTRUSTED"
    s3.meta.endpoint_url="https://s3.attacker.invalid"
    assert audit(env,manifest,s3)["blocker"]=="AWS_PROVIDER_ENDPOINT_UNTRUSTED"


@pytest.mark.parametrize(("field","value","reason"),[
    ("JW_WORM_AUDIT_ACK","","READ_ONLY_AUDIT_CONSENT_REQUIRED"),
    ("CODESPACES","true","INDEPENDENT_CUSTODIAN_RUNTIME_REQUIRED"),
    ("JW_PG_BACKUP_KEY","source-secret","SOURCE_OR_BACKUP_SECRET_PRESENT"),
    ("DATABASE_URL","postgresql://source.invalid","SOURCE_OR_BACKUP_SECRET_PRESENT"),
    ("AWS_ENDPOINT_URL","http://attacker.invalid","CUSTOM_S3_ENDPOINT_NOT_ALLOWED"),
    ("AWS_ENDPOINT_URL_STS","http://attacker.invalid","CUSTOM_S3_ENDPOINT_NOT_ALLOWED"),
    ("AWS_CA_BUNDLE","/tmp/untrusted-ca.pem","CUSTOM_S3_ENDPOINT_NOT_ALLOWED"),
    ("JW_WORM_EXPECTED_AWS_ACCOUNT","bad","EXPECTED_BUCKET_OWNER_REQUIRED"),
    ("JW_WORM_BUCKET","bad/bucket","STRICT_BUCKET_NAME_REQUIRED"),
    ("JW_WORM_VAULT_SHA","invalid","PINNED_PRIVATE_VAULT_COMMIT_REQUIRED"),
    ("JW_WORM_MIN_UNTIL","2020-01-01T00:00:00Z","RETENTION_DEADLINE_NOT_FUTURE"),
    ("JW_WORM_MIN_UNTIL","2027-invalid","OWNER_RETENTION_DATE_MISSING_OR_INVALID"),
])
def test_preflight_denies_before_any_provider_access(monkeypatch,field,value,reason):
    env,objects,manifest,s3=fixture(monkeypatch)
    env[field]=value
    r=audit(env,manifest,s3)
    assert r["blocker"]==reason
    assert s3.calls==0


@pytest.mark.parametrize("attack",[
    "duplicate_blob","duplicate_version","wrong_vault_sha",
    "untrusted_blob","traversal_key","null_version",
])
def test_false_manifest_denied_before_s3(monkeypatch,attack):
    env,objects,manifest,s3=fixture(monkeypatch)
    if attack=="duplicate_blob":
        manifest["objects"][1]["blob_sha1"]=manifest["objects"][0]["blob_sha1"]
    elif attack=="duplicate_version":
        manifest["objects"][1]["object_key"]=manifest["objects"][0]["object_key"]
        manifest["objects"][1]["version_id"]=manifest["objects"][0]["version_id"]
    elif attack=="wrong_vault_sha":
        manifest["vault_commit_sha1"]="a"*40
    elif attack=="untrusted_blob":
        manifest["objects"][3]["blob_sha1"]="f"*40
    elif attack=="traversal_key":
        manifest["objects"][3]["object_key"]="../secret"
    else:
        manifest["objects"][3]["version_id"]="null"
    r=audit(env,manifest,s3)
    assert r["worm_readonly_audit"]=="BLOCKED"
    assert r["actual_sha256_readback_count"]==0
    assert s3.calls==0


def test_replaced_s3_cipher_and_forged_matching_manifest_sha256_rejected(monkeypatch):
    """Critical old false PASS: manifest digest matched foreign S3 ciphertext.

    All 11 original Git blob SHA-1s still appear in the trusted Git tree,
    yet the S3 bytes for one blob and the supplied SHA-256 are both replaced.
    The real pinned private Git blob differs: no S3 request may start.
    """
    env,objects,manifest,s3=fixture(monkeypatch)
    original=objects[4]["_bytes"]
    changed=original[:-1]+bytes((original[-1]^1,))
    objects[4]["_bytes"]=changed
    manifest["objects"][4]["cipher_sha256"]=hashlib.sha256(changed).hexdigest()
    result=audit(env,manifest,s3)
    assert result["worm_readonly_audit"]=="BLOCKED"
    assert result["blocker"]=="PINNED_GIT_BLOB_AND_SHA256_DO_NOT_MATCH"
    assert result["private_vault_cipher_verified_count"]==4
    assert result["actual_sha256_readback_count"]==0
    assert s3.calls==0
    assert result["overall"]=="BLOCKED"


def test_forged_sha256_without_s3_write_rejected_before_provider(monkeypatch):
    env,objects,manifest,s3=fixture(monkeypatch)
    manifest["objects"][5]["cipher_sha256"]="f"*64
    r=audit(env,manifest,s3)
    assert r["blocker"]=="PINNED_GIT_BLOB_AND_SHA256_DO_NOT_MATCH"
    assert r["private_vault_cipher_verified_count"]==5
    assert r["actual_sha256_readback_count"]==0
    assert s3.calls==0


def test_default_cli_never_contacts_cloud(monkeypatch,capsys):
    monkeypatch.delenv("JW_WORM_AUDIT_ACK",raising=False)
    assert worm.main([])==2
    assert worm.main(["verify-readonly"])==1
    assert "BLOCKED" in capsys.readouterr().out
