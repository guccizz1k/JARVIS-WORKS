import copy,hashlib,pytest
from scripts import naruv_owner_b2_acquire as a

def test_authz_scope(monkeypatch):
    monkeypatch.setattr(a,"BUCKET",hashlib.sha256(b"fixture").hexdigest())
    doc={"authorizationToken":"synthetic","apiInfo":{"storageApi":{"downloadUrl":"https://f001.backblazeb2.com","allowed":{"capabilities":["readFiles"],"buckets":[{"name":"fixture"}],"namePrefix":None}}}}
    assert a.authorized_download(doc)==("f001.backblazeb2.com","synthetic")
    for change in ("write","other_bucket","host","prefix","missing"):
        bad=copy.deepcopy(doc);s=bad["apiInfo"]["storageApi"];x=s["allowed"]
        if change=="write":x["capabilities"].append("writeFiles")
        if change=="other_bucket":x["buckets"][0]["name"]="wrong"
        if change=="host":s["downloadUrl"]="https://f001.backblazeb2.com.evil.test"
        if change=="prefix":x["namePrefix"]="wrong/"
        if change=="missing":x["capabilities"]=[]
        with pytest.raises(ValueError):a.authorized_download(bad)

def test_unapproved_input_does_not_authorize(monkeypatch,tmp_path):
    monkeypatch.setattr(a,"approved_inputs",lambda d: (_ for _ in ()).throw(ValueError("BAD_PIN")))
    monkeypatch.setattr(a,"read_authorization",lambda *x:pytest.fail("remote contact before pin"))
    with pytest.raises(ValueError,match="BAD_PIN"):a.acquire(tmp_path)

def test_missing_credential_fail_closed(monkeypatch,tmp_path):
    monkeypatch.setattr(a,"approved_inputs",lambda d:b"synthetic")
    for k in a.AUDIT:monkeypatch.delenv(k,raising=False)
    monkeypatch.setattr(a,"read_authorization",lambda *x:pytest.fail("remote contact without credentials"))
    with pytest.raises(ValueError,match="B2_AUDIT_CREDENTIALS_REQUIRED"):a.acquire(tmp_path)
