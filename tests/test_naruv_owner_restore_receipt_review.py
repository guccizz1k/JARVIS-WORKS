import json,os,pytest
from scripts import naruv_owner_restore_receipt_review as r

def fixture():
    return dict(r.STATUS,**dict.fromkeys(r.COUNTS,11),**dict.fromkeys(r.FLAGS,True),**dict.fromkeys(r.FALSES,False),restore_failures=0)

def raw(d):return json.dumps(d,sort_keys=True).encode()

def test_accept_consistency_not_provenance(tmp_path):
    os.chmod(tmp_path,0o700)
    for name in ("legacy.json","staged.json"):
        p=tmp_path/name;p.write_bytes(raw(fixture()));p.chmod(0o600)
    out=r.review(tmp_path)
    assert out["receipt_consistency"]=="PASS_TWO_11_COUNT_RECEIPTS"
    assert out["receipt_sha256"]["legacy"]==out["receipt_sha256"]["staged"]
    assert out["scope_binding_in_receipts"] is False
    assert out["p2_acceptance"]=="BLOCKED"
    (tmp_path/"extra").write_bytes(b"x")
    with pytest.raises(ValueError):r.review(tmp_path)

@pytest.mark.parametrize("key,value",[
    ("restored_pg17_archive_count",10),("restore_failures",False),
    ("restore_failures",1),("b2_staged_scope_bound",1),
    ("production_release_ready",True),("overall","PASS"),
    ("rls_effective_enforcement","PASS"),("disposable_pg17_removed","BLOCKED"),
    ("independent_key_custody","PASS"),("custody_model","EXTERNAL_CUSTODIAN"),
    ("offline_key_copy_verified",True)])
def test_reject_drift(key,value):
    d=fixture();d[key]=value
    with pytest.raises(ValueError):r.check(raw(d))

def test_duplicate_and_symlink(tmp_path):
    with pytest.raises(ValueError):r.check(b'{"overall":"PASS","overall":"BLOCKED"}')
    os.chmod(tmp_path,0o700)
    p=tmp_path/"legacy.json";p.write_bytes(raw(fixture()));p.chmod(0o600)
    (tmp_path/"staged.json").symlink_to(p)
    with pytest.raises(OSError):r.review(tmp_path)
