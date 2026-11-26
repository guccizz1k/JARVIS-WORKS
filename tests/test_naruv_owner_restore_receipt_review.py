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

def _pair(directory):
    directory.mkdir(mode=0o700)
    for name in ('legacy.json','staged.json'):
        p=directory/name;p.write_bytes(raw(fixture()));p.chmod(0o600)

def test_hardlink_denied(tmp_path):
    d=tmp_path/'receipts';_pair(d)
    (d/'staged.json').unlink();os.link(d/'legacy.json',d/'staged.json')
    with pytest.raises(ValueError):r.review(d)

def test_directory_swap_denied(tmp_path,monkeypatch):
    d=tmp_path/'receipts';_pair(d);replacement=tmp_path/'replacement';_pair(replacement)
    original=r.check;calls=0
    def swap(data):
        nonlocal calls
        calls+=1
        if calls==1:
            d.rename(tmp_path/'old');replacement.rename(d)
        return original(data)
    monkeypatch.setattr(r,'check',swap)
    with pytest.raises(ValueError):r.review(d)

def test_first_file_replaced_during_second_check(tmp_path,monkeypatch):
    d=tmp_path/'receipts';_pair(d);original=r.check;calls=0
    def swap(data):
        nonlocal calls
        calls+=1
        if calls==2:
            (d/'legacy.json').unlink();p=d/'legacy.json';p.write_bytes(data);p.chmod(0o600)
        return original(data)
    monkeypatch.setattr(r,'check',swap)
    with pytest.raises(ValueError):r.review(d)
