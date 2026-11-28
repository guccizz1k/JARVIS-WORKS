"""Synthetic inputs only. No provider or key access."""
import base64,json
import pytest
from scripts import p1_cleanroom_key_recovery_v223 as c
PIN="a"*40
KEY=base64.urlsafe_b64encode(bytes(range(32)))
def fixture(monkeypatch,key=KEY,bad=None):
    monkeypatch.delenv("CODESPACES",raising=False)
    monkeypatch.delenv("JW_PG_BACKUP_KEY",raising=False)
    monkeypatch.setenv("JW_PG_CLEANROOM_ACK",c.ACK)
    monkeypatch.setenv("JW_PG_CLEANROOM_VAULT_SHA",PIN)
    archives=[{"blob_sha1":f"{i:040x}","cipher_sha256":f"{i:064x}"} for i in range(11)]
    if bad is not None:archives[0].update(bad)
    doc=json.dumps(dict(vault_commit_sha1=PIN,archives=archives)).encode()
    monkeypatch.setattr(c,"_read_pipe",lambda fd,limit,label:key if label=="EXTERNAL_KEY_PIPE_REQUIRED" else doc)
def test_valid(monkeypatch):
    fixture(monkeypatch);pin,key,pairs=c._inputs();assert pin==PIN and key==bytes(range(32)) and len(pairs)==11
@pytest.mark.parametrize("bad",[{"blob_sha1":None},{"blob_sha1":1},{"cipher_sha256":[]},{"cipher_sha256":False}])
def test_manifest_type(monkeypatch,bad):
    fixture(monkeypatch,bad=bad)
    with pytest.raises(c.Blocked,match="EXTERNAL_MANIFEST_DIGEST_INVALID"):c._inputs()
@pytest.mark.parametrize("key",[KEY[:5]+b"!"+KEY[5:],KEY+b"=",KEY.rstrip(b"=")])
def test_noncanonical_key(monkeypatch,key):
    fixture(monkeypatch,key)
    with pytest.raises(c.Blocked,match="EXTERNAL_KEY_ENCODING_INVALID"):c._inputs()
def test_bad_tree_type(monkeypatch):
    def api(endpoint,**kw):
        if "/ref/" in endpoint:return {"object":{"sha":PIN}}
        return {"sha":PIN,"tree":{"sha":None}}
    monkeypatch.setattr(c,"_api",api)
    with pytest.raises(c.Blocked,match="VAULT_COMMIT_TREE_INVALID"):c._head_tree(PIN)
def test_bad_tree_entry(monkeypatch):
    def api(endpoint,**kw):
        if "/ref/" in endpoint:return {"object":{"sha":PIN}}
        if "/commits/" in endpoint:return {"sha":PIN,"tree":{"sha":"b"*40}}
        return {"truncated":False,"tree":[{"type":"blob","mode":"100644","path":"x.jwpgbk","sha":None}]*11}
    monkeypatch.setattr(c,"_api",api)
    with pytest.raises(c.Blocked,match="VAULT_TREE_UNSAFE_ENTRY"):c._head_tree(PIN)
