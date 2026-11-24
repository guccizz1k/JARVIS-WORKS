"""All provider operations simulated; no user ciphertext or GitHub secrets."""
import base64
import hashlib
import json
from pathlib import Path
import pytest
from scripts import p1_owner_vault_upload_v223 as up
from scripts import p1_owner_vault_readback_v223 as vault

def blobid(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

class Provider:
    def __init__(self):
        self.head="b"*40
        self.origin=self.head
        self.commits={self.head:"a"*40}
        self.trees={"a"*40:{}}
        self.objects={}
        self.calls=[]
        self.deny_write=False
        self.private=True
        self.write=True

    def api(self,method,path,data=None):
        self.calls.append((method,path))
        if self.deny_write and method!="GET":raise up.Blocked("VAULT_WRITE_BLOCKED")
        p=up.REPO+"/"
        if (method,path)==("GET",up.REPO):
            return {"private":self.private,"full_name":"guccizz1k/jw-backup-vault-261111",
                    "default_branch":"main","permissions":{"push":self.write},
                    "archived":False,"disabled":False}
        if method=="GET" and path==p+"git/ref/heads/main":
            return {"object":{"sha":self.head}}
        if method=="GET" and path.startswith(p+"git/commits/"):
            x=path.rsplit("/",1)[-1]
            return {"sha":x,"tree":{"sha":self.commits[x]}}
        if method=="GET" and path.startswith(p+"git/trees/"):
            x=path[len(p+"git/trees/"):].split("?")[0]
            return {"truncated":False,"tree":[
                {"type":"blob","mode":"100644","path":n,
                 "sha":s,"size":len(self.objects[s])} for n,s in self.trees[x].items()]}
        if method=="POST" and path==p+"git/blobs":
            raw=base64.b64decode(data["content"],validate=True)
            digest=blobid(raw)
            self.objects[digest]=raw
            return {"sha":digest}
        if method=="POST" and path==p+"git/trees":
            base=dict(self.trees[data["base_tree"]])
            for x in data["tree"]:
                assert x["path"] not in base
                base[x["path"]]=x["sha"]
            name=f"{len(self.trees)+1:040x}"
            self.trees[name]=base
            return {"sha":name}
        if method=="POST" and path==p+"git/commits":
            assert data["parents"]==[self.head]
            name=f"{len(self.commits)+5:040x}"
            self.commits[name]=data["tree"]
            return {"sha":name}
        if method=="PATCH" and path==p+"git/refs/heads/main":
            assert data["force"] is False
            self.head=data["sha"]
            return {"object":{"sha":self.head}}
        raise AssertionError("unexpected API endpoint")

    def read_blob(self,sha):
        raw=self.objects[sha]
        return hashlib.sha256(raw).hexdigest(),len(raw)

def sample(tmp_path,monkeypatch):
    provider=Provider()
    files=[]
    for i in range(11):
        f=tmp_path/f"synthetic_{i}.jwpgbk"
        f.write_bytes(b"JWPGBK2\n"+bytes([i])*2000)
        f.chmod(0o600)
        files.append(f)
    ids=[vault.local_hash(x)[0] for x in files]
    for f in files[:2]:
        provider.objects[vault.local_hash(f)[0]]=f.read_bytes()
    older=b"JWPGBK1\nOLDER_SYNTHETIC_CIPHER_NOT_OWNER"
    extra=blobid(older)
    provider.objects[extra]=older
    provider.trees["a"*40]={
        "old/first.jwpgbk":ids[0],"old/repeat.jwpgbk":ids[0],
        "old/second.jwpgbk":ids[1],"old/extra.jwpgbk":extra}
    monkeypatch.setattr(up.owner,"discover_owner_archive",lambda:(files,"MULTIPLE_ARCHIVES"))
    monkeypatch.setattr(up,"api",provider.api)
    monkeypatch.setattr(vault,"_vault_api_json",
        lambda endpoint,max_bytes=65536,timeout=45:provider.api("GET",endpoint))
    monkeypatch.setattr(vault,"_vault_api_blob_sha256",provider.read_blob)
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.setenv("JW_PG_VAULT_READBACK_ACK",vault.ACK)
    monkeypatch.setenv("JW_PG_VAULT_WRITE_ACK",up.WRITE_ACK)
    monkeypatch.setenv("JW_PG_VAULT_EXPECTED_SHA",provider.origin)
    return provider,files

def test_nine_approved_ciphertext_copies_end_to_end(tmp_path,monkeypatch,capsys):
    server,files=sample(tmp_path,monkeypatch)
    originals=[(p.read_bytes(),p.stat().st_mtime_ns) for p in files]
    existing=dict(server.trees["a"*40])
    assert up.main(["upload-approved"])==0
    x=json.loads(capsys.readouterr().out)
    assert x["new_ciphertext_file_count"]==9
    assert x["vault_remote_file_count"]==13
    assert x["vault_remote_unique_cipher_count"]==12
    assert x["owner_eleven_full_sha256_remote_readback"]=="PASS"
    assert x["owner_original_eleven_archives_unchanged"]=="PASS"
    assert x["overall"]=="BLOCKED"
    assert server.head!=server.origin
    after=server.trees[server.commits[server.head]]
    assert len(after)==13
    assert all(after.get(name)==sha for name,sha in existing.items())
    assert sum(k=="POST" and p.endswith("/git/blobs") for k,p in server.calls)==9
    assert sum(k=="PATCH" for k,p in server.calls)==1
    assert originals==[(p.read_bytes(),p.stat().st_mtime_ns) for p in files]
    assert all(str(p) not in str(x) for p in files)

def test_no_write_approval_means_zero_provider_access(tmp_path,monkeypatch):
    provider,files=sample(tmp_path,monkeypatch)
    monkeypatch.delenv("JW_PG_VAULT_WRITE_ACK")
    assert up.main(["upload-approved"])==1
    assert provider.calls==[]

def test_public_or_readonly_vault_fail_before_write(tmp_path,monkeypatch):
    provider,_=sample(tmp_path,monkeypatch)
    provider.private=False
    assert up.main(["upload-approved"])==1
    assert not any(m!="GET" for m,_ in provider.calls)
    provider.private=True
    provider.calls=[]
    provider.write=False
    assert up.main(["upload-approved"])==1
    assert not any(m!="GET" for m,_ in provider.calls)

def test_unexpected_branch_head_rejects_all_remote_writes(tmp_path,monkeypatch):
    provider,_=sample(tmp_path,monkeypatch)
    provider.head="e"*40
    assert up.main(["upload-approved"])==1
    assert not any(m!="GET" for m,_ in provider.calls)

def test_local_cipher_tampered_after_preflight_refused(tmp_path,monkeypatch):
    provider,files=sample(tmp_path,monkeypatch)
    before=up.approved_preflight
    def change():
        evidence=before()
        files[7].write_bytes(b"JWPGBK2\nCHANGED_AFTER_APPROVAL")
        return evidence
    monkeypatch.setattr(up,"approved_preflight",change)
    assert up.main(["upload-approved"])==1
    assert provider.head==provider.origin

def test_write_failure_does_not_publish_branch(tmp_path,monkeypatch):
    provider,_=sample(tmp_path,monkeypatch)
    provider.deny_write=True
    assert up.main(["upload-approved"])==1
    assert provider.head==provider.origin

def test_wrong_cipher_header_halts_before_write(tmp_path,monkeypatch):
    provider,files=sample(tmp_path,monkeypatch)
    files[5].write_bytes(b"WRONG_FORMAT")
    assert up.main(["upload-approved"])==1
    assert not any(m!="GET" for m,_ in provider.calls)

def test_bad_remote_sha256_fails_before_branch_update(tmp_path,monkeypatch):
    provider,_=sample(tmp_path,monkeypatch)
    real=provider.read_blob
    original=set(provider.objects)
    def tamper(sha):
        check=real(sha)
        return (("0"*64,check[1]) if sha not in original else check)
    monkeypatch.setattr(vault,"_vault_api_blob_sha256",tamper)
    assert up.main(["upload-approved"])==1
    assert provider.head==provider.origin

def test_invalid_cli_has_zero_side_effects(tmp_path,monkeypatch):
    provider,_=sample(tmp_path,monkeypatch)
    assert up.main(["wrong"])==2
    assert provider.calls==[]
