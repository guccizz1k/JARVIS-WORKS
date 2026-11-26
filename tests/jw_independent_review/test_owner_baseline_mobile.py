import json,hashlib,os
import pytest
from scripts import jw_owner_baseline_mobile_v223 as m

@pytest.fixture
def data(tmp_path,monkeypatch):
    root=tmp_path/'.local/share/jw-v223-restore/backups';root.mkdir(parents=True,mode=0o700)
    old={};new={}
    for i in range(11):
        raw=b'JWPGBK2\n'+bytes([i])*100;f=root/(str(i)+'.jwpgbk');f.write_bytes(raw);f.chmod(0o600);old[m.git_blob(raw)]=m.sha(raw)
        new[hashlib.sha1(b'new'+raw).hexdigest()]=m.sha(b'new'+raw)
    vault='1'*40; n_vault='2'*40
    source=(json.dumps({'vault_commit_sha1':vault,'archives':[{'blob_sha1':i,'cipher_sha256':old[i]} for i in sorted(old)]},indent=2)+'\n').encode()
    receipt=json.dumps({'stage':'complete','verified':11,'activated':False,'remote_writes':False,'new_scope_sha256':m.scope(new),'archives':[{'source_blob_sha1':a,'blob_sha1':b,'cipher_sha256':new[b]} for a,b in zip(sorted(old),sorted(new))]}).encode()
    for k,v in {'OLD':vault,'NEW':n_vault,'OLD_SCOPE':m.scope(old),'NEW_SCOPE':m.scope(new),'SOURCE_PIN':m.sha(source),'RECEIPT_PIN':m.sha(receipt)}.items():monkeypatch.setattr(m,k,v)
    return root,source,receipt

def test_exact_source(data,tmp_path): assert m.source_from_originals(tmp_path,data[2])==data[1]
@pytest.mark.parametrize('kind',['changed','missing','extra','mode','symlink'])
def test_bad_source(data,tmp_path,kind):
    p=data[0]/'0.jwpgbk'
    if kind=='changed':p.write_bytes(b'x')
    if kind=='missing':p.unlink()
    if kind=='extra':(data[0]/'other.jwpgbk').write_bytes(b'y')
    if kind=='mode':p.chmod(0o644)
    if kind=='symlink':p.unlink();p.symlink_to(data[0]/'1.jwpgbk')
    with pytest.raises((m.Blocked,OSError)):m.source_from_originals(tmp_path,data[2])
def test_receipt_pin(data,tmp_path):
    with pytest.raises(m.Blocked,match='RECEIPT_PIN'):m.source_from_originals(tmp_path,data[2]+b' ')
def test_source_pin(data,tmp_path,monkeypatch):
    monkeypatch.setattr(m,'SOURCE_PIN','0'*64)
    with pytest.raises(m.Blocked,match='SOURCE_PIN'):m.source_from_originals(tmp_path,data[2])
def test_no_codespace(monkeypatch):
    monkeypatch.delenv('CODESPACES',raising=False)
    assert m.main(['1'*40,'2'*40]+['a'*64]*5)==1
