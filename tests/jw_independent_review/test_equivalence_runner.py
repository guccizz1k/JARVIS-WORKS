"""Integration with exact patched original runner; provider and PG17 mocked."""
import hashlib
import importlib
import re
import sys
from types import SimpleNamespace, ModuleType
import pytest
from scripts.jw_independent_equivalence_v223 import canonical, owner_scope
from test_jw_independent_equivalence_v223 import fixture, observation, H, admit

@pytest.fixture
def scenario(monkeypatch):
    d,pairs=fixture(); raw=canonical(d); rows=admit(); reference_pin=hashlib.sha256(raw).hexdigest()
    calls=[]; ciphers={}; baseline={}
    # Bind the expected SHA256 to actual synthetic ciphertext bytes.
    for i,r in enumerate(d['archives']):
        c=f'synthetic encrypted archive {i}'.encode(); blob=r['git_blob_sha1']; r['cipher_sha256']=hashlib.sha256(c).hexdigest(); ciphers[blob]=c
    raw=canonical(d); reference_pin=hashlib.sha256(raw).hexdigest();pairs=[(r['git_blob_sha1'],r['cipher_sha256']) for r in d['archives']]
    rows=admit(d,pairs)
    for i,r in enumerate(rows):baseline[i]=observation(r)
    class FakeBlocked(RuntimeError):pass
    clean=ModuleType('scripts.p1_cleanroom_key_recovery_v223');clean.Blocked=FakeBlocked;clean.SHA1=re.compile(r'[0-9a-f]{40}');clean.SHA256=re.compile(r'[0-9a-f]{64}');clean.ACK='ack'
    clean._inputs=lambda:('a'*40,b'K'*32,pairs)
    def tree(pin):calls.append('tree');return set(ciphers)
    def download(blob,expected):calls.append('download');return ciphers[blob]
    clean._head_tree=tree;clean._download=download
    offline=ModuleType('scripts.p1_owner_offline_restore_v223');offline.IMAGE='postgres:17';offline.SHA_RE=re.compile(r'[0-9a-f]{64}')
    def docker(args,**kw):calls.append(args[0]);return SimpleNamespace(returncode=0,stdout=b'f'*64)
    offline._docker=docker;offline._final_pg17_ready=lambda c:True;offline._exec=lambda *a,**k:SimpleNamespace(returncode=0,stdout=b'postgres (PostgreSQL) 17.9')
    def restore(c,plain,i):calls.append('restore');return baseline[i]
    offline._restore_one=restore
    backup=ModuleType('scripts.pg_backup_v223');backup.BackupError=type('BackupError',(RuntimeError,),{})
    for m in (clean,offline,backup):monkeypatch.setitem(sys.modules,m.__name__,m)
    sys.modules.pop('scripts.p1_external_custodian_pg17_v223',None)
    runner=importlib.import_module('scripts.p1_external_custodian_pg17_v223')
    monkeypatch.setattr(runner,'clean',clean);monkeypatch.setattr(runner,'offline',offline);monkeypatch.setattr(runner,'backup',backup)
    monkeypatch.setattr(runner,'preflight',lambda:'PASS');monkeypatch.setattr(runner,'decrypt_verified',lambda c,k:bytearray(b'PGDMPsynthetic'))
    monkeypatch.setenv('JW_WORM_OWNER_SCOPE_SHA256',owner_scope(p[0] for p in pairs))
    return SimpleNamespace(run=runner.run,runner=runner,raw=raw,pin=reference_pin,calls=calls,baseline=baseline,offline=offline,clean=clean,ciphers=ciphers)

def test_complete(scenario):
    s=scenario;r=s.run(s.raw,s.pin)
    assert r['normalized_archive_comparison']=='PASS_11_ARCHIVE_CHECKPOINTS' and r['matched_archives']==11 and r['overall']=='BLOCKED'
    assert s.calls.count('restore')==11 and s.calls.count('rm')==1

def test_pin_bad_before_provider_or_docker(scenario):
    s=scenario;r=s.run(s.raw,'0'*64)
    assert r['normalized_archive_comparison']=='BLOCKED' and r['blocker']=='REFERENCE_PIN_MISMATCH' and s.calls==[]

@pytest.mark.parametrize('field,value',[(4,999),(5,'0'*64),(7,None)])
def test_stops_and_cleans_on_mismatch(scenario,field,value):
    s=scenario;b=list(s.baseline[4]);b[field]=value;s.baseline[4]=b
    r=s.run(s.raw,s.pin)
    assert r['normalized_archive_comparison']=='BLOCKED' and r['matched_archives']==4 and s.calls.count('restore')==5 and s.calls.count('rm')==1

def test_cleanup_failure(scenario,monkeypatch):
    s=scenario;old=s.offline._docker
    def fail(args,**kw):
        if args[0]=='rm':return SimpleNamespace(returncode=1,stdout=b'')
        return old(args,**kw)
    monkeypatch.setattr(s.offline,'_docker',fail);r=s.run(s.raw,s.pin)
    assert r['normalized_archive_comparison']=='BLOCKED' and r['matched_archives']==11 and r['disposable_pg17_removed']=='BLOCKED_CLEANUP'

def test_provider_bytes_mismatch(scenario):
    s=scenario;first=next(iter(s.ciphers));s.ciphers[first]=b'not expected ciphertext'
    r=s.run(s.raw,s.pin)
    assert r['normalized_archive_comparison']=='BLOCKED' and r['blocker']=='ARCHIVE_CIPHERTEXT_MISMATCH' and s.calls.count('rm')==1

def test_legacy_narrow_result_preserved(scenario):
    s=scenario;r=s.run()
    assert r['external_pg17_restore']=='PASS_ELEVEN_PROVIDER_CIPHERS_NETWORKLESS_PG17' and 'normalized_archive_comparison' not in r and r['overall']=='BLOCKED'

def test_early_preflight_failure(scenario,monkeypatch):
    s=scenario;monkeypatch.setattr(s.runner,'preflight',lambda:'DOCKER_CLI_UNAVAILABLE')
    r=s.run(s.raw,s.pin);assert r['external_pg17_restore']=='BLOCKED' and r['overall']=='BLOCKED' and s.calls==[]

def test_cli_new_mode_returns_scoped_receipt(scenario,monkeypatch,capsys):
    import json
    s=scenario
    monkeypatch.setattr(s.runner.equivalence,'read_reference_pipe',lambda env:s.raw)
    monkeypatch.setenv('JW_PG_RESTORE_REFERENCE_SHA256',s.pin)
    assert s.runner.main(['restore-external-equivalence'])==0
    output=capsys.readouterr().out
    r=json.loads(output)
    assert r['normalized_archive_comparison']=='PASS_11_ARCHIVE_CHECKPOINTS' and r['overall']=='BLOCKED'
    assert all(blob not in output for blob in s.ciphers)


def test_cli_no_reference_pin_fails_closed(scenario,monkeypatch,capsys):
    import json
    s=scenario
    monkeypatch.setattr(s.runner.equivalence,'read_reference_pipe',lambda env:s.raw)
    monkeypatch.delenv('JW_PG_RESTORE_REFERENCE_SHA256',raising=False)
    assert s.runner.main(['restore-external-equivalence'])==1
    r=json.loads(capsys.readouterr().out)
    assert r['normalized_archive_comparison']=='BLOCKED' and not s.calls
