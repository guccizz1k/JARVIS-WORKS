"""Fail-closed receipt validation; actual PG17 execution is a separate gate."""
import json
import subprocess
from types import SimpleNamespace
import pytest
from scripts import jw_independent_ci_receipt_v223 as c


def payload(spec):
    _, status, counts = spec
    return {'status': status, 'cleanup': 'PASS', 'overall': 'BLOCKED', **counts}


@pytest.mark.parametrize('spec', c.CHECKS)
def test_valid(spec):
    assert c.verified(0, json.dumps(payload(spec)).encode(), spec[1], spec[2])


@pytest.mark.parametrize('spec', c.CHECKS)
@pytest.mark.parametrize('mutation', ['missing','extra','bool','wrong_count','cleanup','status','overall','duplicate','bad_json','not_object','too_big','nonzero'])
def test_invalid(spec, mutation):
    p=payload(spec); k=next(iter(spec[2])); rc=0
    if mutation=='missing': p.pop(k)
    elif mutation=='extra': p['unexpected']='PASS'
    elif mutation=='bool': p[k]=True
    elif mutation=='wrong_count': p[k]-=1
    elif mutation=='cleanup': p['cleanup']='BLOCKED'
    elif mutation=='status': p['status']='BLOCKED'
    elif mutation=='overall': p['overall']='PASS'
    elif mutation=='nonzero': rc=1
    raw=json.dumps(p).encode()
    if mutation=='duplicate': raw=raw[:-1]+b',"cleanup":"PASS"}'
    elif mutation=='bad_json': raw=b'not-json'
    elif mutation=='not_object': raw=b'[]'
    elif mutation=='too_big': raw+=b' '*8193
    assert not c.verified(rc,raw,spec[1],spec[2])


def test_executor_isolation(monkeypatch,tmp_path):
    monkeypatch.setenv('JW_SOURCE_DB_PASSWORD','synthetic-sensitive-value')
    calls=[]
    def execute(args,**kwargs):
        spec=c.CHECKS[len(calls)]; calls.append(args)
        assert args[-1].endswith(spec[0]) and args[1]=='-I'
        assert 'JW_SOURCE_DB_PASSWORD' not in kwargs['env']
        assert kwargs['timeout']==180 and kwargs['check'] is False
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload(spec)).encode())
    receipt=c.run(tmp_path,execute)
    assert receipt=={'synthetic_pg17':'PASS_34_SYNTHETIC_ASSERTIONS','checks_passed':2,'overall':'BLOCKED','real_backup_restore':'NOT_RUN'}
    assert len(calls)==2


@pytest.mark.parametrize('fail_at',[0,1])
@pytest.mark.parametrize('mode',['rc','timeout','missing_field'])
def test_executor_fails_closed(tmp_path,fail_at,mode):
    calls=[]
    def execute(args,**kwargs):
        i=len(calls); calls.append(args); p=payload(c.CHECKS[i]); rc=0
        if i==fail_at:
            if mode=='timeout': raise subprocess.TimeoutExpired(args,180)
            if mode=='rc': rc=1
            if mode=='missing_field': p.pop('cleanup')
        return SimpleNamespace(returncode=rc,stdout=json.dumps(p).encode())
    r=c.run(tmp_path,execute)
    assert r['synthetic_pg17']=='BLOCKED' and r['checks_passed']==fail_at
    assert r['overall']=='BLOCKED' and len(calls)==fail_at+1
