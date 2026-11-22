import json
from unittest.mock import patch
import pytest
from scripts import ci_cinema_pg_v6_target_adapter as t

def metadata(**changes):
    d={'Id':'abc123','Name':'/'+t.NAME,'Config':{'Image':'postgres:17'},'State':{'Running':True},'HostConfig':{'NetworkMode':'none','PortBindings':{}},'NetworkSettings':{'Networks':{'none':{}},'Ports':{'5432/tcp':None}}}
    for k,v in changes.items():
        d[k]=v
    return json.dumps([d])

@pytest.mark.parametrize('change',[
    {'Name':'/other'}, {'Config':{'Image':'postgres:16'}},
    {'State':{'Running':False}}, {'HostConfig':{'NetworkMode':'bridge','PortBindings':{}}},
    {'HostConfig':{'NetworkMode':'none','PortBindings':{'5432/tcp':[{'HostPort':'55433'}]}}},
    {'NetworkSettings':{'Networks':{'bridge':{}},'Ports':{}}},
])
def test_reject_bad_metadata(change):
    with patch.object(t,'_cmd',return_value=metadata(**change)):
        with pytest.raises(t.TargetBlocked): t.check_docker_identity()

def test_accept_none_network():
    with patch.object(t,'_cmd',return_value=metadata()):
        assert t.check_docker_identity()=='abc123'

def test_reject_invalid_json():
    with patch.object(t,'_cmd',return_value='bad'):
        with pytest.raises(t.TargetBlocked): t.check_docker_identity()

class FakeConn:
    def __init__(self, ident): self.ident=ident
    def __enter__(self): return self
    def __exit__(self,*a): pass
    def execute(self,sql): return self
    def fetchone(self): return (self.ident,)

class FakePsy:
    def __init__(self, ident): self.ident=ident
    def connect(self,**kwargs): return FakeConn(self.ident)

class FakeBackup:
    def __init__(self): self.called=False
    def verify_ephemeral_target(self,conn,token): self.called=True

@pytest.mark.parametrize('outside,ok',[('123456',True),('654321',False)])
def test_system_id(outside,ok):
    b=FakeBackup()
    with patch.object(t,'check_docker_identity',return_value='abc123'),patch.object(t,'_cmd',return_value='123456'):
        if ok:
            assert t.prove_target(FakePsy(outside),'private','token',b)
            assert b.called
        else:
            with pytest.raises(t.TargetBlocked): t.prove_target(FakePsy(outside),'private','token',b)
            assert not b.called

def test_detect_replaced_container():
    with patch.object(t,'check_docker_identity',side_effect=['abc','def']),patch.object(t,'_cmd',return_value='123456'):
        with pytest.raises(t.TargetBlocked,match='replaced'):
            t.prove_target(FakePsy('123456'),'private','token',FakeBackup())
