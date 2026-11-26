import copy
import datetime as dt
import hashlib
import hmac
import json
import pytest
from app import naruv_portone_test_review as m


def fixture():
    now = 1795734000
    t = lambda x: dt.datetime.fromtimestamp(x, dt.timezone.utc).isoformat()
    args = dict(expected_id='request-1', channel_key='channel-test', pg_provider='SYNTHETIC_PG', tenant='tenant-a', store_id='store-a', identifier_kind='ci', pepper=b'x'*32, issued_at=now-10, expires_at=now+60, now=now)
    args['expected_tag']=hmac.new(args['pepper'], b'NARUV_PORTONE_TEST_V1\0tenant-a\0store-a\0channel-test\0ci\0fixture-subject', hashlib.sha256).hexdigest()
    doc=dict(status='VERIFIED',version='V2',id='request-1',channel=dict(type='TEST',key='channel-test',pgProvider='SYNTHETIC_PG'),requestedAt=t(now-9),verifiedAt=t(now-1),verifiedCustomer=dict(ci='fixture-subject'))
    return doc,args


def test_valid():
    doc,args=fixture();out=m.inspect(json.dumps(doc).encode(),**args)
    assert out['test_response_binding_match'] and not any(out[k] for k in out if k!='test_response_binding_match')
    assert 'fixture-subject' not in str(out)


@pytest.mark.parametrize('case', ['live','ready','id','channel','provider','missing_ci','other_subject','di_missing','old_request','future_verified','expired','wrong_tenant','wrong_store','bad_version','duplicate','nonfinite','large','bad_time'])
def test_reject(case):
    doc,args=fixture()
    if case=='live':doc['channel']['type']='LIVE'
    elif case=='ready':doc['status']='READY'
    elif case=='id':doc['id']='request-2'
    elif case=='channel':doc['channel']['key']='other'
    elif case=='provider':doc['channel']['pgProvider']='OTHER'
    elif case=='missing_ci':doc['verifiedCustomer']={}
    elif case=='other_subject':doc['verifiedCustomer']['ci']='other'
    elif case=='di_missing':args['identifier_kind']='di'
    elif case=='old_request':doc['requestedAt']='2020-01-01T00:00:00Z'
    elif case=='future_verified':doc['verifiedAt']='2030-01-01T00:00:00Z'
    elif case=='expired':args['expires_at']=args['now']
    elif case=='wrong_tenant':args['tenant']='tenant-b'
    elif case=='wrong_store':args['store_id']='store-b'
    elif case=='bad_version':doc['version']='V1'
    elif case=='bad_time':doc['verifiedAt']='2026-11-27'
    raw=json.dumps(doc).encode()
    if case=='duplicate':raw=b'{"status":"READY",'+raw[1:]
    elif case=='nonfinite':raw=raw[:-1]+b',"extra":NaN}'
    elif case=='large':raw=b' '*65537
    with pytest.raises(ValueError,match='PORTONE_TEST_REVIEW_DENIED'):m.inspect(raw,**args)


def test_no_approval_no_network(monkeypatch):
    monkeypatch.setattr(m.http.client,'HTTPSConnection',lambda *a,**k:pytest.fail('network attempted'))
    with pytest.raises(ValueError):m.retrieve_test(approved=False,api_secret='fixture',store_id='store-a',expected_id='request-1')


@pytest.mark.parametrize('status,kind,encoding,size,ok',[(200,'application/json','identity',3,True),(302,'application/json','identity',3,False),(401,'application/json','identity',3,False),(200,'text/html','identity',3,False),(200,'application/json','gzip',3,False),(200,'application/json','identity',65537,False)])
def test_transport(monkeypatch,status,kind,encoding,size,ok):
    class Response:
        def getheader(self,key,default):return {'Content-Type':kind,'Content-Encoding':encoding}.get(key,default)
        def read(self,n):assert n==65537;return b'x'*size
    class Conn:
        def __init__(self,host,**kw):assert host=='api.portone.io' and kw['timeout']==5;self.closed=False
        def request(self,method,path,headers):assert method=='GET' and path=='/identity-verifications/request-1?storeId=store-a' and headers['Authorization']=='PortOne fixture'
        def getresponse(self):r=Response();r.status=status;return r
        def close(self):self.closed=True
    monkeypatch.setattr(m.http.client,'HTTPSConnection',Conn)
    args=dict(approved=True,api_secret='fixture',store_id='store-a',expected_id='request-1')
    if ok:assert m.retrieve_test(**args)==b'xxx'
    else:
        with pytest.raises(ValueError):m.retrieve_test(**args)
