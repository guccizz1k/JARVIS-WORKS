"""V17.1 official NTS adapter fail-closed unit and attack coverage.

All HTTP is deterministic local MockTransport. Never sends a real key, name,
business number, or company data outside the runner; real API is NOT certified.
"""
from __future__ import annotations

from dataclasses import asdict
import json
import re
import pytest
import httpx

from scripts.review import nts_registry_v171 as mod

NUMBER = "1234567890"
DATE = "20200101"
NAME = "홍길동"
KEY = "v171-ci-synthetic-only-not-a-real-nts-key"


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    monkeypatch.setenv("JW_ENV","test")
    monkeypatch.setenv("JW_V171_REGISTRY_ACK","ISOLATED_DEV_NTS_PUBLIC_REGISTRY_ONLY")
    monkeypatch.setenv("JW_NTS_SERVICE_KEY",KEY)
    monkeypatch.delenv("JW_INSECURE_LOCAL_DEV",raising=False)
    monkeypatch.delenv("JW_RELEASE_APPROVED",raising=False)


def _response(code="01", state="01", *, bad=None):
    count = []
    def send(req: httpx.Request):
        assert req.method == "POST"
        assert req.url.scheme == "https"
        assert req.url.host == "api.odcloud.kr"
        assert req.headers["Authorization"] == KEY
        data=json.loads(req.content)
        count.append(req.url.path)
        if req.url.path.endswith("/validate"):
            assert data=={"businesses":[{"b_no":NUMBER,"start_dt":DATE,"p_nm":NAME}]}
            record={"status_code":"OK","request_cnt":1,
                    "data":[{"b_no":NUMBER,"valid":code}]}
        else:
            assert req.url.path.endswith("/status")
            assert data=={"b_no":[NUMBER]}
            record={"status_code":"OK","request_cnt":1,
                    "data":[{"b_no":NUMBER,"b_stt_cd":state}]}
        if bad:
            return bad(req.url.path,record)
        return httpx.Response(200,json=record)
    client=httpx.Client(transport=httpx.MockTransport(send))
    return client,count


def test_active_registration_match_does_not_confer_any_other_authority():
    c,calls=_response()
    with c:
        e=mod.check_official_business_record(NUMBER,DATE,NAME,client=c)
    assert asdict(e)=={
        "business_record_matched":True,
        "business_currently_active":True,
        "company_account_ownership_verified":False,
        "representative_authority_verified":False,
        "bank_reconciliation_verified":False,
        "independent_issuer_signature_verified":False,
    }
    assert len(calls)==2


@pytest.mark.parametrize(("valid","state","match","active","count"),[
    ("02","01",False,False,1),
    ("00","01",False,False,1),
    ("01","02",True,False,2),
    ("01","03",True,False,2),
    ("01","01",True,True,2),
])
def test_registry_outcomes_never_become_account_ownership(valid,state,match,active,count):
    c,calls=_response(valid,state)
    with c:
        out=mod.check_official_business_record(NUMBER,DATE,NAME,client=c)
    assert (out.business_record_matched,out.business_currently_active)==(match,active)
    assert out.company_account_ownership_verified is False
    assert len(calls)==count


@pytest.mark.parametrize(("key","value"),[
    ("JW_ENV","production"),
    ("JW_ENV","review"),
    ("JW_V171_REGISTRY_ACK","WRONG"),
    ("JW_INSECURE_LOCAL_DEV","1"),
    ("JW_RELEASE_APPROVED","1"),
    ("JW_RELEASE_APPROVED","true"),
    ("JW_NTS_SERVICE_KEY",""),
    ("JW_NTS_SERVICE_KEY","bad"),
    ("JW_NTS_SERVICE_KEY","a key with spaces"),
])
def test_unauthorized_configuration_fails_before_network(monkeypatch,key,value):
    monkeypatch.setenv(key,value)
    c,calls=_response()
    with c,pytest.raises(mod.RegistryBlocked):
        mod.check_official_business_record(NUMBER,DATE,NAME,client=c)
    assert calls==[]


@pytest.mark.parametrize(("bno","day","name"),[
    ("123456789",DATE,NAME),
    ("12345678901",DATE,NAME),
    ("123-45-67890",DATE,NAME),
    ("123456789x",DATE,NAME),
    (1234567890,DATE,NAME),
    (True,DATE,NAME),
    (NUMBER,"2020-01-01",NAME),
    (NUMBER,"20200230",NAME),
    (NUMBER,"18990101",NAME),
    (NUMBER,"99999999",NAME),
    (NUMBER,None,NAME),
    (NUMBER,DATE,""),
    (NUMBER,DATE," "+NAME),
    (NUMBER,DATE,NAME+"\n"),
    (NUMBER,DATE,True),
    (NUMBER,DATE,"가"*61),
])
def test_invalid_input_fails_before_network(bno,day,name):
    c,calls=_response()
    with c,pytest.raises(mod.RegistryBlocked):
        mod.check_official_business_record(bno,day,name,client=c)
    assert calls==[]


@pytest.mark.parametrize("case",[
    "redirect","timeout","server_error","missing_status","foreign_business",
    "duplicate_records","wrong_count","non_json","giant","unknown_status",
    "wrong_content_type","invalid_payload","status_mismatch",
])
def test_malformed_external_response_fails_closed_without_sensitive_echo(case):
    def tamper(path,record):
        is_validation=path.endswith("/validate")
        if case=="redirect":return httpx.Response(302,headers={"Location":"https://attacker.test"})
        if case=="timeout":raise httpx.ConnectTimeout("internal secret")
        if case=="server_error":return httpx.Response(503,text="internal secret")
        if case=="missing_status":record.pop("status_code")
        if case=="foreign_business":record["data"][0]["b_no"]="0000000000"
        if case=="duplicate_records":record["data"].append(record["data"][0])
        if case=="wrong_count":record["request_cnt"]=2
        if case=="non_json":return httpx.Response(200,content=b"bad",headers={"content-type":"application/json"})
        if case=="giant":return httpx.Response(200,content=b"x"*16400,headers={"content-type":"application/json"})
        if case=="unknown_status" and not is_validation:record["data"][0]["b_stt_cd"]="99"
        if case=="wrong_content_type":return httpx.Response(200,text=json.dumps(record))
        if case=="invalid_payload":record["data"]={"b_no":NUMBER}
        if case=="status_mismatch" and not is_validation:record["data"][0]["b_no"]="0000000000"
        return httpx.Response(200,json=record)
    c,calls=_response(bad=tamper)
    with c,pytest.raises(mod.RegistryBlocked) as error:
        mod.check_official_business_record(NUMBER,DATE,NAME,client=c)
    assert KEY not in str(error.value) and NAME not in str(error.value)
    assert "internal secret" not in str(error.value)
    assert len(calls) in (1,2)


def test_no_implicit_network_on_import_and_only_two_pinned_endpoints():
    assert mod._VALIDATE=="https://api.odcloud.kr/api/nts-businessman/v1/validate"
    assert mod._STATUS=="https://api.odcloud.kr/api/nts-businessman/v1/status"
    assert "company_account_ownership_verified" in asdict(mod.RegistryEvidence(False,False))
    assert not any(re.search(pattern,mod.__file__) for pattern in ("app/main.py","production"))
