"""Exercise exact integrated modules, including genuine OOXML workbooks."""
import copy, importlib.util, io, os, zipfile
from pathlib import Path
from datetime import datetime, timezone
import pytest
from openpyxl import Workbook
from app.naruv_kr_payroll_review import (
    verify_fixed_week_statement_source_2026 as verify,
    fixed_week_wage_statement_draft_2026 as statement, PayrollBlocked)
from app.erp_migration_xlsx import parse_xlsx, MappingBlocked, shared_strings, S
from xml.etree import ElementTree as ET

def load(path,name):
    s=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def fixture():
    m=load(Path(os.environ["WAVE2_DIR"])/"test_paid_statement.py","paid_fixture")
    a=m.PaidStatement().fixture()
    d=statement(**a)
    return d,dict(tenant=a["tenant"],assessment_sha256=a["completeness_assessment_sha256"],expected_review_sha256=d["review_sha256"])
def test_real_payroll_binding():
    d,k=fixture()
    assert verify(draft=d,**k)["status"]=="DRAFT_SOURCE_INTEGRITY_ONLY"
@pytest.mark.parametrize("case",["amount","tenant","assessment","authority","non_json","extra","missing"])
def test_real_payroll_rejects(case):
    d,k=fixture()
    if case=="amount":
        d["components"][0]["amount_krw"]+=1;d["gross_krw"]+=1;d["net_krw"]+=1
    elif case=="tenant":k["tenant"]="wrong"
    elif case=="assessment":k["assessment_sha256"]="b"*64
    elif case=="authority":d["payment_authorized"]=True
    elif case=="non_json":d["components"]=object()
    elif case=="extra":d["extra"]=1
    else:d.pop("rounding")
    with pytest.raises(PayrollBlocked,match="KR_PAID_STATEMENT_SOURCE"):verify(draft=d,**k)
def workbook():
    w=Workbook();w.active.append(["sku","item_name"]);w.active.append(["001","Widget"])
    f=io.BytesIO();w.save(f);w.close();return f.getvalue()
def mutate(raw,old,new):
    out=io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as zin,zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED) as zout:
        for n in zin.namelist():
            b=zin.read(n)
            if n=="xl/worksheets/sheet1.xml":
                assert b.count(old)==1
                b=b.replace(old,new)
            zout.writestr(n,b)
    return out.getvalue()
@pytest.mark.parametrize("old,new",[(b"<sheetData>",b"<sheetData>BAD"),(b"<row r=\"2\">",b"<row r=\"2\">BAD"),(b"</row></sheetData>",b"</row>BAD</sheetData>"),(b"</sheetData>",b"</sheetData>BAD")])
def test_real_xlsx_rejects(old,new):
    with pytest.raises(MappingBlocked,match="XLSX_MIXED_CONTENT"):parse_xlsx(mutate(workbook(),old,new))
def test_real_xlsx_normal():
    raw=workbook();assert parse_xlsx(raw)==(("sku","item_name"),(("001","Widget"),))
    assert parse_xlsx(mutate(raw,b"<sheetData>",b"<sheetData> \n"))==parse_xlsx(raw)
@pytest.mark.parametrize("bad",["BAD<si><t>ok</t></si>","<si><t>ok</t></si>BAD"])
def test_shared_string_root(bad):
    with pytest.raises(MappingBlocked,match="XLSX_MIXED_CONTENT"):
        shared_strings({"xl/sharedStrings.xml":ET.fromstring(f'<sst xmlns="{S}">{bad}</sst>')})
def test_incident_evidence_blocked_signal_preserved():
    mod=load(Path(os.environ["WAVE5_OUT"])/"incident-evidence.py","incident")
    now=datetime(2026,11,28,tzinfo=timezone.utc)
    r=mod.assess(expected_source="a"*40,observed_source="a"*40,observed_at=now,now=now,window_seconds=60,request_count=0,error_count=0,p95_ms=None,health_ok=False,policy=dict(max_age_seconds=60,minimum_requests=100,max_error_bps=100,max_p95_ms=250,window_seconds=60))
    assert r["status"]=="BLOCKED_EVIDENCE"
    assert r["observed_signals_unverified"]==["HEALTH_FAILURE"]
    assert not r["provider_verified"] and not r["rollback_authorized"] and not r["production_authorized"]
