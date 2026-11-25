"""V21.9 exact source-bound evidence preview; synthesized files and isolated tenant only."""
from __future__ import annotations
import hashlib
import pytest
from tests.test_evidence_v64 import stage,xlsx,approve


@pytest.mark.parametrize("kind",["영수증","거래명세표","매출전표","매입전표","재고표"])
def test_current_upload_returns_hash_for_source_comparison(api,kind):
    data=xlsx(kind=kind,reference="V219-"+kind)
    result=stage(api,"source.xlsx",data)
    assert result.status_code==201,result.text
    payload=result.json()
    assert payload["source_file_sha256"]==hashlib.sha256(data).hexdigest()
    assert payload["original_file_stored"] is False
    assert payload["status"]=="pending"
    assert payload["confirmation_required"] is True
    assert api.get("/evidence/dashboard").json()["total_confirmed"]==0


@pytest.mark.parametrize("kind",["영수증","거래명세표","매출전표","매입전표","재고표"])
def test_reopened_preview_hash_stable_without_source_bytes(api,kind):
    data=xlsx(kind=kind,reference="V219-"+kind)
    created=stage(api,"source.xlsx",data).json()
    reopened=api.get("/evidence/preview/"+created["id"])
    assert reopened.status_code==200,reopened.text
    assert reopened.json()["source_file_sha256"]==hashlib.sha256(data).hexdigest()
    assert reopened.json()["original_file_stored"] is False
    assert reopened.json()["digest"]==created["digest"]
    assert "source_file_contents" not in reopened.json()
    assert api.get("/evidence/dashboard").json()["total_confirmed"]==0


def test_other_tenant_cannot_read_source_hash(api):
    data=xlsx(reference="V219-tenant")
    created=stage(api,"a.xlsx",data).json()
    assert api.c.post("/api/login",json={"email":"demo@bada.example","password":"Demo!2026secure"}).status_code==200
    cookie=api.c.cookies.get(__import__("app.main",fromlist=["SESSION_COOKIE"]).SESSION_COOKIE)
    res=api.c.get("/api/evidence/preview/"+created["id"],headers={"Cookie":__import__("app.main",fromlist=["SESSION_COOKIE"]).SESSION_COOKIE+"="+cookie})
    assert res.status_code in (403,404)
    assert "source_file_sha256" not in res.text


def test_unsupported_document_cannot_confirm_even_with_source_hash(api):
    created=stage(api,"consent.xlsx",xlsx(kind="개인정보동의서",reference="V219-CONSENT")).json()
    assert created["source_file_sha256"]
    assert created["document"]["document_kind"] is None
    assert approve(api,created).status_code==409
    assert api.get("/evidence/dashboard").json()["total_confirmed"]==0
