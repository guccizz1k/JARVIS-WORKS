"""Fail-closed V21.8 unsupported document registration; synthetic isolated API only."""
from __future__ import annotations
import pytest
from tests.test_evidence_v64 import xlsx,stage,approve
from app.evidence_v64_worker import extract

UNSUPPORTED=(
 "정보보안동의서","개인(신용)정보 조회 동의서","개인정보수집동의서",
 "대출약정서","금융상품가입신청서","보험계약청약서","계좌개설신청서",
 "보안서약서","행정처분통지서","임직원교육확인서","고객확인서",
 "재직증명서","법인등기부등본","사업자등록증","정기예금약관",
 "은행정보조회서","수신동의서","금융거래확인서","수수료안내서",
 "연말정산간소화문서","근로계약서","전자서명동의서","위임장",
 "주민등록등본","거래관계확인서","고객민원처리확인서",
)

@pytest.mark.parametrize("source",UNSUPPORTED)
def test_unsupported_financial_document_cannot_be_rebranded(api,source):
    raw=xlsx(kind=source,reference="CONSENT-1")
    p=stage(api,"unrecognized.xlsx",raw)
    assert p.status_code==201,p.text
    p=p.json()
    assert p["document"]["document_kind"] is None,p["document"]
    assert p["document"]["kind_inference"] in ("unknown","ambiguous")
    assert p["status"]=="pending"
    result=approve(api,p)
    assert result.status_code==409,result.text
    assert "증빙 문서 유형" in result.text
    dashboard=api.get("/evidence/dashboard").json()
    assert dashboard["pending_review"]==1
    assert dashboard["total_confirmed"]==0
    assert not api.get("/evidence/records").json()
    assert api.get("/dashboard").json()["invoices"]==0


@pytest.mark.parametrize("expected,user_selected",[
    ("영수증","purchase_slip"),("매출전표","receipt"),
    ("매입전표","sales_slip"),("거래명세표","inventory_sheet"),
    ("재고표","trade_statement")
])
def test_recognized_type_cannot_be_rebranded(api,expected,user_selected):
    p=stage(api,"known.xlsx",xlsx(kind=expected)).json()
    assert p["document"]["document_kind"]
    r=approve(api,p,kind=user_selected)
    assert r.status_code==409,r.text
    assert api.get("/evidence/dashboard").json()["total_confirmed"]==0


@pytest.mark.parametrize("source,expected",[
    ("정보보안동의서","unknown"),
    ("미기재","unknown"),
    ("전자서명동의서","unknown")
])
def test_extract_retains_unknown_source_without_guessed_record_type(source,expected):
    result=extract("unknown.xlsx",xlsx(kind=source))
    assert result["document_kind"] is None
    assert result["kind_inference"]==expected
    assert result["proposed_record_type"] is None
    assert result["quality"]["needs_manual_review"] is True
    assert result["quality"]["calibrated_confidence"] is None


def test_recognized_receipt_can_still_be_reviewed_and_confirmed(api):
    p=stage(api,"supported.xlsx",xlsx()).json()
    assert p["document"]["document_kind"]=="receipt"
    assert approve(api,p).status_code==201
    assert api.get("/evidence/dashboard").json()["total_confirmed"]==1
    assert api.get("/dashboard").json()["invoices"]==0
