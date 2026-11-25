"""Strict OCR *candidate* parser attacks; never claims source authenticity."""
import pytest

from scripts.ci_v178_real_ocr_synthetic import parse_fields

@pytest.mark.parametrize(("raw","expected"),[
    ("거래처: 한빛상사",{"counterparty":"한빛상사"}),
    ("고객사：ABC",{"counterparty":"ABC"}),
    ("사업자등록번호: 1234567890",{"business_number":"1234567890"}),
    ("사업자번호: 123-45-67890",{"business_number":"1234567890"}),
    ("사업자번호: 123 456 7890",{"business_number":"1234567890"}),
    ("총금액: 7,700",{"total_amount":"7700"}),
    ("총합계：7700",{"total_amount":"7700"}),
    ("총금액: 0007700",{"total_amount":"7700"}),
    ("총금액: 0",{"total_amount":"0"}),
    ("거래처: A\n총금액: 7700",{"counterparty":"A","total_amount":"7700"}),
    ("거래처: A\n거래처: A",{"counterparty":"A"}),
    ("거래처: A\n거래처: B",{}),
    ("총금액: 7000\n총금액: 7700",{}),
    ("사업자번호: 1234567890\n사업자번호: 1234567891",{}),
    ("거래처: A\n거래처: B\n거래처: A",{}),
    ("총금액: 7O00",{}),
    ("총금액: 7,700원",{}),
    ("사업자번호: 123-45-6789",{}),
    ("사업자번호: 12345678901",{}),
    ("사업자번호: 1234_567890",{}),
    ("비거래처: Forged",{}),
    ("가격총금액: 7700",{}),
    ("총금액 7700",{}),
    ("거래처 - A",{}),
    ("거래처: \nA",{}),
    ("총금액: -100",{}),
    ("총금액: 7.700",{}),
    ("총금액: 1e6",{}),
    ("총금액: 7,70",{}),
    ("사업자등록번호: 12 345 67890",{"business_number":"1234567890"}),
    ("고객사: A" + "x"*200,{}),
    ("견적일: 2026-10-31\n세액: 7700",{}),
    ("총금액: 7700\n총금액: 7700",{"total_amount":"7700"}),
])
def test_parser_abstains_on_ambiguity_and_rejects_forged_labels(raw,expected):
    assert parse_fields(raw)==expected


@pytest.mark.parametrize("raw", [None,{},[],True,42,"x"*20_001])
def test_unbounded_or_nontext_ocr_result_rejected(raw):
    with pytest.raises(ValueError):
        parse_fields(raw)


def test_no_customer_records_or_approval_controls_in_ocr_parser():
    assert parse_fields("사업자번호: 1234567890\n총금액: 100") == {
        "business_number":"1234567890","total_amount":"100"}
    # This module is a *candidate parser* and exports no persistence endpoint.
    from scripts import ci_v178_real_ocr_synthetic as mod
    assert not hasattr(mod,"register_ocr_approval")
    assert not hasattr(mod,"store_verified_document")
