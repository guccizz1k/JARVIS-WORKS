"""V17.2 high difficulty, real deterministic document extraction acceptance.

No mocks of the actual extractor. Money/tenant document dates/hidden data
must never be silently interpreted as valid. Scanned PDF OCR remains BLOCKED:
this test requires safe rejection, not imaginary OCR accuracy certification.
"""
from __future__ import annotations

import io
from copy import deepcopy

import pytest
from openpyxl import Workbook, load_workbook

from app.import_engine import extract, verify, supplement_review, DocumentError
from tests.test_quote_import import ITEMS, FIELDS, qxlsx


def _rewrite(mutate):
    source=qxlsx()
    wb=load_workbook(io.BytesIO(source))
    mutate(wb)
    out=io.BytesIO()
    wb.save(out)
    wb.close()
    return out.getvalue()


@pytest.mark.parametrize(("field","value"),[
    ("총금액",176001),("총금액",175999),("총금액",-1),("총금액",True),
    ("총금액",0),("공급가액",159999),("공급가액",160001),
    ("공급가액","1,60,000"),("부가세",15999),("부가세",16001),
    ("부가세","16,00"),("과세구분","면세"),("과세구분","??"),
    ("견적일","2026-02-30"),("견적일","1999-12-31"),
    ("견적일","2101-01-01"),("견적일","2026-13-01"),
    ("문서종류","발주서"),("문서종류","청구서"),
    ("거래처","\n"),("거래처","X"*121),("제목","X"*151),
])
def test_22_external_metadata_attacks_rejected(field,value):
    with pytest.raises(DocumentError):
        extract("untrusted.xlsx",qxlsx({field:value}))


@pytest.mark.parametrize(("position","value"),[
    ("quantity",0),("quantity",-1),("quantity",100001),
    ("quantity",1.5),("quantity",True),("quantity","3.0"),
    ("quantity","1,00"),("unit_price",-1),
    ("unit_price",1000000001),("unit_price",1.5),
    ("line_total",135001),("line_total",0),
])
def test_12_line_amount_attacks_rejected(position,value):
    item=["유압 펌프",3,45000,135000]
    item[{"quantity":1,"unit_price":2,"line_total":3}[position]]=value
    with pytest.raises(DocumentError):
        extract("untrusted.xlsx",qxlsx(items=[tuple(item),ITEMS[1]]))


@pytest.mark.parametrize("case",[
    "hidden_row", "hidden_column", "formula", "unknown_item_header",
    "duplicate_item_header", "duplicate_quantity_header",
    "duplicate_price_header", "duplicate_name_header",
    "multiple_sheets", "gap_between_items",
    "data_after_total", "unrecognized_meta", "duplicate_conflicting_meta",
    "excess_items", "hidden_extra_row",
])
def test_16_ambiguous_workbook_structures_fail_closed(case):
    def mutate(wb):
        ws=wb.active
        if case=="hidden_row":
            ws.row_dimensions[12].hidden=True
        elif case=="hidden_column":
            ws.column_dimensions["C"].hidden=True
        elif case=="formula":
            ws.cell(12,3,"=45000*1")
        elif case=="unknown_item_header":
            ws.cell(11,5,"할인율")
            ws.cell(12,5,"10%")
        elif case=="duplicate_item_header":
            ws.cell(11,5,"금액")
            ws.cell(12,5,999)
        elif case=="duplicate_quantity_header":
            ws.cell(11,5,"수량")
            ws.cell(12,5,99)
        elif case=="duplicate_price_header":
            ws.cell(11,5,"단가")
            ws.cell(12,5,99)
        elif case=="duplicate_name_header":
            ws.cell(11,5,"품목명")
            ws.cell(12,5,"악성행")
        elif case=="multiple_sheets":
            wb.create_sheet("ambiguous")
        elif case=="gap_between_items":
            ws.insert_rows(13)
        elif case=="data_after_total":
            ws.append(["합계",None,None,160000])
            ws.append(["추가 품목",1,100,100])
        elif case=="unrecognized_meta":
            ws.insert_rows(2)
            ws.cell(2,1,"거래상대 신용등급")
            ws.cell(2,2,"매우 높음")
        elif case=="duplicate_conflicting_meta":
            ws.insert_rows(2)
            ws.cell(2,1,"거래처")
            ws.cell(2,2,"부정확한 다른 회사")
        elif case=="excess_items":
            for index in range(41):
                ws.append([f"누락 위험 {index}",1,100,100])
        elif case=="hidden_extra_row":
            ws.append(["숨겨진 추가 품목",1,1,1])
            ws.row_dimensions[ws.max_row].hidden=True
    with pytest.raises(DocumentError):
        extract("untrusted.xlsx",_rewrite(mutate))


@pytest.mark.parametrize("name,raw",[
    ("wrong_magic.xlsx",b"%PDF-1.0 invalid"),
    ("wrong_magic.pdf",b"PK\x03\x04 untrusted"),
    ("image.png",b"\x89PNG\r\n\x1a\n"),
    ("empty.xlsx",b""),
    ("overlimit.pdf",b"X"*(5*1024*1024+1)),
])
def test_5_bad_file_mime_or_size_denied(name,raw):
    with pytest.raises(DocumentError):
        extract(name,raw)


def test_40_exact_items_and_aggregate_money_preserve_original_lines():
    rows=[(f"검증품목{i:02}",1,100,100) for i in range(40)]
    doc=extract("40rows.xlsx",qxlsx({
        "공급가액":4000,"부가세":400,"총금액":4400
    },items=rows))
    assert doc["item_count"]==40
    assert doc["money"]=={"subtotal":4000,"vat":400,"total":4400}
    assert doc["ordered_quantity"]==40
    assert all(x["line_total"]==100 for x in doc["items"])


def test_invoice_rounding_correctly_half_up_not_banker_rounding():
    doc=extract("precision.xlsx",qxlsx({
        "공급가액":15,"부가세":2,"총금액":17,
    },items=[("small",1,15,15)]))
    assert doc["money"]=={"subtotal":15,"vat":2,"total":17}


def test_empty_scanned_pdf_is_explicitly_rejected_not_misreported_as_ocr():
    from reportlab.pdfgen import canvas
    out=io.BytesIO()
    pdf=canvas.Canvas(out)
    pdf.showPage()
    pdf.save()
    with pytest.raises(DocumentError,match="스캔|이미지"):
        extract("scanned.pdf",out.getvalue())


def test_nine_page_pdf_exceeds_limit_even_when_pages_are_valid():
    from reportlab.pdfgen import canvas
    out=io.BytesIO()
    pdf=canvas.Canvas(out)
    for i in range(9):
        pdf.drawString(40,700,f"Page {i}")
        pdf.showPage()
    pdf.save()
    with pytest.raises(DocumentError,match="8페이지"):
        extract("oversized_page_count.pdf",out.getvalue())


def test_review_cannot_silently_change_any_source_financial_value():
    doc=extract("customer-missing.xlsx",qxlsx({"거래처":""}),allow_missing=True)
    assert "company" in doc["missing_fields"]
    base=deepcopy(doc)
    for override in ({"subtotal":"1"},{"vat":"1"},{"total":"1"},
                     {"items":[]},{"quote_date":"2026-10-19"}):
        with pytest.raises(DocumentError):
            supplement_review(doc,override)
        assert doc==base
    supplemented=supplement_review(doc,{"company":"원본 확인 거래처"})
    assert supplemented["money"]==doc["money"]
    assert supplemented["items"]==doc["items"]
    assert supplemented["company"]=="원본 확인 거래처"


def test_line_formula_cannot_trick_missing_user_review_or_approved_trade():
    doc=extract("quote.xlsx",qxlsx())
    assert doc["record_type"]=="quote"
    assert "bank_reconciliation_verified" not in doc
    assert "approval_posted" not in doc
    assert doc["money"]=={"subtotal":160000,"vat":16000,"total":176000}
