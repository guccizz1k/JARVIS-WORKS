"""Actual review-only Docker isolation and original parser 60+ adversarial checks.

A local Docker network-none result is not a hosted/production release PASS.
"""
from __future__ import annotations

from io import BytesIO
from unittest.mock import patch

from openpyxl import Workbook

from app.import_engine import extract as original
from app.security_hardening import lock_file_scan
from scripts.review import v204_offline_parser as isolated


def valid_quote() -> bytes:
    wb=Workbook()
    sheet=wb.active
    fields=[
        ("문서종류","견적서"),("거래처","Customer A"),
        ("견적일","2026-10-31"),("견적번호","Q-V204-SYNTHETIC"),
        ("과세구분","과세"),("제목","V204 synthetic quote"),
        ("공급가액",160000),("부가세",16000),("총금액",176000),
    ]
    for i,(k,v) in enumerate(fields,1):
        sheet.cell(i,1,k);sheet.cell(i,2,v)
    sheet.append(["품목명","수량","단가","금액"])
    sheet.append(["Synthetic pump",3,45000,135000])
    sheet.append(["Synthetic seal",2,12500,25000])
    out=BytesIO();wb.save(out);wb.close()
    return out.getvalue()


def main() -> None:
    proof=isolated.probe()
    assert proof["blocked"]==20
    raw=valid_quote()
    expected=original("v204-synthetic.xlsx",raw,allow_missing=True)
    actual=isolated.extract("v204-synthetic.xlsx",raw)
    assert actual==expected
    assert actual["money"]=={"subtotal":160000,"vat":16000,"total":176000}
    print("PASS_V204_REAL_ORIGINAL_PARSER_EQUIVALENCE",flush=True)

    # Twenty malformed XLSX/PDF files, not 20 copies of the same input.
    rejected=0
    for i in range(10):
        bad=b"PK"+bytes((3,4))+bytes([i])*((i+1)*17)
        try:isolated.extract(f"invalid-{i}.xlsx",bad)
        except ValueError:rejected+=1
        else:raise AssertionError("V204_CORRUPT_XLSX_ACCEPTED")
    for i in range(10):
        bad=b"%PDF-"+bytes([i+1])*((i+1)*23)
        try:isolated.extract(f"invalid-{i}.pdf",bad)
        except ValueError:rejected+=1
        else:raise AssertionError("V204_CORRUPT_PDF_ACCEPTED")
    assert rejected==20

    # Twenty hostile names denied before passing source bytes to any parser.
    names=[f"../attack-{i}.xlsx" for i in range(5)]
    names += [f"sub/attack-{i}.pdf" for i in range(5)]
    names += [f"sub\\\\attack-{i}.xlsx" for i in range(5)]
    names += [f"bad-{i}{chr(10)}.xlsx" for i in range(5)]
    for name in names:
        try:isolated.extract(name,raw)
        except ValueError:pass
        else:raise AssertionError("V204_UNSAFE_FILENAME_ACCEPTED")
    for size in (b"",b"x"*(5*1024*1024+1)):
        try:isolated.extract("file.xlsx",size)
        except ValueError:pass
        else:raise AssertionError("V204_SIZE_GATE_FAILED")
    with patch.dict("os.environ",{"JW_ENV":"production","JW_UPLOAD_SCAN":"off"}):
        try:lock_file_scan(b"not-a-document")
        except RuntimeError:pass
        else:raise AssertionError("V204_PRODUCTION_AV_BYPASS_ALLOWED")
    with patch.dict("os.environ",{"JW_ENV":"production","JW_V204_ISOLATED":isolated.ACK}):
        try:isolated.extract("file.xlsx",raw)
        except RuntimeError:pass
        else:raise AssertionError("V204_PRODUCTION_REVIEW_IMAGE_ALLOWED")
    print("PASS_V204_20_REAL_NETWORK_AND_FILESYSTEM_ESCAPE_PROBES",flush=True)
    print("PASS_V204_20_MALFORMED_DOCUMENTS_REJECTED",flush=True)
    print("PASS_V204_20_UNSAFE_FILENAMES_REJECTED",flush=True)
    print("PASS_V204_SIZE_AND_PRODUCTION_SCAN_BYPASS_FAIL_CLOSED",flush=True)
    print("LIMIT_V204_CI_ONLY_NO_SIGNATURE_FRESHNESS_OR_HOSTED_AV",flush=True)
    print("LIMIT_V204_NO_REAL_KOREAN_OCR_CORPUS_OR_HOSTED_DR",flush=True)


if __name__=="__main__":
    main()
