"""No ambiguous or non-previewed XLSX source parts can enter a trade ledger."""
from __future__ import annotations

import io
import stat
import warnings
import zipfile

import pytest

from app.import_engine import DocumentError, extract
from tests.test_smart_import import make_xlsx


def modified_package(extra_name, content=b"ignored", *, zipinfo=None):
    base=make_xlsx()
    data=io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(base)) as src:
        with zipfile.ZipFile(data,"w",compression=zipfile.ZIP_DEFLATED) as dst:
            for part in src.infolist():
                dst.writestr(part,src.read(part))
            with warnings.catch_warnings():
                warnings.simplefilter("ignore",UserWarning)
                dst.writestr(zipinfo or extra_name,content)
    return data.getvalue()


def test_standard_offline_xlsx_still_accepted_without_rewriting_source():
    original=make_xlsx()
    info=extract("original.xlsx",original)
    assert info["money"]=={"subtotal":1_550_000,"vat":155_000,
                          "total":1_705_000}
    assert original==make_xlsx()  # deterministic fixture, source is untouched


def test_duplicate_worksheet_entry_cannot_mislead_parser():
    raw=make_xlsx()
    with zipfile.ZipFile(io.BytesIO(raw)) as src:
        sheet=src.read("xl/worksheets/sheet1.xml")
    forged=modified_package("xl/worksheets/sheet1.xml",sheet)
    with pytest.raises(DocumentError,match="중복"):
        extract("ambiguous.xlsx",forged)


@pytest.mark.parametrize("path",[
    "XL/WORKBOOK.XML",  # normal workbook.xml is already in the ZIP
    "xl/../xl/sheet1.xml",
    "xl//payload.xml",
    "../shadow.xml",
    "/xl/hidden.xml",
    "xl\\hidden.xml",
    "xl/./hidden.xml",
])
def test_ambiguous_case_and_internal_paths_fail_closed(path):
    with pytest.raises(DocumentError,match="중복|내부 경로"):
        extract("path.xlsx",modified_package(path))


@pytest.mark.parametrize("name",[
    "xl/embeddings/oleObject1.bin",
    "xl/activeX/activeX1.bin",
    "xl/externalLinks/externalLink1.xml",
    "xl/vbaPROJECT.bin",        # old case-sensitive macro scan missed this
    "xl/connections.xml",
    "xl/queryTables/queryTable1.xml",
    "xl/webextensions/webextension1.xml",
])
def test_invisible_payloads_and_external_sources_rejected(name):
    with pytest.raises(DocumentError,match="매크로|숨은 첨부"):
        extract("invisible.xlsx",modified_package(name))


def test_external_relationship_rejected_even_without_external_links_path():
    relationships=(b'<?xml version="1.0"?>'
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId9" Type="urn:external-test" '
        b'Target="https://attacker.invalid/private.xlsx" TargetMode="External"/>'
        b'</Relationships>')
    with pytest.raises(DocumentError,match="외부 파일 연결"):
        extract("external.xlsx",modified_package("xl/drawings/_rels/drawing1.xml.rels",relationships))


def test_encrypted_or_symlink_member_denied_before_workbook_parse():
    link=zipfile.ZipInfo("xl/media/shortcut")
    link.create_system=3
    link.external_attr=stat.S_IFLNK<<16
    with pytest.raises(DocumentError,match="지원하지 않는 압축"):
        extract("link.xlsx",modified_package(link.filename,b"../secret",zipinfo=link))


def test_original_document_to_settlement_source_not_changed():
    assert extract("test.xlsx",make_xlsx())["record_type"]=="order"


def test_malformed_xlsx_http_preview_rejects_without_db_changes(tmp_path, monkeypatch):
    """Real review adapter HTTP boundary: reject before preview/order writes."""
    from fastapi.testclient import TestClient
    from app import main as core
    from app.owner_review_app_v223 import app as qa_app

    for name,value in {
        "JW_ENV":"review",
        "JW_ROOT_UI":"owner-visual-review",
        "JW_APPROVED_UI_REVIEW":"ISOLATED_REVIEW_ONLY",
        "JW_NO_EXTERNAL_DATABASE":"1",
        "DEMO_SEED":"1",
    }.items():
        monkeypatch.setenv(name,value)
    monkeypatch.delenv("JW_PUBLIC_QA_MODE",raising=False)
    monkeypatch.setattr(core,"DB_PATH",tmp_path/"xlsx_validation_http.db")
    with TestClient(qa_app,base_url="https://testserver") as client:
        login=client.post("/api/login",json={
            "email":"demo@hanbit.example","password":"Demo!2026secure"})
        assert login.status_code==200
        token=login.cookies.get(core.SESSION_COOKIE)
        assert token
        auth={"Cookie":core.SESSION_COOKIE+"="+token,
              "X-CSRF-Token":login.json()["csrf_token"]}
        original_queue=client.get("/api/imports/queue",headers=auth)
        original_orders=client.get("/api/orders",headers=auth)
        assert original_queue.status_code==original_orders.status_code==200
        forged=modified_package("XL/WORKBOOK.XML")
        rejected=client.post("/api/imports/preview",headers=auth,
            files={"file":("ambiguous.xlsx",forged,
                           "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")})
        assert rejected.status_code==422
        assert client.get("/api/imports/queue",headers=auth).json()==original_queue.json()
        assert client.get("/api/orders",headers=auth).json()==original_orders.json()
