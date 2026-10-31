"""Review-only V16.0 import evidence invariants; no real customer content."""
from hashlib import sha256
import json
from datetime import date

from cryptography.fernet import Fernet
from fastapi import FastAPI,HTTPException
import pytest

from app import pg_import_quote_v160 as subject
from app.import_engine import verify
from app.security_hardening import sealed_json


@pytest.fixture
def document(monkeypatch):
    monkeypatch.setenv("JW_DATA_KEY",Fernet.generate_key().decode())
    meta={"document_kind":"견적서","company":"Customer A","quote_date":"2026-10-31",
          "vat_mode":"taxable","subtotal":7000,"vat":700,"total":7700}
    items=[{"name":"Synthetic A","quantity":2,"unit_price":3500,"line_total":7000}]
    return verify(meta,items)


def make_input(doc):
    digest=sha256(json.dumps(doc,ensure_ascii=False,sort_keys=True,
                            separators=(",",":")).encode()).hexdigest()
    return sealed_json(doc),digest


def test_signed_encrypted_source_and_money_validation(document):
    raw,digest=make_input(document)
    assert raw.startswith("ENC1:")
    out,day,lines,money=subject._verified_doc(raw,digest)
    assert day==date(2026,10,31)
    assert lines==[("Synthetic A",2,3500)]
    assert money=={"subtotal":7000,"vat":700,"total":7700}
    assert out==document


@pytest.mark.parametrize("change",[
    lambda doc:doc.update(record_type="order"),
    lambda doc:doc.update(missing_fields=["company"]),
    lambda doc:doc.update(currency="USD"),
    lambda doc:doc["money"].update(vat=701),
    lambda doc:doc["items"][0].update(quantity=3),
    lambda doc:doc.update(quote_date="2026-02-30"),
])
def test_tampered_but_self_consistently_hashed_source_still_denied(document,change):
    change(document)
    raw,digest=make_input(document)
    with pytest.raises(HTTPException) as ex:
        subject._verified_doc(raw,digest)
    assert ex.value.status_code==409


def test_evidence_digest_is_immutable(document):
    raw,digest=make_input(document)
    with pytest.raises(HTTPException) as ex:
        subject._verified_doc(raw,"f"*64)
    assert ex.value.status_code==409


def test_invalid_or_overlarge_import_evidence_fails_closed(document):
    for raw in ("x"*65537,"not-json","ENC1:broken"):
        with pytest.raises(HTTPException) as ex:
            subject._verified_doc(raw,"f"*64)
        assert ex.value.status_code in (409,503)


def test_disabled_by_default_and_invalid_opt_in(monkeypatch):
    monkeypatch.delenv("JW_PG_IMPORT_QUOTE_V160",raising=False)
    assert subject.register_v160_pg_import_quote(FastAPI()) is False
    monkeypatch.setenv("JW_PG_IMPORT_QUOTE_V160","fake")
    with pytest.raises(RuntimeError):
        subject.register_v160_pg_import_quote(FastAPI())


def test_payment_and_finance_paths_never_written():
    import inspect
    source=inspect.getsource(subject)
    assert "INSERT INTO jw_dev.quotes" in source
    assert "INSERT INTO jw_dev.audit_logs" in source
    assert "INSERT INTO jw_dev.payments" not in source
    assert "INSERT INTO jw_dev.invoices" not in source
    assert "INSERT INTO jw_dev.orders" not in source
    assert "approval_posted" in source
    assert "JW_DATA_KEY" in source
