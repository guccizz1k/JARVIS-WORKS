"""CINEMA trade adapter HTTP regression with REAL FastAPI TestClient and FAKE SQL gateway.

This runs no database migrations and transmits only artificial bytes.
PASS tests HTTP parsing, auth ordering, CSRF, evidence bounds, response masking,
and delivery confirmation endpoint plumbing; NOT a Postgres or browser E2E proof.
"""
from __future__ import annotations

import hashlib

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.pg_cinema_trade_v1 import (
    MAX_EVIDENCE_BYTES, VerifiedSession, create_router,
)

REQ = "req-01234567890"
PATH = "/api/pg-stage/cinema-trade"
BODY = b"%PDF-1.7\n% synthetic evidence only\n"
SHA = hashlib.sha256(BODY).hexdigest()


class FakeGateway:
    def __init__(self):
        self.calls = []
        self.responses = None
        self.error = None

    def query(self, session_hash, sql, params):
        self.calls.append((session_hash, sql, params))
        if self.error is not None:
            raise self.error
        if self.responses is not None:
            return self.responses
        if "cinema_pg_evidence_put" in sql:
            return [{"result": {"content_sha256": hashlib.sha256(params[3]).hexdigest(),
                                "id": "synthetic-evidence-id"}}]
        if "cinema_pg_evidence_open" in sql:
            return [{"o_content": BODY, "o_content_type": "application/pdf",
                     "o_file_name": "synthetic.pdf", "o_sha256": SHA}]
        if "cinema_pg_delivery_confirm" in sql:
            return [{"result": {"entity": {"id": "synthetic-delivery"}, "status": "confirmed"}}]
        return []


@pytest.fixture
def http():
    gateway = FakeGateway()
    def authorize(request: Request):
        if request.headers.get("X-Test-Authenticated") != "yes":
            return VerifiedSession(session_hash="", csrf_verified=False)
        return VerifiedSession(session_hash="s" * 64,
                               csrf_verified=request.headers.get("X-Test-CSRF") == "yes")
    app = FastAPI(docs_url=None, openapi_url=None)
    app.include_router(create_router(gateway, authorize))
    with TestClient(app) as client:
        yield client, gateway


def headers(*, auth=True, csrf=True, content_type="application/pdf"):
    h = {"Content-Type": content_type}
    if auth:
        h["X-Test-Authenticated"] = "yes"
    if csrf:
        h["X-Test-CSRF"] = "yes"
    return h


def upload(client, data=BODY, **kwargs):
    return client.post(PATH + "/evidence", params={"request_id": REQ, "name": "synthetic.pdf"},
                       content=data, headers=headers(**kwargs))


def test_upload_rejects_missing_login_before_sql(http):
    client, gate = http
    assert upload(client, auth=False).status_code == 401
    assert gate.calls == []


def test_upload_rejects_missing_csrf_before_sql(http):
    client, gate = http
    assert upload(client, csrf=False).status_code == 403
    assert gate.calls == []


@pytest.mark.parametrize("ctype", ["text/plain", "application/octet-stream",
                                    "application/pdfx", "image/svg+xml"])
def test_upload_rejects_unsupported_file_type(http, ctype):
    client, gate = http
    assert upload(client, content_type=ctype).status_code == 415
    assert gate.calls == []


def test_empty_upload_rejected_before_gateway(http):
    client, gate = http
    assert upload(client, data=b"").status_code == 422
    assert gate.calls == []


def test_evidence_size_over_limit_rejected_before_gateway(http):
    client, gate = http
    assert upload(client, data=b"Z" * (MAX_EVIDENCE_BYTES + 1)).status_code == 413
    assert gate.calls == []


def test_uploaded_bytes_are_forwarded_unchanged_and_hash_comes_from_gateway(http):
    client, gate = http
    r = upload(client)
    assert r.status_code == 200, r.text
    assert r.json()["content_sha256"] == SHA
    assert len(gate.calls) == 1
    session, sql, args = gate.calls[0]
    assert session == "s" * 64
    assert sql.startswith("SELECT jw_dev.cinema_pg_evidence_put")
    assert args == (REQ, "synthetic.pdf", "application/pdf", BODY)


def test_upload_database_empty_result_fails_closed(http):
    client, gate = http
    gate.responses = []
    r = upload(client)
    assert r.status_code == 503
    assert len(gate.calls) == 1


def test_evidence_open_requires_login_and_csrf(http):
    client, gate = http
    for h, code in ((headers(auth=False), 401), (headers(csrf=False), 403)):
        r = client.post(PATH + "/evidence/synthetic-id/open",
                        json={"request_id": REQ}, headers={**h, "Content-Type": "application/json"})
        assert r.status_code == code
    assert gate.calls == []


def test_evidence_open_returns_no_cache_audited_download(http):
    client, gate = http
    r = client.post(PATH + "/evidence/synthetic-id/open",
                    json={"request_id": REQ}, headers=headers(content_type="application/json"))
    assert r.status_code == 200, r.text
    assert r.content == BODY
    assert r.headers["X-Evidence-SHA256"] == SHA
    assert r.headers["Cache-Control"] == "no-store"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Content-Disposition"].startswith("attachment;")
    assert len(gate.calls) == 1
    assert "cinema_pg_evidence_open" in gate.calls[0][1]


def test_evidence_open_without_row_is_404(http):
    client, gate = http
    gate.responses = []
    r = client.post(PATH + "/evidence/synthetic-id/open",
                    json={"request_id": REQ}, headers=headers(content_type="application/json"))
    assert r.status_code == 404


def test_evidence_open_invalid_stored_media_type_fails_closed(http):
    client, gate = http
    gate.responses = [{"o_content": BODY, "o_content_type": "text/html",
                       "o_file_name": "synthetic.pdf", "o_sha256": SHA}]
    r = client.post(PATH + "/evidence/synthetic-id/open",
                    json={"request_id": REQ}, headers=headers(content_type="application/json"))
    assert r.status_code == 503


def test_sql_internal_diagnostic_is_never_exposed_over_real_http(http):
    client, gate = http
    class DbError(Exception):
        sqlstate = "23514"
        class diag:
            message_primary = "SECRET_PASSWORD=DO_NOT_ECHO_PRIVATE_DATA"
    gate.error = DbError("SECRET_PASSWORD=DO_NOT_ECHO_PRIVATE_DATA")
    r = upload(client)
    assert r.status_code == 422
    assert "SECRET_PASSWORD" not in r.text
    assert "PRIVATE_DATA" not in r.text
    assert r.json() == {"detail": "Request rejected by trade rules"}


def test_delivery_confirmation_requires_csrf_before_gateway(http):
    client, gate = http
    r = client.post(PATH + "/deliveries/synthetic-id/confirm",
                    json={"request_id": REQ}, headers=headers(csrf=False,content_type="application/json"))
    assert r.status_code == 403
    assert gate.calls == []


def test_delivery_confirmation_passes_only_auditable_request_id(http):
    client, gate = http
    r = client.post(PATH + "/deliveries/synthetic-id/confirm",
                    json={"request_id": REQ}, headers=headers(content_type="application/json"))
    assert r.status_code == 200
    assert len(gate.calls) == 1
    assert "cinema_pg_delivery_confirm" in gate.calls[0][1]
    assert gate.calls[0][2] == (REQ, "synthetic-id")
