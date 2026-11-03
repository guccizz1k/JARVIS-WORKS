"""Fail-closed V145 invoice-preview tests; mock only the DB edge."""
from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException, Response
from app import pg_invoice_preview_v145 as preview

OID = "a" * 32
ORDER = (OID, "b" * 32, "O-123", "c" * 32, "Customer A",
         "fulfilled", "acknowledged", "taxable", "Order A")
LINES = [("i1", "Product", 2, 100, 0), ("i2", "Service", 1, 50, 1)]


def test_arithmetic_snapshot_deterministic_and_no_posting():
    result = preview.build_invoice_preview(ORDER, LINES)
    assert result["money"] == {"subtotal": 250, "vat": 25, "total": 275}
    assert len(result["source_sha256"]) == 64
    assert result["source_sha256"] == preview.build_invoice_preview(ORDER, LINES)["source_sha256"]
    assert result["draft_only"] and result["requires_human_approval"]
    assert not result["physical_delivery_verified"] and not result["approved_invoice_posted"]
    assert not result["payment_posted"]


def test_exempt_vat_and_changed_amount_changes_hash():
    exempt = list(ORDER)
    exempt[7] = "exempt"
    assert preview.build_invoice_preview(tuple(exempt), LINES)["money"]["vat"] == 0
    assert preview.build_invoice_preview(ORDER, LINES)["source_sha256"] != preview.build_invoice_preview(
        ORDER, [("i1", "Product", 2, 101, 0), LINES[1]])["source_sha256"]


@pytest.mark.parametrize("status,review", [("received", "acknowledged"),
    ("fulfilled", "pending"), ("cancelled", "clean")])
def test_cannot_preview_unfulfilled_or_unacknowledged(status, review):
    data = list(ORDER)
    data[5:7] = [status, review]
    with pytest.raises(HTTPException) as exc:
        preview.build_invoice_preview(tuple(data), LINES)
    assert exc.value.status_code == 409


@pytest.mark.parametrize("lines", [[], [("x", "", 1, 1, 0)],
    [("x", "Item", True, 1, 0)], [("x", "Item", 1, -1, 0)],
    [("x", "Item", 1, 1, 1)], [("x", "Item", 0, 1, 0)],
    [("x", "Item", 1, 0, 0)],
    [("x", "Item", 1, 1, 0), ("x", "Item", 1, 1, 1)],
    [("x", "Item", 100000, 1000000000, 0)] * 41])
def test_invalid_line_fail_closed(lines):
    with pytest.raises(HTTPException):
        preview.build_invoice_preview(ORDER, lines)


class Cursor:
    def __init__(self, *, order=ORDER, invoice=None, lines=LINES):
        self.responses = [order, invoice, lines]
        self.executed = []
    def execute(self, sql, args):
        self.executed.append((sql, args))
    def fetchone(self):
        return self.responses.pop(0)
    def fetchall(self):
        return self.responses.pop(0)


def _route(*, order=ORDER, invoice=None, lines=LINES):
    cur = Cursor(order=order, invoice=invoice, lines=lines)
    @contextmanager
    def fake_cursor(_):
        yield cur, ("jw_app_dev", "actor", "orgA", "admin", "csrf", "Org A")
    with patch.object(preview.quotes, "enabled", return_value=True), \
         patch.object(preview.sessions, "_session_hash", return_value="hashed"), \
         patch.object(preview.sessions, "_pg_validated_cursor", fake_cursor):
        response = Response()
        result = preview.invoice_preview(OID, SimpleNamespace(), response)
    return result, response, cur


def test_route_uses_server_verified_company_id_and_no_store():
    data, response, cur = _route()
    assert data["money"]["total"] == 275
    assert response.headers["Cache-Control"] == "no-store"
    assert len(cur.executed) == 3
    assert cur.executed[0][1] == (OID, "orgA")
    assert cur.executed[1][1] == (OID, "orgA")
    assert all("INSERT" not in sql and "UPDATE" not in sql and "DELETE" not in sql
               for sql, _ in cur.executed)


def test_other_enterprise_and_existing_invoice_rejected():
    for kwargs, status in (({"order": None}, 404), ({"invoice": ("inv123",)}, 409)):
        with pytest.raises(HTTPException) as exc:
            _route(**kwargs)
        assert exc.value.status_code == status


def test_invalid_id_does_not_query_database():
    with patch.object(preview.quotes, "enabled", return_value=True):
        with pytest.raises(HTTPException) as exc:
            preview.invoice_preview("../other", SimpleNamespace(), Response())
        assert exc.value.status_code == 404


def test_disabled_gate_stays_closed():
    with patch.object(preview.quotes, "enabled", return_value=False):
        assert preview.register_v145_invoice_preview(SimpleNamespace()) is False
        with pytest.raises(HTTPException) as exc:
            preview.invoice_preview(OID, SimpleNamespace(), Response())
        assert exc.value.status_code == 404


def test_only_readonly_verified_stage2_checks_are_allowed():
    from pathlib import Path
    source = Path(__file__).parents[1] / "scripts/review/v145_signup_readiness_readonly.sql"
    query = source.read_text()
    assert "PASS_EXISTING_PREREQUISITES_ONLY" in query
    assert "'BLOCKED'::text AS stage2_release_acceptance" in query
    assert "'NOT_VERIFIED'::text AS email_delivery_and_password_reset" in query
    for forbidden in ("INSERT INTO ", "UPDATE jw_dev.", "DELETE FROM ",
                      "CREATE ROLE", "GRANT ", "COMMIT;", "ALTER TABLE "):
        assert forbidden not in query
