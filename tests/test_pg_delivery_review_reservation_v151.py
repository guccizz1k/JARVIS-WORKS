"""V15.1 private reservation contract, no live DB credentials or real posting."""
from __future__ import annotations

import inspect
import pytest

from app.pg_delivery_evidence_gate_v147 import DeliveryReview
from app.pg_delivery_review_reservation_v151 import (
    PendingReviewRejected, reserve_delivery_review_v151)

ORG = "a" * 32
ACTOR = "1" * 32
ORDER_ID = "b" * 32
IDENTITY = ("jw_app_dev", ACTOR, ORG, "admin", "csrf", "Synthetic org")
ORDER = (ORDER_ID, "c" * 32, "O-001", "d" * 32, "Buyer",
         "fulfilled", "acknowledged", "taxable", "Test order")
LINES = [("l1", "Item 1", 2, 3000, 0), ("l2", "Item 2", 1, 1000, 1)]
PROOF_DISPATCH = {"nonce": "2" * 32, "signer_id": "3" * 32,
                  "issuer": "approved-dispatch-attestor-v1",
                  "document_sha256": "4" * 64, "signature": "5" * 64}
PROOF_RECEIPT = {"nonce": "6" * 32, "signer_id": "7" * 32,
                 "issuer": "approved-receipt-attestor-v1",
                 "document_sha256": "8" * 64, "signature": "9" * 64}


class CursorStub:
    def __init__(self, *, identity=IDENTITY, order=ORDER, invoice=None,
                 lines=LINES, existing_nonce=None):
        self.identity = identity
        self.order = order
        self.invoice = invoice
        self.lines = lines
        self.existing_nonce = existing_nonce
        self.sql = []
        self.latest = None

    def execute(self, statement, params=None):
        self.sql.append((statement, params))
        sql = " ".join(statement.split())
        if "stage_identity_v84()" in sql:
            self.latest = self.identity[:4]
        elif "FROM jw_dev.orders" in sql:
            self.latest = self.order
        elif "FROM jw_dev.invoices" in sql:
            self.latest = self.invoice
        elif "FROM jw_dev.review_delivery_nonces_v151" in sql:
            self.latest = self.existing_nonce
        else:
            self.latest = None

    def fetchone(self):
        return self.latest

    def fetchall(self):
        return self.lines


def run(cur, **kwargs):
    args = dict(cur=cur, validated_identity=IDENTITY, order_id=ORDER_ID,
                dispatch_proof=PROOF_DISPATCH,
                recipient_proof=PROOF_RECEIPT,
                independent_dispatch_key=b"a"*32,
                independent_recipient_key=b"b"*32,
                server_now=1793371000)
    args.update(kwargs)
    return reserve_delivery_review_v151(**args)


@pytest.fixture
def verified(monkeypatch):
    def check(**kwargs):
        assert kwargs["org_id"] == ORG
        assert kwargs["invoice_preview"]["order_id"] == ORDER_ID
        assert kwargs["invoice_preview"]["money"]["subtotal"] == 7000
        assert kwargs["dispatch_proof"] is PROOF_DISPATCH
        assert kwargs["recipient_proof"] is PROOF_RECEIPT
        return DeliveryReview("EVIDENCE_VALIDATED_REVIEW_ONLY",
                              kwargs["invoice_preview"]["source_sha256"], "e"*64)
    monkeypatch.setattr(
        "app.pg_delivery_review_reservation_v151.evaluate_delivery", check)


def test_verified_actor_and_order_are_locked_before_pending_review_writes(verified):
    cur = CursorStub()
    digest = run(cur)
    assert digest == "e"*64
    statements = [s for s, _ in cur.sql]
    joined = "\n".join(statements)
    assert "FOR UPDATE" in joined
    assert joined.index("FROM jw_dev.orders") < joined.index("INSERT INTO jw_dev.review_delivery_receipts_v151")
    assert len([x for x in statements if "INSERT INTO jw_dev.review_delivery_nonces_v151" in x]) == 2
    assert len([x for x in statements if "INSERT INTO jw_dev.review_delivery_items_v151" in x]) == 2
    assert not any("INSERT INTO jw_dev.invoices" in s or
                   "INSERT INTO jw_dev.payments" in s or
                   "UPDATE jw_dev.orders" in s for s in statements)
    assert not any("COMMIT" in s or "SET ROLE" in s for s in statements)
    assert len([x for x in statements if "INSERT INTO jw_dev.audit_logs" in x]) == 1
    assert statements[-1].find("INSERT INTO jw_dev.audit_logs") >= 0


@pytest.mark.parametrize("identity", [
    (), ("postgres", ACTOR, ORG, "admin", "csrf", "Synthetic org"),
    ("jw_app_dev", ACTOR, ORG, "staff", "csrf", "Synthetic org"),
    ("jw_app_dev", ACTOR, "wrong", "admin", "csrf", "Synthetic org"),
])
def test_untrusted_role_or_org_fails_before_db(identity):
    cur = CursorStub()
    with pytest.raises(PendingReviewRejected):
        run(cur, validated_identity=identity)
    assert not cur.sql


def test_db_identity_mismatch_fails_before_read_or_write():
    cur = CursorStub(identity=("jw_app_dev", "0"*32, ORG, "admin", "csrf", "Synthetic org"))
    with pytest.raises(PendingReviewRejected):
        run(cur)
    assert len(cur.sql) == 1


@pytest.mark.parametrize("condition", [
    {"order": None}, {"invoice": ("existing-invoice",)},
    {"existing_nonce": ("2"*32,)}, {"lines": []},
])
def test_missing_source_invoice_collision_replay_or_invalid_lines_fail(verified, condition):
    cur = CursorStub(**condition)
    with pytest.raises((PendingReviewRejected, ValueError)):
        run(cur)
    assert not any("INSERT INTO jw_dev.review_" in s for s, _ in cur.sql)


def test_ineligible_delivery_review_status_never_writes(monkeypatch):
    monkeypatch.setattr(
        "app.pg_delivery_review_reservation_v151.evaluate_delivery",
        lambda **_: DeliveryReview("APPROVED", "f"*64, "e"*64,
                                  physical_delivery_verified=True))
    cur = CursorStub()
    with pytest.raises(PendingReviewRejected):
        run(cur)
    assert not any("INSERT INTO" in s for s, _ in cur.sql)


def test_no_registered_api_no_privileged_dsn_no_autonomous_commit():
    from app import pg_delivery_review_reservation_v151 as module
    source = inspect.getsource(module)
    for forbidden in ("@router", "include_router(", "psycopg.connect(",
                      "SET LOCAL ROLE", "COMMIT;", "GRANT ", "service_role"):
        assert forbidden not in source


def test_audit_failure_propagates_without_autonomous_commit(verified):
    class AuditFailureCursor(CursorStub):
        def execute(self, statement, params=None):
            if "INSERT INTO jw_dev.audit_logs" in statement:
                self.sql.append((statement, params))
                raise RuntimeError("synthetic audit constraint")
            super().execute(statement, params)

    cur = AuditFailureCursor()
    with pytest.raises(RuntimeError, match="synthetic audit constraint"):
        run(cur)
    statements = [sql for sql, _ in cur.sql]
    assert "INSERT INTO jw_dev.review_delivery_receipts_v151" in "\n".join(statements)
    assert "INSERT INTO jw_dev.audit_logs" in statements[-1]
    assert not any("COMMIT" in sql for sql in statements)


def test_audit_payload_contains_only_source_digests(verified):
    cur = CursorStub()
    run(cur)
    sql, params = next((sql, params) for sql, params in cur.sql
                       if "INSERT INTO jw_dev.audit_logs" in sql)
    import json
    audit = json.loads(params[-1])
    assert set(audit) == {"source", "source_sha256", "evidence_sha256"}
    assert "signature" not in params[-1] and "nonce" not in params[-1]
    assert params[1] == ORG and params[2] == ACTOR
