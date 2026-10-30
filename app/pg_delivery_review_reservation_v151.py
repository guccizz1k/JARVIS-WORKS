"""Internal V15.1 delivery review reservation; no public router, activation or posting.

The caller MUST provide the authenticated, role-limited cursor inside an existing
PostgreSQL transaction (pg_v90_integrated_entry._pg_validated_cursor).  No new
table privileges are granted by the V15.1 candidate DDL: the function therefore
FAILS CLOSED until a separately reviewed restricted-role grant/approval exists.
It cannot be used for live physical-delivery approval or invoice/payment posting.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping
from uuid import uuid4

from fastapi import HTTPException

from .pg_delivery_evidence_gate_v147 import evaluate_delivery
from .pg_invoice_preview_v145 import build_invoice_preview

_ID = re.compile(r"^[a-f0-9]{32}$")


class PendingReviewRejected(ValueError):
    """Fixed-text rejection: neither tenant identifiers nor evidence leaks."""


def _deny() -> None:
    raise PendingReviewRejected("Delivery review storage unavailable or invalid")


def _proof_digest(packet: Mapping[str, Any]) -> str:
    if not isinstance(packet, dict):
        _deny()
    try:
        raw = json.dumps(packet, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, UnicodeError, ValueError):
        _deny()
    return hashlib.sha256(raw).hexdigest()


def reserve_delivery_review_v151(
    cur: Any, *,
    validated_identity: tuple,
    order_id: str,
    dispatch_proof: dict,
    recipient_proof: dict,
    independent_dispatch_key: bytes,
    independent_recipient_key: bytes,
    server_now: int,
) -> str:
    """Persist ONLY PENDING_HUMAN_REVIEW, atomically in the *caller's* DB tx.

    No COMMIT, auto-approval, existing order UPDATE, invoice/payment INSERT, or
    fallback to privileged role. UNIQUE order/nonce constraints arbitrate races.
    """
    if (not isinstance(validated_identity, tuple)
        or len(validated_identity) != 6
        or validated_identity[0] not in ("jw_app_dev", "jw_delivery_writer_v159")
        or validated_identity[3] != "admin"
        or not isinstance(validated_identity[2], str)
        or not _ID.fullmatch(validated_identity[2])
        or not isinstance(order_id, str) or not _ID.fullmatch(order_id)):
        _deny()
    org_id = validated_identity[2]
    # Independently verify the *current* PostgreSQL session context, not the
    # HTTP body, cookie-derived org string or an unverified test identity.
    cur.execute("""SELECT current_user,actor_id,org_id,actor_role
                   FROM jw_dev.stage_identity_v84()""")
    db_identity = cur.fetchone()
    if db_identity != (
        validated_identity[0], validated_identity[1],
        validated_identity[2], validated_identity[3]
    ):
        _deny()
    # Transaction-scoped advisory lock serializes same-order writers WITHOUT
    # granting the dedicated review writer UPDATE privilege on source orders.
    # The PRIMARY KEY receipt is a separate final concurrency arbiter.
    cur.execute(
        "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(%s,0))",
        (order_id,),
    )
    cur.execute("""SELECT id,quote_id,doc_no,customer_id,
                          customer_name_snapshot,status,review_state,vat_mode,title
                   FROM jw_dev.orders WHERE id=%s AND org_id=%s""",
                (order_id, org_id))
    order = cur.fetchone()
    if order is None:
        _deny()
    cur.execute("""SELECT id FROM jw_dev.invoices
                   WHERE order_id=%s AND org_id=%s LIMIT 1""",
                (order_id, org_id))
    if cur.fetchone():
        _deny()
    cur.execute("""SELECT id,name,quantity,unit_price,position
                   FROM jw_dev.order_items
                   WHERE order_id=%s ORDER BY position,id""", (order_id,))
    try:
        preview = build_invoice_preview(order, cur.fetchall())
    except (HTTPException, TypeError, ValueError):
        _deny()
    # Proof verifier requires truly independent issuer keys and signed
    # external evidence. Synthetic key pairs must never be shipped.
    review = evaluate_delivery(
        invoice_preview=preview, org_id=org_id,
        dispatch_proof=dispatch_proof, recipient_proof=recipient_proof,
        dispatch_key=independent_dispatch_key,
        recipient_key=independent_recipient_key,
        consumed_nonces=frozenset(), now=server_now,
    )
    if (review.status != "EVIDENCE_VALIDATED_REVIEW_ONLY"
        or review.physical_delivery_verified
        or review.invoice_posted or review.payment_posted
        or review.persistent_receipt_recorded):
        _deny()
    proof_hashes = (_proof_digest(dispatch_proof), _proof_digest(recipient_proof))
    # Read prior nonces with the SAME authenticated tenant context. A unique
    # database index is the final concurrency/replay arbiter.
    nonces = (dispatch_proof["nonce"], recipient_proof["nonce"])
    cur.execute("""SELECT nonce FROM jw_dev.review_delivery_nonces_v151
                   WHERE nonce IN (%s,%s)""", nonces)
    if cur.fetchone():
        _deny()
    money = preview["money"]
    cur.execute("""INSERT INTO jw_dev.review_delivery_receipts_v151
       (order_id,org_id,source_sha256,evidence_sha256,
        dispatch_document_sha256,recipient_document_sha256,
        dispatch_actor,recipient_actor,subtotal_krw,vat_krw,total_krw)
       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
       (order_id, org_id, review.source_sha256, review.evidence_sha256,
        dispatch_proof["document_sha256"], recipient_proof["document_sha256"],
        dispatch_proof["signer_id"], recipient_proof["signer_id"],
        money["subtotal"], money["vat"], money["total"]))
    for purpose, packet, digest in (
        ("dispatch", dispatch_proof, proof_hashes[0]),
        ("receipt", recipient_proof, proof_hashes[1]),
    ):
        cur.execute("""INSERT INTO jw_dev.review_delivery_nonces_v151
            (nonce,order_id,purpose,issuer,proof_sha256)
            VALUES (%s,%s,%s,%s,%s)""",
            (packet["nonce"], order_id, purpose, packet["issuer"], digest))
    for item in preview["items"]:
        cur.execute("""INSERT INTO jw_dev.review_delivery_items_v151
            (order_id,source_item_id,position,quantity,unit_price_krw)
            VALUES (%s,%s,%s,%s,%s)""",
            (order_id, item["source_order_item_id"], item["position"],
             item["quantity"], item["unit_price"]))
    # Audit write is mandatory and part of the SAME database transaction.
    # Failed audit insertion must roll back both receipt and proof nonces.
    audit_detail = json.dumps({
        "source": "v154_signed_delivery_pending_review",
        "source_sha256": review.source_sha256,
        "evidence_sha256": review.evidence_sha256,
    }, sort_keys=True, separators=(",", ":"))
    cur.execute("""INSERT INTO jw_dev.audit_logs
        (id,org_id,actor_id,entity_type,entity_id,action,detail,created_at)
        VALUES (%s,%s,%s,'delivery_review',%s,'request',%s,now()::text)""",
        (uuid4().hex, org_id, validated_identity[1], order_id, audit_detail))
    return review.evidence_sha256
