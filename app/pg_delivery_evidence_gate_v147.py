"""Review-only order-bound, two-party delivery evidence verifier.

No DB records, no public route, no proof of real physical delivery, and no
authorization for invoice/payment posting. Signing keys must be from genuinely
independent external issuers; local synthetic tests establish only code logic.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import AbstractSet, Mapping

from fastapi import HTTPException

_HEX32 = re.compile(r"^[a-f0-9]{32}$")
_HEX64 = re.compile(r"^[a-f0-9]{64}$")
_P = {"dispatch": "approved-dispatch-attestor-v1",
      "receipt": "approved-receipt-attestor-v1"}
_FIELDS = frozenset({"schema", "purpose", "issuer", "order_id", "org_id",
                     "source_sha256", "document_sha256", "items", "signer_id",
                     "nonce", "issued_at", "expires_at"})


class DeliveryProofRejected(ValueError):
    """Fixed denial prevents leaking signed payloads or private actor details."""


def _deny() -> None:
    raise DeliveryProofRejected("Delivery evidence invalid or unavailable")


def _json(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        _deny()


def _source(invoice_preview: Mapping, org_id: str) -> tuple[str, str, list[dict]]:
    if (not isinstance(invoice_preview, dict)
        or not isinstance(org_id, str) or not _HEX32.fullmatch(org_id)
        or invoice_preview.get("draft_only") is not True
        or invoice_preview.get("physical_delivery_verified") is not False
        or invoice_preview.get("approved_invoice_posted") is not False
        or invoice_preview.get("payment_posted") is not False):
        _deny()
    order_id = invoice_preview.get("order_id")
    source_sha = invoice_preview.get("source_sha256")
    if (not isinstance(order_id, str) or not _HEX32.fullmatch(order_id)
        or not isinstance(source_sha, str) or not _HEX64.fullmatch(source_sha)):
        _deny()
    fields = ("order_id", "source_quote_id", "source_order_no", "customer_id",
              "customer_name", "title", "vat_mode", "items", "money")
    if any(f not in invoice_preview for f in fields):
        _deny()
    try:
        from .pg_invoice_preview_v145 import build_invoice_preview
        order = (invoice_preview["order_id"], invoice_preview["source_quote_id"],
                 invoice_preview["source_order_no"], invoice_preview["customer_id"],
                 invoice_preview["customer_name"], "fulfilled", "acknowledged",
                 invoice_preview["vat_mode"], invoice_preview["title"])
        original_items = invoice_preview["items"]
        if not isinstance(original_items, list):
            _deny()
        lines = [(item["source_order_item_id"], item["name"], item["quantity"],
                  item["unit_price"], item["position"]) for item in original_items]
        regenerated = build_invoice_preview(order, lines)
    except (KeyError, TypeError, IndexError, AttributeError, ValueError, HTTPException):
        _deny()
    if (set(invoice_preview) != set(regenerated) or regenerated != invoice_preview
        or regenerated["source_sha256"] != source_sha):
        _deny()
    return order_id, source_sha, regenerated["items"]


def _validate(packet: Mapping, *, purpose: str, issuer_key: bytes,
              now: int, org_id: str, order_id: str, source_sha: str,
              lines: list[dict], consumed_nonces: AbstractSet[str]) -> tuple[str, str, str, int]:
    if (not isinstance(packet, dict) or set(packet) != _FIELDS | {"signature"}
        or type(issuer_key) is not bytes or len(issuer_key) < 32):
        _deny()
    payload = {f: packet[f] for f in _FIELDS}
    if (payload["schema"] != "jw-delivery-evidence-v147"
        or payload["purpose"] != purpose or payload["issuer"] != _P[purpose]
        or payload["order_id"] != order_id or payload["org_id"] != org_id
        or payload["source_sha256"] != source_sha
        or not isinstance(payload["document_sha256"], str)
        or not _HEX64.fullmatch(payload["document_sha256"])):
        _deny()
    if (not isinstance(payload["signer_id"], str)
        or not _HEX32.fullmatch(payload["signer_id"]) or
        not isinstance(payload["nonce"], str) or not _HEX32.fullmatch(payload["nonce"])
        or payload["nonce"] in consumed_nonces):
        _deny()
    issued, expiry = payload["issued_at"], payload["expires_at"]
    if (type(issued) is not int or type(expiry) is not int or
        not issued <= now < expiry or not 1 <= expiry - issued <= 86400):
        _deny()
    item_proofs = payload["items"]
    if not isinstance(item_proofs, list) or len(item_proofs) != len(lines):
        _deny()
    for saved, attested in zip(lines, item_proofs):
        if (not isinstance(attested, dict)
            or set(attested) != {"source_order_item_id", "delivered_quantity"}
            or attested["source_order_item_id"] != saved["source_order_item_id"]
            or type(attested["delivered_quantity"]) is not int
            or attested["delivered_quantity"] != saved["quantity"]):
            _deny()
    sig = packet["signature"]
    if not isinstance(sig, str) or not _HEX64.fullmatch(sig):
        _deny()
    expected = hmac.new(issuer_key, _json(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        _deny()
    return (payload["nonce"], payload["signer_id"],
            payload["document_sha256"], issued)


@dataclass(frozen=True)
class DeliveryReview:
    status: str
    source_sha256: str
    evidence_sha256: str
    physical_delivery_verified: bool = False
    invoice_posted: bool = False
    payment_posted: bool = False
    persistent_receipt_recorded: bool = False


def evaluate_delivery(*, invoice_preview: Mapping, org_id: str,
                      dispatch_proof: Mapping, recipient_proof: Mapping,
                      dispatch_key: bytes, recipient_key: bytes,
                      consumed_nonces: AbstractSet[str], now: int) -> DeliveryReview:
    """Review only. Actual signed physical proof, durable DB and audit needed."""
    if (type(now) is not int or now < 1 or
        type(dispatch_key) is not bytes or type(recipient_key) is not bytes
        or len(dispatch_key) < 32 or len(recipient_key) < 32
        or hmac.compare_digest(dispatch_key, recipient_key)
        or not isinstance(consumed_nonces, (set, frozenset))):
        _deny()
    order_id, source_sha, items = _source(invoice_preview, org_id)
    dispatch = _validate(dispatch_proof, purpose="dispatch", issuer_key=dispatch_key,
                         now=now, org_id=org_id, order_id=order_id,
                         source_sha=source_sha, lines=items,
                         consumed_nonces=consumed_nonces)
    recipient = _validate(recipient_proof, purpose="receipt", issuer_key=recipient_key,
                          now=now, org_id=org_id, order_id=order_id,
                          source_sha=source_sha, lines=items,
                          consumed_nonces=consumed_nonces)
    if (dispatch[0] == recipient[0] or dispatch[1] == recipient[1]
        or recipient[3] < dispatch[3]):
        _deny()
    digest = hashlib.sha256(_json({"source": source_sha,
                    "dispatch_receipt_nonce": dispatch[0],
                    "recipient_receipt_nonce": recipient[0],
                    "dispatch_document_sha256": dispatch[2],
                    "recipient_document_sha256": recipient[2]})).hexdigest()
    return DeliveryReview(status="EVIDENCE_VALIDATED_REVIEW_ONLY",
                          source_sha256=source_sha, evidence_sha256=digest)
