"""V15.4 isolated HTTPS delivery-proof REVIEW ONLY route.

Disabled by default. This is not a delivery acceptance, invoice posting,
payment, official issuer verification service, or public signup endpoint.
Successful requests atomically reserve PENDING_HUMAN_REVIEW only, using the
existing restricted PG trade session/transaction; no privileged connection.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import time
from typing import Any

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict
from psycopg import errors

from . import pg_quote_api_v92 as quotes
from . import pg_v90_integrated_entry as sessions
from .pg_delivery_evidence_gate_v147 import DeliveryProofRejected
from .pg_delivery_review_reservation_v151 import (
    PendingReviewRejected, reserve_delivery_review_v151,
)

_MODE = "ISOLATED_DEV_SIGNED_RECEIPT_REVIEW_ONLY"
_PREFIX = "/api/pg-stage/v154"
_ID = re.compile(r"^[a-f0-9]{32}$")
_HEX_KEY = re.compile(r"^[0-9a-f]{64,128}$")
_MAX_PROOF_BYTES = 16_384


class DeliveryReviewPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    dispatch_proof: dict[str, Any]
    recipient_proof: dict[str, Any]


def _issuer_keys() -> tuple[bytes, bytes]:
    """Read only externally controlled verification secrets; never log them."""
    a = os.environ.get("JW_V154_DISPATCH_VERIFY_KEY_HEX", "")
    b = os.environ.get("JW_V154_RECEIPT_VERIFY_KEY_HEX", "")
    if not (_HEX_KEY.fullmatch(a) and _HEX_KEY.fullmatch(b)\n            and len(a) % 2 == 0 and len(b) % 2 == 0):
        raise RuntimeError("V154 external issuer verification keys unavailable")
    dispatch, receipt = bytes.fromhex(a), bytes.fromhex(b)
    if hmac.compare_digest(dispatch, receipt):
        raise RuntimeError("V154 issuer verification keys must be independent")
    return dispatch, receipt


def enabled() -> bool:
    return (
        os.environ.get("JW_PG_DELIVERY_REVIEW_V154") == _MODE
        and os.environ.get("JW_V154_ISSUER_INDEPENDENCE_ACK")
            == "EXTERNAL_ISSUER_KEYS_VERIFIED"
        and quotes.enabled() and sessions.v90_enabled()
        and os.environ.get("JW_ENV", "").lower()
            in ("dev", "development", "test")
        and os.environ.get("JW_INSECURE_LOCAL_DEV") != "1"
    )


def create_delivery_review(
    order_id: str, request: Request, payload: DeliveryReviewPayload,
    response: Response,
) -> dict[str, Any]:
    if not enabled():
        raise HTTPException(404, "Delivery review unavailable")
    if not _ID.fullmatch(order_id):
        raise HTTPException(404, "Order not found")
    # Untrusted proof contents must not cause arbitrary memory use.
    try:
        total_size = len(json.dumps(payload.model_dump(), ensure_ascii=False,
                              separators=(",", ":"), allow_nan=False).encode("utf-8"))
    except (ValueError, UnicodeError, TypeError):
        raise HTTPException(422, "Invalid review envelope") from None
    if total_size > _MAX_PROOF_BYTES:
        raise HTTPException(413, "Review envelope too large")

    quotes._origin_checked(request)  # explicit pre-approved HTTPS origin
    session_hash = sessions._session_hash(request)
    dispatch_key, receipt_key = _issuer_keys()
    with sessions._pg_validated_cursor(session_hash) as (cur, identity):
        csrf = request.headers.get("X-CSRF-Token", "")
        if not csrf or not hmac.compare_digest(str(identity[4]), csrf):
            raise HTTPException(403, "Invalid CSRF token")
        if identity[3] != "admin":
            raise HTTPException(403, "Administrator role required")
        try:
            evidence_sha = reserve_delivery_review_v151(
                cur, validated_identity=identity, order_id=order_id,
                dispatch_proof=payload.dispatch_proof,
                recipient_proof=payload.recipient_proof,
                independent_dispatch_key=dispatch_key,
                independent_recipient_key=receipt_key,
                server_now=int(time.time()),
            )
        except (DeliveryProofRejected, PendingReviewRejected):
            raise HTTPException(409, "Delivery evidence invalid") from None
        except (errors.UniqueViolation, errors.CheckViolation,
                errors.ForeignKeyViolation):
            raise HTTPException(409, "Delivery evidence conflict") from None
        except (errors.InsufficientPrivilege, errors.UndefinedTable):
            # A missing migration or role grant is NOT grounds to bypass RLS.
            raise HTTPException(503, "Review storage unavailable") from None

    response.status_code = 201
    response.headers["Cache-Control"] = "no-store"
    return {
        "order_id": order_id,
        "evidence_sha256": evidence_sha,
        "status": "PENDING_HUMAN_REVIEW",
        "physical_delivery_verified": False,
        "invoice_posted": False,
        "payment_posted": False,
    }


def register_v154_delivery_review(app: FastAPI) -> bool:
    """Only opt into the isolated PG-only ASGI entrypoint, never app.main."""
    requested = os.environ.get("JW_PG_DELIVERY_REVIEW_V154", "")
    if not requested:
        return False
    if requested != _MODE or not enabled():
        raise RuntimeError("BLOCKED: V154 delivery review opt-in invalid")
    _issuer_keys()  # fail startup on absent or accidentally shared keys
    router = APIRouter(prefix=_PREFIX, tags=["Isolated signed delivery review"])
    router.add_api_route("/orders/{order_id}/delivery-review", create_delivery_review,
                         methods=["POST"], response_model=None)
    app.include_router(router)
    return True
