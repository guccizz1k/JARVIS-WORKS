"""Stage-2 ONLY: validate independent signup proof envelopes (no account creation).

This pure gate is NOT a public API. Callers must supply issuer-owned independent
keys, an authoritative account-existence lookup, and a consumed-nonce ledger.
A positive result means eligible for a separate HUMAN review, never activation.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Callable, Mapping, AbstractSet

_SCHEMA = "jw-onboarding-proof-v146"
_EMAIL_RE = re.compile(r"^[a-z0-9][a-z0-9._+\-]{0,63}@[a-z0-9][a-z0-9.\-]{1,240}$")
_REQUEST_RE = re.compile(r"^[a-f0-9]{32}$")
_SIGNATURE_RE = re.compile(r"^[a-f0-9]{64}$")
_NONCE_RE = re.compile(r"^[a-f0-9]{32}$")
_FIELDS = frozenset({"schema", "purpose", "request_id", "intent_sha256", "subject", "issuer", "issued_at", "expires_at", "nonce"})
_ALLOWED = {"email_control": "approved-mail-verifier-v1", "business_control": "approved-business-verifier-v1"}


class ProofRejected(ValueError):
    """No identity details are included in exceptions or logs."""


def _deny() -> None:
    raise ProofRejected("Onboarding evidence unavailable or invalid")


def _email(raw: str) -> str:
    if not isinstance(raw, str) or raw != raw.strip():
        _deny()
    value = raw.casefold()
    if len(value) > 254 or not _EMAIL_RE.fullmatch(value):
        _deny()
    local, host = value.split("@", 1)
    if (".." in value or local.endswith(".") or host.startswith(".")
            or host.endswith(".") or "." not in host
            or any(not label or label.startswith("-") or label.endswith("-")
                   for label in host.split("."))):
        _deny()
    return value


def _business_number(raw: str) -> str:
    if not isinstance(raw, str) or any(c not in "0123456789- " for c in raw):
        _deny()
    result = raw.replace("-", "").replace(" ", "")
    if not re.fullmatch(r"[0-9]{10}", result):
        _deny()
    return result


@dataclass(frozen=True)
class EnrollmentIntent:
    request_id: str
    company_name: str
    email: str
    business_number: str

    def canonical(self) -> dict[str, str]:
        if not isinstance(self.request_id, str) or not _REQUEST_RE.fullmatch(self.request_id):
            _deny()
        if (not isinstance(self.company_name, str) or
                not self.company_name or self.company_name != self.company_name.strip() or
                not 2 <= len(self.company_name) <= 120 or
                any(ord(c) < 32 or ord(c) == 127 for c in self.company_name)):
            _deny()
        return {"request_id": self.request_id, "company_name": self.company_name,
                "email": _email(self.email), "business_number": _business_number(self.business_number)}

    def sha256(self) -> str:
        return hashlib.sha256(json.dumps(self.canonical(), sort_keys=True,
            separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ReviewDecision:
    status: str
    intent_sha256: str
    account_created: bool = False
    enrollment_approved: bool = False
    recovery_enabled: bool = False


def _check_envelope(*, envelope: Mapping, purpose: str, key: bytes,
                    intent: dict[str, str], digest: str, now: int,
                    consumed: AbstractSet[str]) -> str:
    if not isinstance(envelope, dict) or set(envelope) != (_FIELDS | {"signature"}):
        _deny()
    payload = {k: envelope[k] for k in _FIELDS}
    if (payload["schema"] != _SCHEMA or payload["purpose"] != purpose or
        payload["issuer"] != _ALLOWED[purpose] or
        payload["request_id"] != intent["request_id"] or
        payload["intent_sha256"] != digest or
        payload["subject"] != intent["email" if purpose == "email_control" else "business_number"]):
        _deny()
    if (type(payload["issued_at"]) is not int or type(payload["expires_at"]) is not int or
        not payload["issued_at"] <= now < payload["expires_at"] or
        not 1 <= payload["expires_at"] - payload["issued_at"] <= 900):
        _deny()
    nonce = payload["nonce"]
    if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce) or nonce in consumed:
        _deny()
    signature = envelope["signature"]
    if (not isinstance(signature, str) or not _SIGNATURE_RE.fullmatch(signature)
        or not isinstance(key, bytes) or len(key) < 32):
        _deny()
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                           separators=(",", ":"), allow_nan=False).encode("utf-8")
    expected = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        _deny()
    return nonce


def evaluate_signup(*, intent: EnrollmentIntent, email_proof: Mapping,
                    business_proof: Mapping, email_issuer_key: bytes,
                    business_issuer_key: bytes, consumed_nonces: AbstractSet[str],
                    account_exists: Callable[[str, str], bool], now: int) -> ReviewDecision:
    """Return REVIEW_READY only; never issue sessions/users/company ownership.

    A future DB transaction MUST atomically reserve both unique identifiers and
    consume both proof nonces. This read-only gate cannot provide such finality.
    """
    if (type(now) is not int or now < 1 or
            type(email_issuer_key) is not bytes or type(business_issuer_key) is not bytes or
            len(email_issuer_key) < 32 or len(business_issuer_key) < 32 or
            hmac.compare_digest(email_issuer_key, business_issuer_key) or
            not isinstance(consumed_nonces, (set, frozenset)) or
            not callable(account_exists)):
        _deny()
    identifiers = intent.canonical()
    digest = intent.sha256()
    email_nonce = _check_envelope(envelope=email_proof, purpose="email_control",
        key=email_issuer_key, intent=identifiers, digest=digest, now=now,
        consumed=consumed_nonces)
    biz_nonce = _check_envelope(envelope=business_proof, purpose="business_control",
        key=business_issuer_key, intent=identifiers, digest=digest, now=now,
        consumed=consumed_nonces)
    if email_nonce == biz_nonce:
        _deny()
    # This lookup MUST use an authoritative server-side source, never a caller's flag.
    # Even a clean lookup is not a durable reservation, so activation is forbidden.
    try:
        exists = account_exists(identifiers["email"], identifiers["business_number"])
    except Exception:
        _deny()
    # A missing/uncertain lookup must not be treated as "available".
    if exists is not False:
        _deny()
    return ReviewDecision(status="REVIEW_READY", intent_sha256=digest)
