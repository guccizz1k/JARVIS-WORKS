"""Canonical flat JSON and detached Ed25519 verification primitives."""

import hashlib
import json
from hmac import compare_digest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class ApprovalError(ValueError):
    """The approval could not be verified."""


def canonical_payload(payload: bytes) -> dict[str, str | int]:
    """Accept bounded ASCII JSON with sorted keys and compact separators."""
    if type(payload) is not bytes or not 0 < len(payload) <= 4096:
        raise ApprovalError("invalid payload size or type")
    try:
        fields = json.loads(payload.decode("ascii"))
        if type(fields) is not dict or any(
            not key.isascii()
            or type(value) not in (str, int)
            or (type(value) is str and not value.isascii())
            for key, value in fields.items()
        ):
            raise ApprovalError("invalid payload fields")
        canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    except (ValueError, RecursionError) as exc:
        raise ApprovalError("invalid payload fields") from exc
    # Re-encoding exactly also rejects duplicated keys and alternate escapes.
    if payload != canonical.encode("ascii"):
        raise ApprovalError("noncanonical payload")
    return fields


def pinned_ed25519_key(public_key: bytes, fingerprint: str) -> Ed25519PublicKey:
    """Load a raw Ed25519 key using an independently supplied SHA-256 pin."""
    if type(public_key) is not bytes or len(public_key) != 32:
        raise ApprovalError("invalid public key")
    if type(fingerprint) is not str or not fingerprint.isascii() or not compare_digest(
        hashlib.sha256(public_key).hexdigest(), fingerprint
    ):
        raise ApprovalError("untrusted key")
    return Ed25519PublicKey.from_public_bytes(public_key)


def verify_ed25519(
    payload: bytes, signature: bytes, public_key: bytes, fingerprint: str
) -> None:
    """Verify a detached Ed25519 signature using a pinned public key."""
    if type(payload) is not bytes:
        raise ApprovalError("invalid payload type")
    if type(signature) is not bytes or len(signature) != 64:
        raise ApprovalError("invalid signature")
    try:
        pinned_ed25519_key(public_key, fingerprint).verify(signature, payload)
    except InvalidSignature as exc:
        raise ApprovalError("invalid signature") from exc
