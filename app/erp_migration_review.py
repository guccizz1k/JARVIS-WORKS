"""Isolated ERP metadata review binding. Not authentication or import approval.

Caller must supply separately authenticated tenant and source identities. No
database, cache, external AI, I/O, row inspection or mutation. A digest is
an identity consistency check, never proof of authorization or a signature.
"""
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from app.erp_migration_mapping import MappingBlocked, plan_headers

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_HASH = re.compile(r"[a-f0-9]{64}")

def _identity(value):
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise MappingBlocked("REVIEW_IDENTITY_INVALID")
    return value

@dataclass(frozen=True)
class HeaderReview:
    organization_id: str
    source_id: str
    entity: str
    source_headers_sha256: str
    fields: tuple[tuple[int, str], ...]
    binding_sha256: str
    row_import_authorized: bool = False

def prepare_header_review(organization_id, source_id, entity, headers):
    """Produce deterministic metadata bound to the exact tenant and source."""
    org = _identity(organization_id)
    source = _identity(source_id)
    plan = plan_headers(entity, headers)
    payload = {"version": 1, "purpose": "metadata-review-only",
               "organization_id": org, "source_id": source, "entity": plan.entity,
               "source_headers_sha256": plan.source_headers_sha256,
               "fields": plan.fields, "row_import_authorized": False}
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    return HeaderReview(org, source, plan.entity, plan.source_headers_sha256,
                        plan.fields, hashlib.sha256(raw).hexdigest())

def check_header_review(review, *, organization_id, source_id, entity, headers):
    """Reject stale or mixed review metadata; success never authorizes import.

    Supplied current identifiers must come from an authenticated server-side
    context in a future integration. No such context is implemented here.
    """
    if type(review) is not HeaderReview:
        raise MappingBlocked("REVIEW_TYPE_INVALID")
    expected = prepare_header_review(organization_id, source_id, entity, headers)
    if (type(review.organization_id) is not str or
            review.organization_id != expected.organization_id or
            type(review.source_id) is not str or review.source_id != expected.source_id):
        raise MappingBlocked("REVIEW_SCOPE_MISMATCH")
    if (type(review.entity) is not str or review.entity != expected.entity or
            type(review.source_headers_sha256) is not str or
            _HASH.fullmatch(review.source_headers_sha256) is None or
            not hmac.compare_digest(review.source_headers_sha256, expected.source_headers_sha256)):
        raise MappingBlocked("REVIEW_HEADER_MISMATCH")
    if (type(review.fields) is not tuple or
            any(type(f) is not tuple or len(f) != 2 or type(f[0]) is not int
                or type(f[1]) is not str for f in review.fields) or
            review.fields != expected.fields):
        raise MappingBlocked("REVIEW_MAPPING_MISMATCH")
    if review.row_import_authorized is not False:
        raise MappingBlocked("REVIEW_IMPORT_FORBIDDEN")
    if (type(review.binding_sha256) is not str or
            _HASH.fullmatch(review.binding_sha256) is None or
            not hmac.compare_digest(review.binding_sha256, expected.binding_sha256)):
        raise MappingBlocked("REVIEW_BINDING_MISMATCH")
    return expected
