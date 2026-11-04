"""S4 historical quote reconciliation, audit-only and strictly fail-closed.

This module cannot write PostgreSQL, alter the v92/CINEMA ledgers, approve a
link, or create a business document. An explicit, independently reviewed link
is mandatory: common business numbers, amounts, names, dates or titles alone
NEVER establish transaction identity.

Amounts are KRW integers. A snapshot contains the full quote line multiset,
not an aggregate alone, to detect line substitution and accidental duplicates.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from typing import Literal

Ledger = Literal["v92", "cinema"]
_ALLOWED_VAT = frozenset({"taxable", "exempt"})
_CANCELLED = frozenset({"cancelled", "rejected", "voided", "reversed"})


@dataclass(frozen=True)
class Line:
    name: str
    quantity: int
    unit_price: int

    def canonical(self) -> tuple[str, int, int]:
        if (not isinstance(self.name, str) or not self.name.strip()
                or self.name != self.name.strip() or len(self.name) > 150):
            raise ValueError("invalid line name")
        if type(self.quantity) is not int or not 1 <= self.quantity <= 100_000:
            raise ValueError("invalid quantity")
        if type(self.unit_price) is not int or not 0 <= self.unit_price <= 1_000_000_000:
            raise ValueError("invalid unit price")
        return (self.name, self.quantity, self.unit_price)


@dataclass(frozen=True)
class Quote:
    ledger: Ledger
    org_id: str
    quote_id: str
    doc_no: str
    business_number: str
    vat_mode: str
    status: str
    lines: tuple[Line, ...]

    def key(self) -> tuple[str, str, str]:
        return (self.ledger, self.org_id, self.quote_id)

    def canonical(self) -> dict:
        if self.ledger not in ("v92", "cinema"):
            raise ValueError("unknown ledger")
        if (not isinstance(self.org_id, str) or not self.org_id.strip()
                or self.org_id != self.org_id.strip() or len(self.org_id) > 128):
            raise ValueError("invalid tenant")
        if not isinstance(self.quote_id, str) or not self.quote_id.strip():
            raise ValueError("invalid quote id")
        if not isinstance(self.doc_no, str) or not self.doc_no.strip():
            raise ValueError("invalid document number")
        if self.vat_mode not in _ALLOWED_VAT:
            raise ValueError("invalid vat mode")
        if not isinstance(self.status, str) or not self.status.strip():
            raise ValueError("invalid status")
        if not isinstance(self.business_number, str):
            raise ValueError("business identifier must be text")
        number = self.business_number.replace("-", "")
        if len(number) != 10 or not number.isascii() or not number.isdecimal():
            raise ValueError("independent counterparty identity unavailable")
        if not isinstance(self.lines, tuple) or not 1 <= len(self.lines) <= 40:
            raise ValueError("quote lines missing or invalid")
        canon = sorted(line.canonical() for line in self.lines)
        if sum(qty * price for _, qty, price in canon) > 9_000_000_000_000_000_000:
            raise ValueError("quote amount overflow")
        return {"ledger": self.ledger, "org": self.org_id,
                "id": self.quote_id, "doc_no": self.doc_no,
                "business_number": number, "vat_mode": self.vat_mode,
                "status": self.status, "lines": canon,
                "subtotal_krw": sum(qty * price for _, qty, price in canon)}


@dataclass(frozen=True)
class ReviewedLink:
    org_id: str
    legacy_quote_id: str
    cinema_quote_id: str
    reviewer_id: str
    review_reference: str
    legacy_digest: str
    cinema_digest: str


@dataclass(frozen=True)
class Finding:
    code: str
    legacy_quote_id: str
    cinema_quote_id: str
    detail: str


@dataclass(frozen=True)
class AuditResult:
    accepted: tuple[ReviewedLink, ...]
    findings: tuple[Finding, ...]
    unlinked_legacy: tuple[str, ...]
    unlinked_cinema: tuple[str, ...]
    publishable: bool


def digest(quote: Quote) -> str:
    payload = quote.canonical()
    data = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def audit_links(legacy: tuple[Quote, ...], cinema: tuple[Quote, ...],
                proposed: tuple[ReviewedLink, ...]) -> AuditResult:
    """Return findings; never auto-create links or publish inferred totals.

    A reviewed link requires BOTH independently observed snapshots' complete
    digests. The caller must separately authorize reviewer identity, evidence
    and DB ownership before recording a link; this pure function cannot do so.
    """
    findings: list[Finding] = []
    old_by_key: dict[tuple[str, str], Quote] = {}
    new_by_key: dict[tuple[str, str], Quote] = {}
    for rows, expected, target in ((legacy, "v92", old_by_key),
                                   (cinema, "cinema", new_by_key)):
        for quote in rows:
            if quote.ledger != expected:
                findings.append(Finding("LEDGER_MISMATCH", quote.quote_id, "",
                                        "snapshot in wrong ledger"))
                continue
            try:
                quote.canonical()
            except (TypeError, ValueError, AttributeError) as exc:
                findings.append(Finding("INVALID_SNAPSHOT", quote.quote_id, "",
                                        str(exc)))
                continue
            key = (quote.org_id, quote.quote_id)
            if key in target:
                findings.append(Finding("DUPLICATE_SNAPSHOT", quote.quote_id, "",
                                        "duplicate tenant+id within ledger"))
            else:
                target[key] = quote

    accepted: list[ReviewedLink] = []
    used_old: set[tuple[str, str]] = set()
    used_new: set[tuple[str, str]] = set()
    for link in proposed:
        old_id, new_id = link.legacy_quote_id, link.cinema_quote_id
        def add(code: str, detail: str) -> None:
            findings.append(Finding(code, old_id, new_id, detail))

        if (not isinstance(link.org_id, str) or not link.org_id.strip()
                or not isinstance(link.reviewer_id, str) or not link.reviewer_id.strip()
                or not isinstance(link.review_reference, str)
                or len(link.review_reference.strip()) < 8):
            add("MISSING_REVIEW", "trusted reviewer and evidence reference required")
            continue
        left_key, right_key = (link.org_id, old_id), (link.org_id, new_id)
        if left_key in used_old or right_key in used_new:
            add("NON_BIJECTIVE", "one source quote cannot map to multiple targets")
            continue
        used_old.add(left_key)
        used_new.add(right_key)
        left, right = old_by_key.get(left_key), new_by_key.get(right_key)
        if left is None or right is None:
            add("MISSING_SOURCE", "unknown or cross-tenant quote id")
            continue
        lc, rc = left.canonical(), right.canonical()
        if lc["business_number"] != rc["business_number"]:
            add("COUNTERPARTY_MISMATCH", "verified business numbers differ")
            continue
        if lc["vat_mode"] != rc["vat_mode"]:
            add("VAT_MISMATCH", "vat modes differ")
            continue
        if lc["lines"] != rc["lines"]:
            add("ITEM_MISMATCH", "exact item multiset differs")
            continue
        if ((lc["status"] in _CANCELLED) != (rc["status"] in _CANCELLED)):
            add("STATUS_MISMATCH", "cancel/reversal differs across ledgers")
            continue
        try:
            if (link.legacy_digest != digest(left)
                    or link.cinema_digest != digest(right)):
                add("STALE_REVIEW", "snapshots changed after independent review")
                continue
        except (TypeError, ValueError, AttributeError):
            add("INVALID_REVIEW", "invalid source digest")
            continue
        accepted.append(link)

    accounted_old = {(x.org_id, x.legacy_quote_id) for x in accepted}
    accounted_new = {(x.org_id, x.cinema_quote_id) for x in accepted}
    old_unlinked = sorted(f"{a}:{b}" for (a,b) in old_by_key if (a,b) not in accounted_old)
    new_unlinked = sorted(f"{a}:{b}" for (a,b) in new_by_key if (a,b) not in accounted_new)
    # No auto-link and no inferred mixed-ledger totals if any missing mapping.
    publishable = (bool(accepted) and not findings and not old_unlinked
                   and not new_unlinked)
    return AuditResult(tuple(accepted), tuple(findings), tuple(old_unlinked),
                       tuple(new_unlinked), publishable)


def approved_unique_subtotal(result: AuditResult, cinema: tuple[Quote, ...]) -> int:
    """Unique linked subtotal only; zero links or unresolved items => BLOCKED."""
    if not result.publishable:
        raise ValueError("BLOCKED: double-ledger totals require all verified links")
    lookup = {(q.org_id, q.quote_id): q for q in cinema}
    return sum(lookup[(x.org_id, x.cinema_quote_id)].canonical()["subtotal_krw"]
               for x in result.accepted)
