"""Regression: an accepted S4 quote snapshot must not be swapped before totals.

Synthetic, pure Python only: no DB, network, user secrets or real business data.
The function remains FORENSIC ONLY; publishable must always remain False.
"""
from dataclasses import replace
import unittest

from app.pg_cinema_s4_reconciliation_v1 import (
    AuditResult, Line, Quote, ReviewedLink, audit_links, digest,
    provisional_unique_subtotal,
)


def fixtures():
    old = Quote("v92", "org-a", "old-q1", "Q-2026-A", "1234567890",
                "taxable", "approved",
                (Line("Part A", 5, 3501), Line("Part B", 2, 1000)))
    new = Quote("cinema", "org-a", "new-q1", "T-2026-A", "1234567890",
                "taxable", "ordered",
                (Line("Part B", 2, 1000), Line("Part A", 5, 3501)))
    link = ReviewedLink("org-a", old.quote_id, new.quote_id,
                        "independent-reviewer", "evidence-reference-0000001",
                        digest(old), digest(new))
    result = audit_links((old,), (new,), (link,))
    assert result.consistent_for_manual_review
    assert not result.publishable
    return result, new


class ProvisionalSubtotalIntegrityTests(unittest.TestCase):
    def test_unchanged_snapshot_still_returns_forensic_subtotal(self):
        result, new = fixtures()
        self.assertEqual(provisional_unique_subtotal(result, (new,)), 19505)

    def test_permuted_line_order_is_semantically_identical(self):
        result, new = fixtures()
        equivalent = replace(new, lines=tuple(reversed(new.lines)))
        self.assertEqual(provisional_unique_subtotal(result, (equivalent,)), 19505)

    def test_post_review_price_change_is_refused(self):
        result, new = fixtures()
        stale = replace(new, lines=(new.lines[0], replace(new.lines[1], unit_price=3502)))
        with self.assertRaisesRegex(ValueError, "BLOCKED"):
            provisional_unique_subtotal(result, (stale,))

    def test_post_review_quantity_change_is_refused(self):
        result, new = fixtures()
        stale = replace(new, lines=(replace(new.lines[0], quantity=3), new.lines[1]))
        with self.assertRaisesRegex(ValueError, "BLOCKED"):
            provisional_unique_subtotal(result, (stale,))

    def test_document_id_change_is_refused_even_with_same_amount(self):
        result, new = fixtures()
        with self.assertRaisesRegex(ValueError, "BLOCKED"):
            provisional_unique_subtotal(result, (replace(new, doc_no="OTHER-DOC"),))

    def test_ledger_identity_change_is_refused(self):
        result, new = fixtures()
        with self.assertRaisesRegex(ValueError, "BLOCKED"):
            provisional_unique_subtotal(result, (replace(new, ledger="v92"),))

    def test_status_change_is_refused_even_when_still_approved(self):
        result, new = fixtures()
        with self.assertRaisesRegex(ValueError, "BLOCKED"):
            provisional_unique_subtotal(result, (replace(new, status="approved"),))

    def test_company_identifier_change_is_refused(self):
        result, new = fixtures()
        with self.assertRaisesRegex(ValueError, "BLOCKED"):
            provisional_unique_subtotal(result, (replace(new, business_number="9999999999"),))

    def test_unreviewed_second_quote_is_refused(self):
        result, new = fixtures()
        second = replace(new, quote_id="new-q2", doc_no="T-2026-B")
        with self.assertRaisesRegex(ValueError, "BLOCKED"):
            provisional_unique_subtotal(result, (new, second))

    def test_duplicate_current_snapshot_is_refused(self):
        result, new = fixtures()
        with self.assertRaisesRegex(ValueError, "BLOCKED"):
            provisional_unique_subtotal(result, (new, new))

    def test_missing_current_snapshot_is_refused(self):
        result, _ = fixtures()
        with self.assertRaisesRegex(ValueError, "BLOCKED"):
            provisional_unique_subtotal(result, ())

    def test_tampered_audit_report_with_findings_is_refused(self):
        result, new = fixtures()
        malicious = replace(result, findings=("synthetic-finding",))
        with self.assertRaisesRegex(ValueError, "BLOCKED"):
            provisional_unique_subtotal(malicious, (new,))


if __name__ == "__main__":
    unittest.main()
