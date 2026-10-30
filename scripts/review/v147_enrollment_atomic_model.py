"""TEST-ONLY SQLite reference model for future PostgreSQL review reservation.

Not an app module, not a PostgreSQL implementation, not signup approval.
This checks atomic uniqueness/replay invariants under real thread contention.
No user accounts, passwords, secrets, roles or provider credentials are stored.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from app.pg_signup_review_gate_v146 import EnrollmentIntent, ReviewDecision

DDL = """
CREATE TABLE review_requests (
  request_id TEXT PRIMARY KEY, company TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE, business_number TEXT NOT NULL UNIQUE,
  digest TEXT NOT NULL UNIQUE, status TEXT NOT NULL CHECK(status='PENDING_HUMAN_REVIEW')
);
CREATE TABLE used_nonces (
  nonce TEXT PRIMARY KEY, request_id TEXT NOT NULL REFERENCES review_requests(request_id),
  purpose TEXT NOT NULL CHECK(purpose IN ('email','business')),
  UNIQUE(request_id,purpose)
);
"""


class ReservationRejected(ValueError):
    pass


def initialize_test_db(path: Path) -> None:
    with sqlite3.connect(str(path)) as db:
        db.execute("PRAGMA foreign_keys=ON")
        db.executescript(DDL)


def reserve_for_human_review(path: Path, *, intent: EnrollmentIntent,
                             decision: ReviewDecision,
                             email_nonce: str, business_nonce: str) -> bool:
    """Atomic proof-consumption model, NEVER business activation or signup."""
    from re import fullmatch
    canonical = intent.canonical()
    if (type(decision) is not ReviewDecision or
        decision.status != "REVIEW_READY" or
        decision.account_created is not False or
        decision.enrollment_approved is not False or
        decision.recovery_enabled is not False or
        decision.intent_sha256 != intent.sha256() or
        not isinstance(email_nonce, str) or
        not isinstance(business_nonce, str) or
        not fullmatch(r"[a-f0-9]{32}", email_nonce) or
        not fullmatch(r"[a-f0-9]{32}", business_nonce) or
        email_nonce == business_nonce):
        raise ReservationRejected("Review reservation rejected")
    try:
        with sqlite3.connect(str(path), timeout=3, isolation_level=None) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("INSERT INTO review_requests VALUES(?,?,?,?,?,'PENDING_HUMAN_REVIEW')",
                    (canonical["request_id"], canonical["company_name"], canonical["email"],
                     canonical["business_number"], decision.intent_sha256))
                db.execute("INSERT INTO used_nonces VALUES(?,?,'email')",
                    (email_nonce, canonical["request_id"]))
                db.execute("INSERT INTO used_nonces VALUES(?,?,'business')",
                    (business_nonce, canonical["request_id"]))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
    except (sqlite3.IntegrityError, sqlite3.OperationalError):
        raise ReservationRejected("Review reservation rejected") from None
    return True
