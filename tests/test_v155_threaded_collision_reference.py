"""Parallel synthetic reservation collision proof (SQLite reference, not PostgreSQL).

No DSN, external credentials, persistent schema, or production tables. PostgreSQL
multi-session verification remains an independent acceptance gate.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
import sqlite3


def test_two_writers_same_order_only_one_atomic_review_and_audit():
    with TemporaryDirectory() as temp:
        database = str(Path(temp) / "review.sqlite")
        with sqlite3.connect(database) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE reviews(
                order_id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                evidence_sha TEXT NOT NULL UNIQUE)""")
            db.execute("""CREATE TABLE nonces(
                nonce TEXT PRIMARY KEY,
                order_id TEXT NOT NULL REFERENCES reviews(order_id),
                purpose TEXT NOT NULL CHECK(purpose IN ('dispatch','receipt')),
                UNIQUE(order_id,purpose))""")
            db.execute("""CREATE TABLE audits(
                id TEXT PRIMARY KEY,
                order_id TEXT NOT NULL REFERENCES reviews(order_id),
                actor_id TEXT NOT NULL)""")
        barrier = Barrier(2)

        def writer(label):
            with sqlite3.connect(database, isolation_level=None,
                                 timeout=3) as db:
                db.execute("PRAGMA foreign_keys=ON")
                barrier.wait(timeout=3)
                try:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute("INSERT INTO reviews VALUES(?,?,?)",
                               ("same-order", "company-a", label))
                    db.execute("INSERT INTO nonces VALUES(?,?,?)",
                               (label+"-dispatch", "same-order", "dispatch"))
                    db.execute("INSERT INTO nonces VALUES(?,?,?)",
                               (label+"-receipt", "same-order", "receipt"))
                    db.execute("INSERT INTO audits VALUES(?,?,?)",
                               (label+"-audit", "same-order", label))
                    db.execute("COMMIT")
                    return "created"
                except (sqlite3.IntegrityError, sqlite3.OperationalError):
                    db.execute("ROLLBACK")
                    return "denied"

        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(writer, "one")
            b = pool.submit(writer, "two")
            outcomes = [a.result(timeout=8), b.result(timeout=8)]
        assert sorted(outcomes) == ["created", "denied"]

        with sqlite3.connect(database) as db:
            assert db.execute("SELECT count(*) FROM reviews").fetchone() == (1,)
            assert db.execute("SELECT count(*) FROM nonces").fetchone() == (2,)
            assert db.execute("SELECT count(*) FROM audits").fetchone() == (1,)
            winning = db.execute(
                "SELECT evidence_sha FROM reviews").fetchone()[0]
            assert db.execute(
                "SELECT actor_id FROM audits").fetchone() == (winning,)
            assert db.execute(
                "SELECT distinct substr(nonce,1,instr(nonce,'-')-1)"
                " FROM nonces").fetchone() == (winning,)
