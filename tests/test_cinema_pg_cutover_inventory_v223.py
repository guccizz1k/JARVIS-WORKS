"""SQLite cutover inventory: read-only, counts-only, built against the REAL legacy DDL.

The test database is created from the CREATE TABLE statements found in app/main.py and
app/complex_settlement_v69.py (parsed as text, so FastAPI is not needed), which means a renamed or
dropped column in the application schema breaks these tests instead of silently breaking the tool.
"""
import json
import re
import sqlite3
from pathlib import Path

import pytest

from scripts import ci_cinema_pg_cutover_inventory_v223 as inv

ROOT = Path(__file__).resolve().parents[1]
NEEDED = ("organizations", "users", "customers", "quotes", "quote_items", "orders", "order_items",
          "invoices", "invoice_items", "payments")


def _ddl(text: str, table: str) -> str:
    m = re.search(rf"CREATE TABLE IF NOT EXISTS {table} \(\n.*?\n\s*\);", text, re.S)
    assert m, f"DDL for {table} not found: the application schema moved"
    return m.group(0)


def build(path: Path, with_adjustments=True) -> sqlite3.Connection:
    main = (ROOT / "app/main.py").read_text(encoding="utf-8")
    con = sqlite3.connect(path)
    for t in NEEDED:
        con.execute(_ddl(main, t))
    if with_adjustments:
        con.execute(_ddl((ROOT / "app/complex_settlement_v69.py").read_text(encoding="utf-8"), "invoice_adjustments_v69"))
    return con


NOW = "2026-11-06T00:00:00"
SECRET_NAME, SECRET_MAIL, SECRET_BN = "ACME-SECRET-NAME", "secret@example.invalid", "123-45-67890"


@pytest.fixture()
def db(tmp_path):
    p = tmp_path / "legacy.sqlite3"
    c = build(p)
    c.execute("INSERT INTO organizations VALUES('org-a','A',?)", (NOW,))
    c.execute("INSERT INTO organizations VALUES('org-b','B',?)", (NOW,))
    c.execute("INSERT INTO users VALUES('u-a','org-a','a@x.invalid','h','U','admin',?)", (NOW,))

    def cust(i, org, name, bn="", contact="", email="", phone=""):
        c.execute("INSERT INTO customers VALUES(?,?,?,?,?,?,?,?)", (i, org, name, bn, contact, email, phone, NOW))
    cust("c1", "org-a", SECRET_NAME, SECRET_BN, "p", SECRET_MAIL, "010")
    cust("c2", "org-a", "dup same number", "1234567890")           # same number, different notation -> duplicate
    cust("c3", "org-a", "bad number", "12345")
    cust("c4", "org-a", "x" * 121)
    cust("c5", "org-a", "ok no number")
    cust("c6", "org-b", "b only", "9999999999")

    def quote(i, org, status):
        c.execute("INSERT INTO quotes VALUES(?,?,?,?,?,?,?,?,?,?)", (i, org, "c1", "n", "D-" + i, "t" * (151 if i == "q-long" else 5), status, "taxable", NOW, NOW))
    for i, s in (("q1", "draft"), ("q2", "accepted"), ("q3", "accepted"), ("q-long", "sent")):
        quote(i, "org-a", s)
    c.execute("INSERT INTO quote_items VALUES('qi1','q1',?,1,1,0)", ("n" * 151,))

    def order(i, qid, status, review="clean", due="2026-12-01"):
        c.execute("INSERT INTO orders (id,org_id,customer_id,quote_id,customer_name_snapshot,doc_no,title,status,review_state,vat_mode,due_date,created_at,updated_at)"
                  " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (i, "org-a", "c1", qid, "n", "O-" + i, "t", status, review, "taxable", due, NOW, NOW))
    order("o1", "q2", "received")
    order("o2", "q3", "fulfilled", due="")
    # invoice i1: taxable, items 10x1 + 5x1 = 15 -> VAT (15+5)//10 = 2 -> total 17
    def invoice(i, oid, vat, due="2026-12-31"):
        c.execute("INSERT INTO invoices VALUES(?,?,?,?,?,?,?,?,?,?)", (i, "org-a", oid, "c1", "n", "I-" + i, "issued", vat, due, NOW))
    invoice("i1", "o1", "taxable")
    invoice("i2", "o2", "exempt", due="")
    for item_id, inv_id, qty, price in (("a", "i1", 10, 1), ("b", "i1", 5, 1), ("c", "i2", 3, 100)):
        c.execute("INSERT INTO invoice_items VALUES(?,?,NULL,'n',?,?,0)", (item_id, inv_id, qty, price))

    def pay(i, inv_id, amt, ref, note="", reversed_at=None):
        c.execute("INSERT INTO payments VALUES(?,?,?,?,?,?,?,?,?,?)", (i, "org-a", inv_id, amt, "2026-11-01", note, NOW, ref, reversed_at, None))
    pay("p1", "i1", 16, "r1")                                  # 16 < 17 -> not fully paid
    pay("p2", "i2", 300, "r2", note="memo")                    # exempt 300 -> fully paid
    pay("p3", "i1", 1, "r3", reversed_at=NOW)                  # reversed: must not count toward i1
    c.execute("INSERT INTO invoice_adjustments_v69 VALUES('ad1','org-a','i2','k','discount','',0,10,'r','u-a',?)", (NOW,))
    c.commit()
    c.close()
    return p


def org(report, label_of):
    return next(o for o in report["organizations"] if o["org"] == inv.org_label(label_of))


def test_counts_per_organisation_against_the_real_legacy_ddl(db):
    rep = inv.run(db)
    a, b = org(rep, "org-a"), org(rep, "org-b")
    assert a["customers"]["total"] == 5 and b["customers"]["total"] == 1
    assert a["quotes"]["by_status"] == {"draft": 1, "accepted": 2, "sent": 1}
    assert a["orders"]["by_status"] == {"received": 1, "fulfilled": 1}
    assert a["orders"]["open_in_flight"] == 1 and a["orders"]["with_due_date"] == 1
    assert a["invoices"]["total"] == 2 and a["invoices"]["with_pay_by_date"] == 1
    assert a["payments"] == {"total": 3, "reversed": 1, "with_note": 1}
    assert sum(b["orders"]["by_status"].values()) == 0 and b["invoices"]["total"] == 0


def test_balance_uses_the_legacy_vat_rule_and_ignores_reversed_payments(db):
    a = org(inv.run(db), "org-a")["invoices"]
    # i1: 15 + round-half-up 10% = 17, paid 16 (the reversed 1 does not count) -> unpaid; i2: exempt 300, paid 300
    assert (a["fully_paid_unadjusted"], a["not_fully_paid_unadjusted"]) == (1, 1)
    assert a["with_adjustments"] == 1
    assert inv.money_total([(10, 1), (5, 1)], "taxable") == 17
    assert inv.money_total([(5, 1)], "taxable") == 6          # (5+5)//10 = 1 -> half up
    assert inv.money_total([(4, 1)], "taxable") == 4          # (4+5)//10 = 0
    assert inv.money_total([(10, 10)], "exempt") == 100


def test_partner_import_blockers_are_counted_not_fixed(db):
    a = org(inv.run(db), "org-a")
    c = a["customers"]
    assert c["bn_not_10_digits"] == 1 and c["bn_duplicate_groups"] == 1 and c["name_over_120"] == 1
    assert a["verdict"]["partner_import"] == "BLOCKED_BY_DATA"
    assert set(a["verdict"]["partner_import_blockers"]) == {"bn_not_10_digits", "bn_duplicate_groups", "name_over_120"}
    assert org(inv.run(db), "org-b")["verdict"]["partner_import"] == "READY"


def test_documents_are_never_offered_for_import_and_in_flight_decides_dual_home(db):
    a, b = org(inv.run(db), "org-a")["verdict"], org(inv.run(db), "org-b")["verdict"]
    assert a["legacy_history"] == "KEEP_IN_SQLITE_READ_ONLY_OR_LEGACY_HOME"
    assert a["documents_not_importable"] == 2 + 2 + 2          # 2 accepted quotes + 2 orders + 2 invoices
    assert a["new_documents_in_pg"] == "DUAL_HOME_REQUIRED" and a["legacy_in_flight_items"] == 3
    assert b["new_documents_in_pg"] == "CLEAN_START" and b["legacy_in_flight_items"] == 0


def test_database_is_never_modified_and_no_sidecar_files_appear(db):
    before = (inv.file_sha256(db), sorted(p.name for p in db.parent.iterdir()))
    rep = inv.run(db)
    assert rep["read_only_proof"]["unchanged"] is True
    assert (inv.file_sha256(db), sorted(p.name for p in db.parent.iterdir())) == before


def test_connection_is_physically_read_only(db):
    con = inv.open_readonly(db)
    for stmt in ("INSERT INTO organizations VALUES('x','x','x')", "DELETE FROM customers", "CREATE TABLE t(a)",
                 "UPDATE orders SET status='cancelled'"):
        with pytest.raises(sqlite3.OperationalError):
            con.execute(stmt)
    con.close()


def test_output_contains_no_personal_data_and_orgs_are_hashed(db):
    rep = inv.run(db)
    text = inv.render_text(rep) + json.dumps(rep, ensure_ascii=False)
    for secret in (SECRET_NAME, SECRET_MAIL, SECRET_BN.replace("-", ""), SECRET_BN, "org-a", "org-b", "dup same number"):
        assert secret not in text
    assert all(re.fullmatch(r"[0-9a-f]{8}", o["org"]) for o in rep["organizations"])


def test_missing_database_is_refused_without_creating_a_file(tmp_path, capsys):
    ghost = tmp_path / "nope.sqlite3"
    assert inv.main(["--db", str(ghost)]) == 2
    assert not ghost.exists() and "BLOCKED" in capsys.readouterr().err


def test_symlink_is_refused(db, tmp_path):
    link = tmp_path / "link.sqlite3"
    link.symlink_to(db)
    assert inv.main(["--db", str(link)]) == 2


def test_unexpected_schema_is_reported_as_blocked_not_guessed(tmp_path, capsys):
    p = tmp_path / "odd.sqlite3"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE organizations(id TEXT)")
    c.commit()
    c.close()
    assert inv.main(["--db", str(p)]) == 2
    assert "differs from the expected legacy layout" in capsys.readouterr().err


def test_database_without_the_optional_adjustments_table_still_works(tmp_path):
    p = tmp_path / "noadj.sqlite3"
    c = build(p, with_adjustments=False)
    c.execute("INSERT INTO organizations VALUES('o','O',?)", (NOW,))
    c.commit()
    c.close()
    rep = inv.run(p)
    assert rep["schema"]["adjustments_table_present"] is False
    assert rep["organizations"][0]["invoices"]["with_adjustments"] == 0


def test_cli_text_and_json_modes(db, capsys):
    assert inv.main(["--db", str(db)]) == 0
    assert "SQLITE CUTOVER INVENTORY" in capsys.readouterr().out
    assert inv.main(["--db", str(db), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["read_only_proof"]["unchanged"] is True


def test_tool_has_no_write_statements():
    src = (ROOT / "scripts/ci_cinema_pg_cutover_inventory_v223.py").read_text(encoding="utf-8")
    code = re.sub(r'""".*?"""', "", src, flags=re.S)
    assert not re.search(r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE)\b\s", code.replace("SELECT", ""), re.I), "inventory must only read"


# Each read-only layer is asserted on its own: either one alone would already block writes, so the
# behavioural test above cannot notice if the other is removed.
def test_uri_is_mode_ro_and_query_only_pragma_is_on(db, monkeypatch):
    seen = []
    real = sqlite3.connect
    monkeypatch.setattr(inv.sqlite3, "connect", lambda *a, **k: (seen.append(a[0]), real(*a, **k))[1])
    con = inv.open_readonly(db)
    assert seen and "mode=ro" in seen[0] and "mode=rw" not in seen[0]
    assert con.execute("PRAGMA query_only").fetchone()[0] == 1
    con.close()


def test_a_file_that_changes_during_the_run_is_reported_and_fails_the_exit_code(db, monkeypatch, capsys):
    real = inv.inventory_org

    def touching(con, org, has_adj):
        with open(db, "ab") as f:                      # simulate the application writing meanwhile
            f.write(b"\0")
        return real(con, org, has_adj)
    monkeypatch.setattr(inv, "inventory_org", touching)
    rep = inv.run(db)
    assert rep["read_only_proof"]["unchanged"] is False
    assert rep["read_only_proof"]["file_sha256_before"] != rep["read_only_proof"]["file_sha256_after"]
    assert inv.main(["--db", str(db)]) == 3
