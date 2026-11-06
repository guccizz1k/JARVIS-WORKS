#!/usr/bin/env python3
"""Read-only inventory of a legacy SQLite database before any per-organisation PostgreSQL cutover.

Why it exists: the legacy order -> invoice shortcut has no honest PostgreSQL equivalent (the PG chain
needs a recorded delivery with uploaded evidence confirmed by a second user, then a statement). So
existing SQLite quotes, orders, invoices and payments can NOT be copied into the PG chain without
inventing records. This tool measures, per organisation, what exists, what would stay in SQLite as
history, and whether the only honestly importable master data (customers -> PG partners) fits the PG
limits. It decides nothing and changes nothing.

Safety
  * opens the file with SQLite ``mode=ro`` plus ``PRAGMA query_only=ON``; never writes;
  * hashes the file before and after and reports whether the bytes are identical;
  * prints counts and verdicts ONLY: no names, e-mails, phone or business numbers, and the
    organisation is shown as the first 8 hex characters of a SHA-256 (output is safe to paste);
  * run it on a COPY of the database taken while the application is stopped.

Usage:  python -I scripts/ci_cinema_pg_cutover_inventory_v223.py --db /path/to/copy.sqlite3 [--json]
Standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path

PG_LIMITS = {"partner_name": 120, "contact_name": 80, "email": 254, "phone": 40,
             "quote_title": 150, "quote_item_name": 150, "quote_items": 40}
REQUIRED = {  # table -> columns this inventory reads
    "organizations": ("id",),
    "customers": ("id", "org_id", "name", "business_number", "contact_name", "email", "phone"),
    "quotes": ("id", "org_id", "status", "title"),
    "quote_items": ("id", "quote_id", "name"),
    "orders": ("id", "org_id", "status", "review_state", "due_date"),
    "order_items": ("id", "order_id", "quantity", "unit_price"),
    "invoices": ("id", "org_id", "order_id", "vat_mode", "due_date"),
    "invoice_items": ("id", "invoice_id", "quantity", "unit_price"),
    "payments": ("id", "org_id", "invoice_id", "amount", "note", "reversed_at"),
}
OPTIONAL = {"invoice_adjustments_v69": ("id", "org_id", "invoice_id")}
OPEN_ORDER = ("received", "processing")


class InventoryError(Exception):
    pass


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def check_path(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise InventoryError("database file not found (or a symlink)")


def open_readonly(path: Path) -> sqlite3.Connection:
    check_path(path)
    con = sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True)
    con.execute("PRAGMA query_only=ON")
    con.row_factory = sqlite3.Row
    return con


def schema_report(con: sqlite3.Connection) -> dict:
    """Which tables/columns exist; anything missing is reported, never guessed."""
    have = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing, cols = {}, {}
    for table, need in {**REQUIRED, **OPTIONAL}.items():
        if table not in have:
            if table in REQUIRED:
                missing[table] = list(need)
            continue
        present = {r[1] for r in con.execute(f'PRAGMA table_info("{table}")')}
        cols[table] = present
        lack = [c for c in need if c not in present]
        if lack:
            missing[table] = lack
    return {"tables": sorted(have & (set(REQUIRED) | set(OPTIONAL))), "missing": missing, "present_optional": [t for t in OPTIONAL if t in have]}


def org_label(org_id: str) -> str:
    return hashlib.sha256(org_id.encode()).hexdigest()[:8]


def normalise_bn(value: str | None) -> str:
    return re.sub(r"[\s-]", "", value or "")


def money_total(items, vat_mode) -> int:
    """The legacy rule (app/main.py money()): VAT = round-half-up 10% of the invoice subtotal."""
    subtotal = sum(int(q) * int(p) for q, p in items)
    return subtotal + ((subtotal + 5) // 10 if vat_mode == "taxable" else 0)


def inventory_org(con: sqlite3.Connection, org: str, has_adjustments: bool) -> dict:
    q = lambda sql, *a: con.execute(sql, a).fetchall()           # noqa: E731
    cust = q("SELECT id, name, business_number, contact_name, email, phone FROM customers WHERE org_id=?", org)
    bn_groups: dict[str, int] = {}
    bad_bn = 0
    for r in cust:
        bn = normalise_bn(r["business_number"])
        if bn and not re.fullmatch(r"[0-9]{10}", bn):
            bad_bn += 1
        elif bn:
            bn_groups[bn] = bn_groups.get(bn, 0) + 1
    over = lambda col, lim: sum(1 for r in cust if len(r[col] or "") > lim)    # noqa: E731
    customers = {
        "total": len(cust),
        "with_business_number": sum(1 for r in cust if normalise_bn(r["business_number"])),
        "bn_not_10_digits": bad_bn,
        "bn_duplicate_groups": sum(1 for n in bn_groups.values() if n > 1),
        "name_over_120": over("name", PG_LIMITS["partner_name"]),
        "name_empty_after_trim": sum(1 for r in cust if not (r["name"] or "").strip()),
        "contact_over_80": over("contact_name", PG_LIMITS["contact_name"]),
        "email_over_254": over("email", PG_LIMITS["email"]),
        "phone_over_40": over("phone", PG_LIMITS["phone"]),
    }
    blockers = {k: v for k, v in customers.items()
                if k in ("bn_not_10_digits", "bn_duplicate_groups", "name_over_120", "name_empty_after_trim",
                         "contact_over_80", "email_over_254", "phone_over_40") and v}

    quotes = {r["status"]: r["n"] for r in q("SELECT status, count(*) n FROM quotes WHERE org_id=? GROUP BY status", org)}
    orders = {r["status"]: r["n"] for r in q("SELECT status, count(*) n FROM orders WHERE org_id=? GROUP BY status", org)}
    quote_stats = {
        "by_status": quotes,
        "title_over_150": q("SELECT count(*) FROM quotes WHERE org_id=? AND length(title)>150", org)[0][0],
        "with_over_40_items": q("SELECT count(*) FROM (SELECT quote_id FROM quote_items i JOIN quotes x ON x.id=i.quote_id "
                                "WHERE x.org_id=? GROUP BY quote_id HAVING count(*)>40)", org)[0][0],
        "item_name_over_150": q("SELECT count(*) FROM quote_items i JOIN quotes x ON x.id=i.quote_id "
                                "WHERE x.org_id=? AND length(i.name)>150", org)[0][0],
    }
    order_stats = {
        "by_status": orders,
        "review_pending": q("SELECT count(*) FROM orders WHERE org_id=? AND review_state='pending'", org)[0][0],
        "with_due_date": q("SELECT count(*) FROM orders WHERE org_id=? AND coalesce(due_date,'')<>''", org)[0][0],
        "open_in_flight": sum(orders.get(s, 0) for s in OPEN_ORDER),
    }

    inv_rows = q("SELECT id, order_id, vat_mode, due_date FROM invoices WHERE org_id=?", org)
    paid = {r["invoice_id"]: r["s"] for r in q(
        "SELECT invoice_id, coalesce(sum(amount),0) s FROM payments WHERE org_id=? AND reversed_at IS NULL GROUP BY invoice_id", org)}
    adjusted = set()
    if has_adjustments:
        adjusted = {r[0] for r in q("SELECT DISTINCT invoice_id FROM invoice_adjustments_v69 WHERE org_id=?", org)}
    fully = unpaid = 0
    for r in inv_rows:
        items = [(i["quantity"], i["unit_price"]) for i in q(
            "SELECT quantity, unit_price FROM invoice_items WHERE invoice_id=?", r["id"])]
        if paid.get(r["id"], 0) >= money_total(items, r["vat_mode"]):
            fully += 1
        else:
            unpaid += 1
    invoice_stats = {
        "total": len(inv_rows),
        "fully_paid_unadjusted": fully,
        "not_fully_paid_unadjusted": unpaid,       # before v69 adjustments; those change the balance
        "with_adjustments": len(adjusted),
        "with_pay_by_date": sum(1 for r in inv_rows if (r["due_date"] or "")),
    }
    pay = q("SELECT count(*) total, sum(reversed_at IS NOT NULL) reversed, sum(coalesce(note,'')<>'') with_note "
            "FROM payments WHERE org_id=?", org)[0]
    payment_stats = {"total": pay["total"] or 0, "reversed": pay["reversed"] or 0, "with_note": pay["with_note"] or 0}

    in_flight = order_stats["open_in_flight"] + invoice_stats["not_fully_paid_unadjusted"] + invoice_stats["with_adjustments"]
    return {
        "org": org_label(org),
        "customers": customers, "quotes": quote_stats, "orders": order_stats,
        "invoices": invoice_stats, "payments": payment_stats,
        "verdict": {
            # the only honestly importable master data
            "partner_import": "READY" if not blockers else "BLOCKED_BY_DATA",
            "partner_import_blockers": blockers,
            # quotes/orders/invoices/payments: PG chain needs delivery+evidence+statement that do not exist
            "legacy_history": "KEEP_IN_SQLITE_READ_ONLY_OR_LEGACY_HOME",
            "documents_not_importable": quote_stats["by_status"].get("accepted", 0) + sum(orders.values()) + invoice_stats["total"],
            "legacy_in_flight_items": in_flight,
            "new_documents_in_pg": "CLEAN_START" if in_flight == 0 else "DUAL_HOME_REQUIRED",
        },
    }


def run(db_path: Path) -> dict:
    check_path(db_path)
    before = file_sha256(db_path)
    con = open_readonly(db_path)
    try:
        schema = schema_report(con)
        if schema["missing"]:
            raise InventoryError("schema differs from the expected legacy layout: " + json.dumps(schema["missing"], sort_keys=True))
        has_adj = "invoice_adjustments_v69" in schema["present_optional"]
        orgs = [r[0] for r in con.execute("SELECT id FROM organizations ORDER BY id")]
        report = {"organizations": [inventory_org(con, o, has_adj) for o in orgs], "schema": {
            "tables_seen": schema["tables"], "adjustments_table_present": has_adj}}
    finally:
        con.close()
    after = file_sha256(db_path)
    report["read_only_proof"] = {"file_sha256_before": before, "file_sha256_after": after, "unchanged": before == after}
    report["not_measured"] = ["semantic equivalence of any legacy route with the PG engine (needs FastAPI + PG17)",
                              "customers referenced only inside free-text import metadata",
                              "balances after v69 adjustments (counted separately, not recomputed)"]
    return report


def render_text(rep: dict) -> str:
    out = ["SQLITE CUTOVER INVENTORY (counts only; read-only)"]
    for o in rep["organizations"]:
        v = o["verdict"]
        out += [f"- org {o['org']}: customers={o['customers']['total']} quotes={sum(o['quotes']['by_status'].values())} "
                f"orders={sum(o['orders']['by_status'].values())} invoices={o['invoices']['total']} "
                f"payments={o['payments']['total']}",
                f"    partner_import={v['partner_import']} {v['partner_import_blockers'] or ''}".rstrip(),
                f"    legacy_in_flight_items={v['legacy_in_flight_items']} new_documents_in_pg={v['new_documents_in_pg']}",
                f"    not importable without inventing records: {v['documents_not_importable']} documents (kept in SQLite)"]
    p = rep["read_only_proof"]
    out.append(f"read-only proof: file unchanged={p['unchanged']}")
    out.append("NOT MEASURED: " + "; ".join(rep["not_measured"]))
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--db", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        rep = run(Path(args.db))
    except (InventoryError, sqlite3.Error, OSError) as exc:
        print("BLOCKED: " + (str(exc) if isinstance(exc, InventoryError) else type(exc).__name__), file=sys.stderr)
        return 2
    print(json.dumps(rep, ensure_ascii=False, indent=2, sort_keys=True) if args.json else render_text(rep))
    return 0 if rep["read_only_proof"]["unchanged"] else 3


if __name__ == "__main__":
    sys.exit(main())
