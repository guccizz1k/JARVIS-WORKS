"""V7.1/V7.2: read-only, tenant-scoped pre-cutover invariants for the SQLite review app.

This is not a PostgreSQL RLS attestation, a replacement for foreign keys, or a
legal accounting audit. Fail closed on SQL errors and incomplete inspections.
No personally identifiable data or document contents leave this check.
"""
from __future__ import annotations

from fastapi import Depends

MAX_INVOICES = 2000

# Static SQL only; these checks intentionally assert *both* sides' org_id.
CHECKS = {
    'quote_customer_tenant': '''SELECT COUNT(*) FROM quotes q
        LEFT JOIN customers c ON c.id=q.customer_id AND c.org_id=q.org_id
        WHERE q.org_id=? AND c.id IS NULL''',
    'order_customer_tenant': '''SELECT COUNT(*) FROM orders o
        LEFT JOIN customers c ON c.id=o.customer_id AND c.org_id=o.org_id
        WHERE o.org_id=? AND c.id IS NULL''',
    'order_quote_tenant': '''SELECT COUNT(*) FROM orders o
        LEFT JOIN quotes q ON q.id=o.quote_id AND q.org_id=o.org_id
        WHERE o.org_id=? AND q.id IS NULL''',
    'invoice_order_tenant': '''SELECT COUNT(*) FROM invoices i
        LEFT JOIN orders o ON o.id=i.order_id AND o.org_id=i.org_id
        WHERE i.org_id=? AND o.id IS NULL''',
    'invoice_customer_tenant': '''SELECT COUNT(*) FROM invoices i
        LEFT JOIN customers c ON c.id=i.customer_id AND c.org_id=i.org_id
        WHERE i.org_id=? AND c.id IS NULL''',
    'payment_invoice_tenant': '''SELECT COUNT(*) FROM payments p
        LEFT JOIN invoices i ON i.id=p.invoice_id AND i.org_id=p.org_id
        WHERE p.org_id=? AND i.id IS NULL''',
    'quote_item_source': '''SELECT COUNT(*) FROM orders o
        JOIN order_items oi ON oi.order_id=o.id
        LEFT JOIN quote_items qi ON qi.id=oi.source_quote_item_id AND qi.quote_id=o.quote_id
        WHERE o.org_id=? AND oi.source_quote_item_id IS NOT NULL AND qi.id IS NULL''',
    'order_item_source': '''SELECT COUNT(*) FROM invoices i
        JOIN invoice_items ii ON ii.invoice_id=i.id
        LEFT JOIN order_items oi ON oi.id=ii.source_order_item_id AND oi.order_id=i.order_id
        WHERE i.org_id=? AND ii.source_order_item_id IS NOT NULL AND oi.id IS NULL''',
    'audit_actor_tenant': '''SELECT COUNT(*) FROM audit_logs a
        LEFT JOIN users u ON u.id=a.actor_id AND u.org_id=a.org_id
        WHERE a.org_id=? AND u.id IS NULL''',
    'adjustment_creator_tenant': '''SELECT COUNT(*) FROM invoice_adjustments_v69 a
        LEFT JOIN users u ON u.id=a.created_by AND u.org_id=a.org_id
        WHERE a.org_id=? AND u.id IS NULL''',
}


def inspect_tenant(c, org: str, *, retrieve_items, money, adjusted_settlement):
    """Return aggregate violations, never source records. No database writes."""
    if not isinstance(org, str) or not org:
        raise ValueError('tenant identifier required')
    violations = {key:int(c.execute(query,(org,)).fetchone()[0]) for key,query in CHECKS.items()}
    total=int(c.execute('SELECT COUNT(*) FROM invoices WHERE org_id=?',(org,)).fetchone()[0])
    # Do not incorrectly claim clean if the scan is capped.
    checked=0
    amount_discrepancies=0
    settlement_errors=0
    for row in c.execute('SELECT * FROM invoices WHERE org_id=? ORDER BY id LIMIT ?', (org,MAX_INVOICES)):
        checked+=1
        try:
            inv=dict(row)
            summary=adjusted_settlement(c,inv,retrieve_items(c,'invoice',inv['id']),money)
            if summary['balance']<0 or summary['paid']<0 or summary['adjusted_total']<0:
                amount_discrepancies+=1
        except (ValueError, KeyError, TypeError, OverflowError, ArithmeticError):
            settlement_errors+=1
    violations['negative_balance_or_amount']=amount_discrepancies
    violations['settlement_calculation_error']=settlement_errors
    complete=checked==total
    return {'status':'pass' if complete and not any(violations.values()) else 'review_required',
            'tenant_scope':'authenticated_organization_only',
            'checked_invoices':checked,'total_invoices':total,'scan_complete':complete,
            'violations':violations,'operational_pg_rls_verified':False,
            'accounting_certified':False}


def register_routes(app, *, conn, current_user, need_admin, retrieve_items, money, adjusted_settlement):
    @app.get('/api/operations/integrity')
    def integrity_summary(user=Depends(current_user)):
        need_admin(user)
        with conn() as c:
            c.execute('BEGIN')  # consistent read snapshot: concurrent payment cannot split the check
            try:
                return inspect_tenant(c,user['org_id'],retrieve_items=retrieve_items,
                                      money=money,adjusted_settlement=adjusted_settlement)
            finally:
                c.execute('ROLLBACK')
