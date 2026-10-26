"""JARVIS-WORKS V6.0 additive automation candidate (SQLite review branch only).

Goals:
* (2) one-click, immutable trade-statement snapshot from a fulfilled order;
* (3) a tenant-isolated quote/order/statement/invoice/payment timeline;
* (5) honest, server-timed workflow comparison (not inferred ROI).

No money movement, inventory mutation, outbound dispatch or tax document issuance.
Do NOT mount against production until full integration and security gates pass.
"""
from __future__ import annotations

import json
import statistics
from datetime import datetime, timezone, timedelta
from typing import Literal

from fastapi import Depends, Response
from pydantic import BaseModel, ConfigDict, Field


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)


class StatementRequest(Strict):
    order_id: str = Field(min_length=1, max_length=100)


class TimerStart(Strict):
    workflow: Literal['trade_statement']
    mode: Literal['manual', 'automated']


class TimerFinish(Strict):
    completed: Literal[True]
    statement_id: str | None = Field(default=None, max_length=100)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


DDL = '''
CREATE TABLE IF NOT EXISTS automation_statements_v60 (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    order_id TEXT NOT NULL REFERENCES orders(id),
    created_by TEXT NOT NULL REFERENCES users(id),
    doc_no TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(org_id,order_id), UNIQUE(org_id,doc_no)
);
CREATE INDEX IF NOT EXISTS idx_auto_stmt_org ON automation_statements_v60(org_id,created_at);
CREATE TRIGGER IF NOT EXISTS auto_stmt_org_guard_v60
BEFORE INSERT ON automation_statements_v60
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM orders o JOIN users u ON u.id=NEW.created_by
        WHERE o.id=NEW.order_id AND o.org_id=NEW.org_id AND u.org_id=NEW.org_id
    ) THEN RAISE(ABORT, 'cross_tenant_statement') END;
END;
CREATE TRIGGER IF NOT EXISTS auto_stmt_update_guard_v60
BEFORE UPDATE ON automation_statements_v60
BEGIN SELECT RAISE(ABORT, 'immutable_statement'); END;
CREATE TRIGGER IF NOT EXISTS auto_stmt_delete_guard_v60
BEFORE DELETE ON automation_statements_v60
BEGIN SELECT RAISE(ABORT, 'immutable_statement'); END;
CREATE TABLE IF NOT EXISTS automation_task_times_v60 (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    workflow TEXT NOT NULL CHECK(workflow='trade_statement'),
    mode TEXT NOT NULL CHECK(mode IN ('manual','automated')),
    status TEXT NOT NULL CHECK(status IN ('running','completed')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    elapsed_ms INTEGER CHECK(elapsed_ms BETWEEN 0 AND 1800000),
    statement_id TEXT REFERENCES automation_statements_v60(id),
    CHECK ((status='running' AND finished_at IS NULL AND elapsed_ms IS NULL)
        OR (status='completed' AND finished_at IS NOT NULL AND elapsed_ms IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_auto_time_org ON automation_task_times_v60(org_id,workflow,mode,status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_auto_time_auto_doc_v60
    ON automation_task_times_v60(statement_id)
    WHERE mode='automated' AND status='completed' AND statement_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_auto_time_one_active_v60
    ON automation_task_times_v60(user_id) WHERE status='running';
'''


def install_schema(conn):
    """Call after existing init_db(); strictly additive and re-entrant."""
    with conn() as c:
        c.executescript(DDL)


def register_routes(app, *, conn, transaction, current_user, get_row,
                    retrieve_items, money, audit, ident, now, fail):
    """Mount on the existing FastAPI app, using original authorization/audit helpers."""

    def statement_public(row):
        return {'id': row['id'], 'org_id': row['org_id'], 'order_id': row['order_id'],
                'doc_no': row['doc_no'], 'document': json.loads(row['payload_json']),
                'created_at': row['created_at'], 'reused': False}

    @app.post('/api/automation/statements/from-order', status_code=201)
    def statement_from_order(body: StatementRequest, response: Response,
                             user=Depends(current_user)):
        # Existing transaction() uses SQLite BEGIN IMMEDIATE, protecting unique conversion.
        with transaction() as c:
            order = get_row(c, 'orders', body.order_id, user['org_id'])
            existing = c.execute('''SELECT * FROM automation_statements_v60
                WHERE org_id=? AND order_id=?''', (user['org_id'], body.order_id)).fetchone()
            if existing:
                response.status_code = 200
                return {**statement_public(dict(existing)), 'reused': True}
            if order['status'] != 'fulfilled' or order['review_state'] == 'pending':
                fail('납품 완료 및 변경사항 검증 이후에 거래명세표를 만들 수 있습니다', 409)
            entries = retrieve_items(c, 'order', order['id'])
            if not entries:
                fail('품목이 없는 발주는 전환할 수 없습니다', 409)
            total = money(entries, order['vat_mode'])
            # Historical snapshot: never read mutable customer master data here.
            document = {
                'document_type': 'trade_statement',
                'source_order_id': order['id'],
                'source_order_no': order['doc_no'],
                'customer_id': order['customer_id'],
                'customer_name': order['customer_name_snapshot'],
                'title': order['title'],
                'vat_mode': order['vat_mode'],
                'due_date': order['due_date'],
                'items': [
                    {'source_order_item_id': x['id'], 'name': x['name'],
                     'quantity': x['quantity'], 'unit_price': x['unit_price'],
                     'line_total': x['quantity'] * x['unit_price']}
                    for x in entries
                ],
                'money': total,
                'finalized': True,
                'legal_status': 'internal_business_record_not_tax_invoice',
            }
            key = ident()
            doc_no = f'TS-{key[:12].upper()}'
            c.execute('''INSERT INTO automation_statements_v60
                (id,org_id,order_id,created_by,doc_no,payload_json,created_at)
                VALUES(?,?,?,?,?,?,?)''',
                (key, user['org_id'], order['id'], user['id'], doc_no,
                 json.dumps(document, ensure_ascii=False, sort_keys=True), now()))
            audit(c, user, 'trade_statement', key, 'create',
                  {'source_order_id': order['id'], 'doc_no': doc_no})
            row = c.execute('SELECT * FROM automation_statements_v60 WHERE id=?', (key,)).fetchone()
            return statement_public(dict(row))

    @app.get('/api/automation/statements/{statement_id}')
    def statement_detail(statement_id: str, user=Depends(current_user)):
        with conn() as c:
            row = c.execute('''SELECT * FROM automation_statements_v60
                WHERE id=? AND org_id=?''', (statement_id, user['org_id'])).fetchone()
            if not row:
                fail('거래명세표를 찾을 수 없습니다', 404)
            return statement_public(dict(row))

    @app.get('/api/automation/transactions/{order_id}')
    def transaction_trace(order_id: str, user=Depends(current_user)):
        with conn() as c:
            order = get_row(c, 'orders', order_id, user['org_id'])
            quote = get_row(c, 'quotes', order['quote_id'], user['org_id'])
            statement = c.execute('''SELECT id,doc_no,created_at FROM automation_statements_v60
                WHERE org_id=? AND order_id=?''', (user['org_id'], order_id)).fetchone()
            invoice = c.execute('''SELECT * FROM invoices
                WHERE org_id=? AND order_id=?''', (user['org_id'], order_id)).fetchone()
            events = [
                {'type': 'quote', 'id': quote['id'], 'no': quote['doc_no'],
                 'status': quote['status'], 'occurred_at': quote['created_at']},
                {'type': 'order', 'id': order['id'], 'no': order['doc_no'],
                 'status': order['status'], 'occurred_at': order['created_at']},
            ]
            if statement:
                events.append({'type': 'trade_statement', 'id': statement['id'],
                               'no': statement['doc_no'], 'status': 'created',
                               'occurred_at': statement['created_at']})
            payments = []
            if invoice:
                events.append({'type': 'invoice', 'id': invoice['id'], 'no': invoice['doc_no'],
                               'status': invoice['status'], 'occurred_at': invoice['created_at']})
                payments = [dict(x) for x in c.execute('''SELECT id,amount,paid_at,reversed_at,created_at
                    FROM payments WHERE org_id=? AND invoice_id=?
                    ORDER BY created_at,id''', (user['org_id'], invoice['id']))]
                for x in payments:
                    events.append({'type': 'payment', 'id': x['id'], 'no': None,
                                   'status': 'reversed' if x['reversed_at'] else 'active',
                                   'amount': x['amount'], 'occurred_at': x['created_at']})
            active_paid = sum(x['amount'] for x in payments if x['reversed_at'] is None)
            invoice_money = money(retrieve_items(c, 'invoice', invoice['id']),
                                  invoice['vat_mode']) if invoice else None
            events.sort(key=lambda x: (datetime.fromisoformat(x['occurred_at']).astimezone(timezone.utc),
                                       x['type'], x['id']))
            return {
                'source_order_id': order_id,
                'quote_id': quote['id'],
                'statement_id': statement['id'] if statement else None,
                'invoice_id': invoice['id'] if invoice else None,
                'order_money': money(retrieve_items(c, 'order', order_id), order['vat_mode']),
                'invoice_money': invoice_money,
                'active_paid': active_paid,
                'remaining_balance': (invoice_money['total'] - active_paid) if invoice else None,
                'events': events,
                'scope': 'authenticated_tenant_only',
            }

    @app.post('/api/automation/timing/start', status_code=201)
    def timing_start(body: TimerStart, user=Depends(current_user)):
        with transaction() as c:
            if c.execute('''SELECT 1 FROM automation_task_times_v60
                WHERE user_id=? AND status='running' ''', (user['id'],)).fetchone():
                fail('진행 중인 작업 측정부터 종료해야 합니다', 409)
            key = ident()
            c.execute('''INSERT INTO automation_task_times_v60
                (id,org_id,user_id,workflow,mode,status,started_at)
                VALUES(?,?,?,?,?,?,?)''',
                (key, user['org_id'], user['id'], body.workflow, body.mode,
                 'running', utcnow().isoformat()))
            return {'id': key, 'workflow': body.workflow, 'mode': body.mode,
                    'status': 'running'}

    @app.post('/api/automation/timing/{run_id}/finish')
    def timing_finish(run_id: str, body: TimerFinish, user=Depends(current_user)):
        with transaction() as c:
            task = c.execute('''SELECT * FROM automation_task_times_v60
                WHERE id=? AND org_id=? AND user_id=?''',
                (run_id, user['org_id'], user['id'])).fetchone()
            if not task:
                fail('작업 측정을 찾을 수 없습니다', 404)
            if task['status'] != 'running':
                fail('이미 종료된 측정입니다', 409)
            if task['mode'] == 'automated':
                if not body.statement_id or not c.execute('''SELECT 1 FROM automation_statements_v60
                    WHERE id=? AND org_id=?''', (body.statement_id, user['org_id'])).fetchone():
                    fail('자동화 측정에는 해당 회사의 확정 문서가 필요합니다', 409)
                output = c.execute('''SELECT created_at,created_by FROM automation_statements_v60
                    WHERE id=? AND org_id=?''', (body.statement_id,user['org_id'])).fetchone()
                if output['created_by'] != user['id'] or (
                    datetime.fromisoformat(output['created_at']).astimezone(timezone.utc)
                    < datetime.fromisoformat(task['started_at']).astimezone(timezone.utc) - timedelta(seconds=1)
                ):
                    fail('측정 시작 이후 본인이 만든 문서만 자동화 결과로 인정합니다', 409)
                already = c.execute('''SELECT 1 FROM automation_task_times_v60
                    WHERE statement_id=? AND mode='automated' AND status='completed' ''',
                    (body.statement_id,)).fetchone()
                if already:
                    fail('이미 측정한 자동화 결과물입니다', 409)
            elif body.statement_id is not None:
                fail('수작업 비교 기록에는 자동화 문서를 연결하지 않습니다', 400)
            finished = utcnow()
            duration_ms = round((finished - datetime.fromisoformat(task['started_at'])).total_seconds() * 1000)
            if not 0 <= duration_ms <= 1_800_000:
                fail('30분을 초과한 측정은 비교 통계에 포함할 수 없습니다', 409)
            c.execute('''UPDATE automation_task_times_v60
                SET status='completed',finished_at=?,elapsed_ms=?,statement_id=?
                WHERE id=? AND org_id=? AND status='running' ''',
                (finished.isoformat(), duration_ms, body.statement_id, run_id, user['org_id']))
            return {'id': run_id, 'mode': task['mode'], 'workflow': task['workflow'],
                    'elapsed_ms': duration_ms, 'status': 'completed',
                    'measurement': 'server_elapsed_time',
                    'task_outcome': 'linked_document' if task['mode'] == 'automated' else 'self_reported_completion'}

    @app.get('/api/automation/timing/active')
    def timing_active(user=Depends(current_user)):
        with conn() as c:
            row = c.execute('''SELECT id,workflow,mode,started_at
                FROM automation_task_times_v60 WHERE user_id=? AND org_id=?
                AND status='running' LIMIT 1''',
                (user['id'],user['org_id'])).fetchone()
        return dict(row) if row else None

    @app.post('/api/automation/timing/{run_id}/cancel')
    def timing_cancel(run_id: str, user=Depends(current_user)):
        # Only running measurements can be discarded; completed evidence is immutable.
        with transaction() as c:
            task = c.execute('''SELECT * FROM automation_task_times_v60
                WHERE id=? AND org_id=? AND user_id=?''',
                (run_id,user['org_id'],user['id'])).fetchone()
            if not task:
                fail('작업 측정을 찾을 수 없습니다',404)
            if task['status'] != 'running':
                fail('완료한 작업 측정은 취소할 수 없습니다',409)
            c.execute("DELETE FROM automation_task_times_v60 WHERE id=? AND org_id=? AND user_id=? AND status='running'",
                      (run_id,user['org_id'],user['id']))
            audit(c,user,'automation_timing',run_id,'cancel',
                  {'workflow':task['workflow'],'mode':task['mode']})
            return {'id':run_id,'status':'cancelled','excluded_from_metrics':True}

    @app.get('/api/automation/time-savings')
    def timing_report(user=Depends(current_user)):
        with conn() as c:
            rows = c.execute('''SELECT mode, elapsed_ms FROM automation_task_times_v60
                WHERE org_id=? AND workflow='trade_statement' AND status='completed'
                AND elapsed_ms IS NOT NULL''', (user['org_id'],)).fetchall()
        data = {
            m: sorted(x['elapsed_ms'] for x in rows if x['mode'] == m)
            for m in ('manual', 'automated')
        }
        n_manual, n_automated = len(data['manual']), len(data['automated'])
        enough = n_manual >= 3 and n_automated >= 3
        result = {
            'workflow': 'trade_statement',
            'samples': {'manual': n_manual, 'automated': n_automated},
            'median_manual_ms': statistics.median(data['manual']) if n_manual else None,
            'median_automated_ms': statistics.median(data['automated']) if n_automated else None,
            'observed_difference_ms': (statistics.median(data['manual']) -
                                       statistics.median(data['automated'])) if enough else None,
            'status': 'COMPARISON_AVAILABLE' if enough else 'NOT_MEASURED',
            'disclaimer': ('비교는 동일 업무의 서버 측정시간 중위수 차이입니다. '
                           '수작업 완료는 사용자 확인값이며 실험 통제·인과적 절감효과를 입증하지 않습니다.'),
        }
        return result
