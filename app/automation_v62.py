"""V6.2 verified-source business document drafts and Excel export.

Creates *internal frozen drafts*, never invoices, delivery attestations, purchase
orders, outbound messages, money movements, or inventory transactions.
"""
from __future__ import annotations

import io
import json
from typing import Literal

from fastapi import Depends, Response
from pydantic import BaseModel, ConfigDict, Field
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)


DocKind = Literal['sales_order_draft', 'delivery_note_draft', 'payment_request_draft']


class CreateDraft(Strict):
    source_id: str = Field(min_length=1, max_length=100)
    kind: DocKind


class BatchDraft(Strict):
    kind: Literal['delivery_note_draft']
    source_ids: list[str] = Field(min_length=1, max_length=20)


DDL = '''
CREATE TABLE IF NOT EXISTS automation_document_drafts_v62 (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    created_by TEXT NOT NULL REFERENCES users(id),
    kind TEXT NOT NULL CHECK(kind IN ('sales_order_draft','delivery_note_draft','payment_request_draft')),
    source_type TEXT NOT NULL CHECK(source_type IN ('quote','order','invoice')),
    source_id TEXT NOT NULL,
    document_no TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(org_id,kind,source_id),
    UNIQUE(org_id,document_no),
    CHECK ((kind='sales_order_draft' AND source_type='quote')
        OR (kind='delivery_note_draft' AND source_type='order')
        OR (kind='payment_request_draft' AND source_type='invoice'))
);
CREATE INDEX IF NOT EXISTS idx_auto_drafts_org_v62
  ON automation_document_drafts_v62(org_id,created_at);
CREATE TRIGGER IF NOT EXISTS auto_draft_insert_guard_v62
BEFORE INSERT ON automation_document_drafts_v62
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1 FROM users WHERE id=NEW.created_by AND org_id=NEW.org_id
    ) THEN RAISE(ABORT, 'draft_actor_tenant_mismatch') END;
    SELECT CASE WHEN NOT (
        (NEW.source_type='quote' AND EXISTS(SELECT 1 FROM quotes WHERE id=NEW.source_id AND org_id=NEW.org_id))
        OR (NEW.source_type='order' AND EXISTS(SELECT 1 FROM orders WHERE id=NEW.source_id AND org_id=NEW.org_id))
        OR (NEW.source_type='invoice' AND EXISTS(SELECT 1 FROM invoices WHERE id=NEW.source_id AND org_id=NEW.org_id))
    ) THEN RAISE(ABORT, 'draft_source_tenant_mismatch') END;
END;
CREATE TRIGGER IF NOT EXISTS auto_draft_update_guard_v62
BEFORE UPDATE ON automation_document_drafts_v62
BEGIN SELECT RAISE(ABORT,'immutable_document_draft'); END;
CREATE TRIGGER IF NOT EXISTS auto_draft_delete_guard_v62
BEFORE DELETE ON automation_document_drafts_v62
BEGIN SELECT RAISE(ABORT,'immutable_document_draft'); END;
'''

KIND_SOURCE = {
    'sales_order_draft': ('quotes', 'quote', 'SO'),
    'delivery_note_draft': ('orders', 'order', 'DN'),
    'payment_request_draft': ('invoices', 'invoice', 'PR'),
}


def install_schema(conn):
    with conn() as c:
        c.executescript(DDL)


def safe_excel_string(value):
    """Prevent user-controlled text from evaluating as a spreadsheet formula."""
    if value is None:
        return ''
    if not isinstance(value, str):
        return value
    if value.lstrip(' \t\r\n').startswith(('=', '+', '-', '@')) or value[:1] in ('\t', '\r', '\n'):
        return "'" + value
    return value


def build_xlsx(public_document: dict) -> bytes:
    data = public_document['document']
    wb = Workbook()
    ws = wb.active
    ws.title = '문서초안'
    ws.append(['JARVIS WORKS 업무 문서 초안'])
    ws.merge_cells('A1:D1')
    ws['A1'].font = Font(bold=True, size=16, color='FFFFFF')
    ws['A1'].fill = PatternFill('solid', fgColor='17365D')
    ws.append(['문서 유형', safe_excel_string(data['label']), '문서 번호', public_document['document_no']])
    ws.append(['원본 유형', data['source_type'], '원본 번호', safe_excel_string(data['source_no'])])
    ws.append(['거래처', safe_excel_string(data['customer_name']), '작성 기준', public_document['created_at']])
    ws.append(['주의', '내부 검토용 초안 · 전자세금계산서/법정 증명 문서가 아님'])
    ws.merge_cells('B5:D5')
    ws.append([])
    ws.append(['품목', '수량', '단가 (KRW)', '금액 (KRW)'])
    for item in data['items']:
        ws.append([safe_excel_string(item['name']), int(item['quantity']), int(item['unit_price']), int(item['line_total'])])
    ws.append([])
    for label, key in (('공급가액', 'subtotal'), ('부가세', 'vat'), ('합계', 'total')):
        ws.append([label, '', '', data['money'][key]])
    if data.get('balance_at_creation') is not None:
        ws.append(['생성 시점 미수 잔액', '', '', data['balance_at_creation']])
    ws.freeze_panes = 'A8'
    for col, width in [('A', 38), ('B', 18), ('C', 22), ('D', 22)]:
        ws.column_dimensions[col].width = width
    for cell in ws[7]:
        cell.fill = PatternFill('solid', fgColor='E6EEF8')
        cell.font = Font(bold=True, color='17365D')
        cell.alignment = Alignment(horizontal='center')
    for row in ws.iter_rows(min_row=8, max_col=4):
        for cell in row[1:]:
            if isinstance(cell.value, int):
                cell.number_format = '#,##0;[Red](#,##0)'
    ws.sheet_view.showGridLines = False
    output = io.BytesIO()
    wb.save(output)
    return output.getvalue()


def register_routes(app, *, conn, transaction, current_user, get_row,
                    retrieve_items, money, audit, ident, now, fail):

    def public(row, reused=False):
        return {
            'id': row['id'], 'kind': row['kind'], 'document_no': row['document_no'],
            'source_id': row['source_id'], 'source_type': row['source_type'],
            'created_at': row['created_at'], 'reused': reused,
            'document': json.loads(row['payload_json']),
            'scope': 'authenticated_tenant_only',
        }

    def current_invoice_balance(c, org_id, invoice_id):
        invoice = c.execute('SELECT * FROM invoices WHERE id=? AND org_id=?',
                            (invoice_id,org_id)).fetchone()
        if invoice is None:
            return None
        total = money(retrieve_items(c,'invoice',invoice_id),invoice['vat_mode'])['total']
        paid = c.execute('''SELECT COALESCE(SUM(amount),0) FROM payments
            WHERE org_id=? AND invoice_id=? AND reversed_at IS NULL''',
            (org_id,invoice_id)).fetchone()[0]
        return total-paid

    def with_freshness(c, org_id, document):
        if document['kind'] == 'payment_request_draft':
            balance = current_invoice_balance(c,org_id,document['source_id'])
            document['current_balance'] = balance
            document['stale'] = balance != document['document']['balance_at_creation']
        else:
            document['stale'] = False
        return document

    def get_existing(c, org_id, kind, source_id):
        return c.execute('''SELECT * FROM automation_document_drafts_v62
            WHERE org_id=? AND kind=? AND source_id=?''', (org_id, kind, source_id)).fetchone()

    def create_one(c, user, kind, source_id):
        table, source_type, prefix = KIND_SOURCE[kind]
        # Read org-filtered source before returning an existing snapshot: no ID oracle.
        source = get_row(c, table, source_id, user['org_id'])
        existing = get_existing(c, user['org_id'], kind, source_id)
        if existing:
            out = with_freshness(c,user['org_id'],public(dict(existing), reused=True))
            if out['stale']:
                fail('생성 후 입금 잔액이 변경되어 기존 초안 재사용을 차단했습니다',409)
            return out
        if kind == 'sales_order_draft' and source['status'] != 'accepted':
            fail('승인된 견적서만 수주서 초안을 만들 수 있습니다', 409)
        if kind == 'delivery_note_draft' and (source['status'] != 'fulfilled' or source['review_state'] == 'pending'):
            fail('납품 완료되고 변경 검토가 끝난 발주만 납품서 초안을 만들 수 있습니다', 409)
        if kind == 'payment_request_draft' and source['status'] != 'issued':
            fail('발행 상태의 청구서만 입금요청 초안을 만들 수 있습니다', 409)
        entries = retrieve_items(c, source_type, source_id)
        if not entries:
            fail('품목 없는 거래는 문서 초안으로 변환할 수 없습니다', 409)
        amounts = money(entries, source['vat_mode'])
        balance = None
        if kind == 'payment_request_draft':
            paid = c.execute('''SELECT COALESCE(SUM(amount),0) FROM payments
                WHERE org_id=? AND invoice_id=? AND reversed_at IS NULL''',
                (user['org_id'], source_id)).fetchone()[0]
            balance = amounts['total'] - paid
            if balance <= 0:
                fail('미수 잔액이 없는 청구서는 입금요청 초안을 만들 수 없습니다', 409)
        label = {'sales_order_draft': '수주서 초안', 'delivery_note_draft': '납품서 초안',
                 'payment_request_draft': '입금요청서 초안'}[kind]
        snap = {
            'label': label, 'source_type': source_type, 'source_id': source_id,
            'source_no': source['doc_no'], 'customer_name': source['customer_name_snapshot'],
            'title': source['title'] if source_type != 'invoice' else source['doc_no'],
            'vat_mode': source['vat_mode'], 'money': amounts,
            'source_status_at_creation': source['status'],
            'source_updated_at': source['updated_at'] if source_type != 'invoice' else None,
            'items': [
                {'name': item['name'], 'quantity': item['quantity'],
                 'unit_price': item['unit_price'], 'line_total': item['quantity'] * item['unit_price']}
                for item in entries
            ],
            'balance_at_creation': balance,
            'document_status': 'internal_review_draft_only',
            'warning': '실제 수주/납품 확정, 회계 전표, 입금 또는 외부 발송은 실행하지 않습니다',
        }
        key = ident()
        doc_no = f'{prefix}-{key[:12].upper()}'
        created_at = now()
        c.execute('''INSERT INTO automation_document_drafts_v62
            (id,org_id,created_by,kind,source_type,source_id,document_no,payload_json,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)''',
            (key,user['org_id'],user['id'],kind,source_type,source_id,doc_no,
             json.dumps(snap,ensure_ascii=False,sort_keys=True),created_at))
        audit(c, user, 'automation_document_draft', key, 'create',
              {'kind':kind,'source_type':source_type,'source_id':source_id,'document_no':doc_no})
        return public(dict(c.execute(
            'SELECT * FROM automation_document_drafts_v62 WHERE id=? AND org_id=?',
            (key,user['org_id'])).fetchone()))

    @app.post('/api/automation/drafts/from-source', status_code=201)
    def draft_from_source(body: CreateDraft, response: Response, user=Depends(current_user)):
        with transaction() as c:
            d = create_one(c,user,body.kind,body.source_id)
            if d['reused']:
                response.status_code = 200
            return d

    @app.post('/api/automation/drafts/batch', status_code=201)
    def drafts_batch(body: BatchDraft, user=Depends(current_user)):
        # Transactional fail-closed: any invalid/foreign/duplicate source rejects all.
        if len(set(body.source_ids)) != len(body.source_ids):
            fail('중복된 원본 문서가 포함되어 있습니다', 400)
        with transaction() as c:
            # Validate ALL prior to writing any new draft.
            for source_id in body.source_ids:
                source = get_row(c, 'orders', source_id, user['org_id'])
                existing = get_existing(c,user['org_id'],body.kind,source_id)
                if not existing and (source['status'] != 'fulfilled' or source['review_state'] == 'pending'):
                    fail('일괄 전환 목록에 납품 완료·검토 조건을 만족하지 않는 발주가 있습니다', 409)
            results = [create_one(c,user,body.kind,source_id) for source_id in body.source_ids]
            return {'kind':body.kind,'count':len(results),
                    'created':sum(not d['reused'] for d in results),
                    'reused':sum(d['reused'] for d in results),
                    'documents':results, 'atomic':True}

    @app.get('/api/automation/drafts/summary')
    def draft_summary(user=Depends(current_user)):
        with conn() as c:
            records=c.execute('''SELECT kind,COUNT(*) AS n FROM automation_document_drafts_v62
                WHERE org_id=? GROUP BY kind''',(user['org_id'],)).fetchall()
            latest=c.execute('''SELECT id,kind,document_no,created_at FROM automation_document_drafts_v62
                WHERE org_id=? ORDER BY created_at DESC,id DESC LIMIT 5''',
                (user['org_id'],)).fetchall()
            return {'total':sum(row['n'] for row in records),
                    'by_kind':{row['kind']:row['n'] for row in records},
                    'recent':[dict(row) for row in latest],
                    'scope':'authenticated_tenant_only'}

    @app.get('/api/automation/drafts/{draft_id}')
    def draft_detail(draft_id: str, user=Depends(current_user)):
        with conn() as c:
            row = c.execute('''SELECT * FROM automation_document_drafts_v62
                WHERE id=? AND org_id=?''', (draft_id,user['org_id'])).fetchone()
            if row is None:
                fail('문서 초안을 찾을 수 없습니다',404)
            return with_freshness(c,user['org_id'],public(dict(row)))

    @app.get('/api/automation/drafts/{draft_id}/xlsx')
    def draft_xlsx(draft_id: str, user=Depends(current_user)):
        with conn() as c:
            row = c.execute('''SELECT * FROM automation_document_drafts_v62
                WHERE id=? AND org_id=?''', (draft_id,user['org_id'])).fetchone()
            if row is None:
                fail('문서 초안을 찾을 수 없습니다',404)
            doc = with_freshness(c,user['org_id'],public(dict(row)))
            if doc['stale']:
                fail('입금 잔액이 변경된 이전 초안은 엑셀로 내려받을 수 없습니다',409)
            raw = build_xlsx(doc)
        filename = doc['document_no']+'.xlsx'  # generated ASCII identifier only
        return Response(content=raw,
                        media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                        headers={'Content-Disposition':f'attachment; filename="{filename}"',
                                 'Cache-Control':'private, no-store',
                                 'X-Content-Type-Options':'nosniff'})
