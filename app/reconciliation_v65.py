"""V6.5 conservative, tenant-scoped evidence-vs-sales-document comparison.

Comparisons are advisory. The linked record is immutable, and no accounting,
payment, inventory, quote, order, or invoice mutation is allowed here.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Literal
from fastapi import Depends
from pydantic import BaseModel, ConfigDict, Field
from .security_hardening import unseal_json
from .reconciliation_lines_v66 import snapshot as line_snapshot

SOURCE_TABLES = {'quote': 'quotes', 'order': 'orders', 'invoice': 'invoices'}
ALLOWED_EVIDENCE = ('sales_slip', 'trade_statement')


class LinkRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    source_type: Literal['quote', 'order', 'invoice']
    source_id: str = Field(min_length=1, max_length=100)
    comparison_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    original_and_differences_checked: Literal[True]
    discrepancy_reason: str = Field(default='', max_length=400)


def install_schema(conn):
    with conn() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS evidence_links_v65 (
          id TEXT PRIMARY KEY,
          org_id TEXT NOT NULL REFERENCES organizations(id),
          record_id TEXT NOT NULL UNIQUE REFERENCES evidence_records_v64(id),
          source_type TEXT NOT NULL CHECK (source_type IN ('quote','order','invoice')),
          source_id TEXT NOT NULL,
          comparison_json TEXT NOT NULL,
          comparison_digest TEXT NOT NULL,
          discrepancy_reason TEXT NOT NULL,
          reviewed_by TEXT NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_evidence_links_v65_org ON evidence_links_v65(org_id,created_at);
        CREATE TRIGGER IF NOT EXISTS trg_v65_insert_guard BEFORE INSERT ON evidence_links_v65
        BEGIN
          SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM evidence_records_v64 WHERE id=NEW.record_id AND org_id=NEW.org_id
              AND kind='sales' AND source_kind IN ('sales_slip','trade_statement')
          ) THEN RAISE(ABORT,'evidence_tenant_or_type_mismatch') END;
          SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM users WHERE id=NEW.reviewed_by AND org_id=NEW.org_id
          ) THEN RAISE(ABORT,'reviewer_tenant_mismatch') END;
          SELECT CASE WHEN NOT (
            (NEW.source_type='quote' AND EXISTS(SELECT 1 FROM quotes WHERE id=NEW.source_id AND org_id=NEW.org_id)) OR
            (NEW.source_type='order' AND EXISTS(SELECT 1 FROM orders WHERE id=NEW.source_id AND org_id=NEW.org_id)) OR
            (NEW.source_type='invoice' AND EXISTS(SELECT 1 FROM invoices WHERE id=NEW.source_id AND org_id=NEW.org_id))
          ) THEN RAISE(ABORT,'source_tenant_mismatch') END;
        END;
        CREATE TRIGGER IF NOT EXISTS trg_v65_no_update BEFORE UPDATE ON evidence_links_v65
        BEGIN SELECT RAISE(ABORT,'immutable_reconciliation_link'); END;
        CREATE TRIGGER IF NOT EXISTS trg_v65_no_delete BEFORE DELETE ON evidence_links_v65
        BEGIN SELECT RAISE(ABORT,'immutable_reconciliation_link'); END;
        ''')


def norm(value):
    # Exact-ish for whitespace / common punctuation only, NOT fuzzy, romanization or OCR guessing.
    return re.sub(r'[\s\-_.·()（）]+', '', str(value or '')).casefold()


def digest(payload):
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True,
            separators=(',', ':')).encode('utf-8')).hexdigest()


def compare_lines(source_items, evidence_lines):
    """Exact name-based line compare; ambiguous names are *not* guessed.

    A missing line means unverified coverage, not inferred delivered quantity.
    Unit prices are integer KRW. Product codes are informational only because
    the current source item schema has no trustworthy product_code field.
    """
    from collections import Counter
    source_counts = Counter(norm(x['name']) for x in source_items)
    evidence_counts = Counter(norm(x['name']) for x in evidence_lines)
    by_source = {norm(x['name']): x for x in source_items if source_counts[norm(x['name'])] == 1}
    issues=[]
    detail=[]
    matched_names=set()
    for entry in evidence_lines:
        k=norm(entry['name'])
        if not k or evidence_counts[k]>1 or source_counts[k]>1:
            state='ambiguous_line'
            issues.append({'field':state,'item':entry['name'],'expected':'단일 고유 품목명','actual':'품목명 중복/빈 값'})
        elif k not in by_source:
            state='unmatched_line'
            issues.append({'field':state,'item':entry['name'],'expected':'내부 등록 품목','actual':entry['name']})
        else:
            src=by_source[k]
            matched_names.add(k)
            quantity,price=entry['quantity'],entry['unit_price']
            if price!=src['unit_price']:
                issues.append({'field':'line_unit_price','item':entry['name'],
                               'expected':src['unit_price'],'actual':price})
            if quantity<src['quantity']:
                state='partial_quantity'
                issues.append({'field':state,'item':entry['name'],
                               'expected':src['quantity'],'actual':quantity})
            elif quantity>src['quantity']:
                state='excess_quantity'
                issues.append({'field':state,'item':entry['name'],
                               'expected':src['quantity'],'actual':quantity})
            else:state='quantity_match'
        detail.append({'item':entry['name'],'quantity':entry['quantity'],
                       'unit_price':entry['unit_price'],'line_amount':entry['quantity']*entry['unit_price'],
                       'status':state,'product_code_checked':False})
        if entry['product_code']:
            issues.append({'field':'product_code_unverifiable','item':entry['name'],
                           'expected':'원본 품목코드 저장 필드 없음','actual':entry['product_code']})
    for source in source_items:
        k=norm(source['name'])
        if k not in matched_names and evidence_counts[k]==0:
            issues.append({'field':'missing_source_line','item':source['name'],
                           'expected':source['quantity'],'actual':0})
    return {'lines':detail,'issues':issues,
            'source_line_count':len(source_items),'evidence_line_count':len(evidence_lines),
            'matched_line_count':len(matched_names),
            'evidence_subtotal':sum(x['quantity']*x['unit_price'] for x in evidence_lines),
            'full_source_coverage':len(matched_names)==len(source_items) and
                 len(evidence_lines)==len(source_items) and all(
                    line['status']=='quantity_match' for line in detail)}


def comparison(c, record, source_type, source, retrieve_items, money):
    items = retrieve_items(c, source_type, source['id'])
    expected = money(items, source['vat_mode'])
    actual_amount = record['gross_amount']
    same_name = bool(norm(record['counterparty'])) and norm(record['counterparty']) == norm(source['customer_name_snapshot'])
    same_ref = bool(norm(record['reference_number'])) and norm(record['reference_number']) == norm(source['doc_no'])
    issues = []
    # Never infer identity solely from matching gross amount.
    if not same_name:
        issues.append({'field': 'counterparty', 'expected': source['customer_name_snapshot'], 'actual': record['counterparty']})
    if record['reference_number'] and not same_ref:
        issues.append({'field': 'reference_number', 'expected': source['doc_no'], 'actual': record['reference_number']})
    if actual_amount != expected['total']:
        issues.append({'field': 'gross_amount', 'expected': expected['total'], 'actual': actual_amount})
    approved_lines=line_snapshot(c,record['id'],record['org_id'])
    line_evaluation=None
    if approved_lines:
        line_evaluation=compare_lines(items,approved_lines)
        issues.extend(line_evaluation['issues'])
        # Cannot prove how an external invoice rounds VAT / handles discounts.
        # A discrepancy is advisory, never an automatic accounting adjustment.
        calculated=money(approved_lines,source['vat_mode'])
        if calculated['total']!=actual_amount:
            issues.append({'field':'evidence_lines_gross_total',
                           'expected':calculated['total'],'actual':actual_amount})
    elif record['sku']:
        sku_items = [item for item in items if norm(item['name']) == norm(record['sku'])]
        if len(sku_items) != 1:
            issues.append({'field': 'sku', 'expected': '내부 품목명과 정확히 대응하지 않음', 'actual': record['sku']})
        elif record['quantity'] is not None and record['quantity'] != sku_items[0]['quantity']:
            issues.append({'field': 'quantity', 'expected': sku_items[0]['quantity'], 'actual': record['quantity']})
    elif record['quantity'] is not None:
        issues.append({'field': 'quantity_unverifiable', 'expected': '품목 식별 필요', 'actual': record['quantity']})
    payload = {
        'record_id': record['id'], 'record_type': record['kind'], 'source_kind': record['source_kind'],
        'source_type': source_type, 'source_id': source['id'], 'source_no': source['doc_no'],
        'source_status': source['status'],
        'customer': source['customer_name_snapshot'], 'expected_amount': expected['total'],
        'actual_amount': actual_amount, 'issues': issues,
        'identity_basis': 'document_number' if same_ref else ('counterparty' if same_name else 'none'),
        'recommendation': 'manual_review_required' if issues else 'exact_fields_match',
        'mutates_source': False, 'official_accounting': False,
    }
    if line_evaluation is not None:
        payload['line_comparison'] = line_evaluation
    return {**payload, 'comparison_digest': digest(payload)}


def register_routes(app, *, conn, transaction, current_user, get_row, retrieve_items, money, audit, ident, now, fail):
    def get_record(c, rid, user):
        record = get_row(c, 'evidence_records_v64', rid, user['org_id'])
        # Members can only reconcile evidence created from their own previews.
        if user['role'] != 'admin':
            source = c.execute('SELECT uploaded_by FROM evidence_previews_v64 WHERE id=? AND org_id=?',
                               (record['preview_id'], user['org_id'])).fetchone()
            if not source or source['uploaded_by'] != user['id']:
                fail('업로더 또는 관리자만 대조할 수 있습니다',403)
        return record

    def read_source(c, source_type, source_id, org):
        return get_row(c, SOURCE_TABLES[source_type], source_id, org)

    def existing_link(c, rid, org):
        link = c.execute('SELECT * FROM evidence_links_v65 WHERE org_id=? AND record_id=?',
                         (org, rid)).fetchone()
        return dict(link) if link else None

    @app.get('/api/evidence/reconciliation/queue')
    def reconciliation_queue(user=Depends(current_user)):
        with conn() as c:
            clause = '' if user['role']=='admin' else ' AND p.uploaded_by=?'
            params = (user['org_id'],) if user['role']=='admin' else (user['org_id'],user['id'])
            rows = c.execute('''SELECT r.id,r.kind,r.source_kind,r.counterparty,r.document_date,
                r.gross_amount,r.reference_number,r.created_at,
                l.id AS link_id,l.source_type,l.source_id,l.comparison_json
                FROM evidence_records_v64 r
                JOIN evidence_previews_v64 p ON p.id=r.preview_id AND p.org_id=r.org_id
                LEFT JOIN evidence_links_v65 l ON l.record_id=r.id AND l.org_id=r.org_id
                WHERE r.org_id=?'''+clause+''' ORDER BY r.created_at DESC,r.rowid DESC LIMIT 100''', params).fetchall()
            items=[]
            for row in rows:
                o=dict(row)
                snapshot=json.loads(o.pop('comparison_json')) if o['link_id'] else None
                o['issues_at_link']=snapshot['issues'] if snapshot else []
                o['status']='linked_with_issues' if snapshot and snapshot['issues'] else ('linked' if snapshot else 'needs_review')
                if o['kind']!='sales' or o['source_kind'] not in ALLOWED_EVIDENCE:
                    o['status']='unsupported_source_direction' if not snapshot else o['status']
                items.append(o)
            return {'items': items, 'unlinked':sum(x['status']=='needs_review' for x in items),
                'linked_with_issues':sum(x['status']=='linked_with_issues' for x in items),
                'note':'대조는 내부 매출 거래의 판매 증빙만 지원합니다. 매입·경비·재고는 자동 연결하지 않습니다.'}

    @app.get('/api/evidence/records/{rid}/candidates')
    def candidates(rid: str, user=Depends(current_user)):
        with conn() as c:
            record = get_record(c, rid, user)
            link=existing_link(c,rid,user['org_id'])
            if record['kind']!='sales' or record['source_kind'] not in ALLOWED_EVIDENCE:
                return {'candidates': [], 'supported':False, 'already_linked':bool(link),
                        'reason':'내부 매출 거래 증빙만 대조할 수 있습니다. 매입·경비·재고는 수동 검토하세요.'}
            result=[]
            for source_type, table in SOURCE_TABLES.items():
                # Tenant restriction precedes all comparisons. Keep a strict query bound.
                rows=c.execute(f'''SELECT id,org_id,doc_no,customer_name_snapshot,vat_mode,status
                    FROM {table} WHERE org_id=? ORDER BY rowid DESC LIMIT 120''',(user['org_id'],)).fetchall()
                for source in rows:
                    matched_ref=bool(norm(record['reference_number'])) and norm(record['reference_number'])==norm(source['doc_no'])
                    matched_party=bool(norm(record['counterparty'])) and norm(record['counterparty'])==norm(source['customer_name_snapshot'])
                    if matched_ref or matched_party:
                        result.append(comparison(c,record,source_type,source,retrieve_items,money))
            result.sort(key=lambda x:(x['identity_basis']!='document_number',bool(x['issues']),len(x['issues']),x['source_type'],x['source_no']))
            return {'candidates':result[:30], 'supported':True, 'truncated':len(result)>30,
                    'already_linked':bool(link), 'linked_source':{'type':link['source_type'],'id':link['source_id']} if link else None,
                    'auto_linked':False, 'note':'후보는 참고용이며 자동 확정하지 않습니다.'}

    @app.post('/api/evidence/records/{rid}/reconcile-link',status_code=201)
    def link_to_source(rid:str,body:LinkRequest,user=Depends(current_user)):
        with transaction() as c:
            record=get_record(c,rid,user)
            if record['kind']!='sales' or record['source_kind'] not in ALLOWED_EVIDENCE:
                fail('현재 매출전표와 매출 거래명세표만 거래 연결을 지원합니다',422)
            source=read_source(c,body.source_type,body.source_id,user['org_id'])
            d=comparison(c,record,body.source_type,source,retrieve_items,money)
            if not hmac.compare_digest(d['comparison_digest'],body.comparison_digest):
                fail('원본 거래 또는 증빙 값이 달라졌습니다. 다시 대조하세요',409)
            if d['identity_basis']=='none':fail('거래처 또는 문서번호가 일치하지 않습니다. 직접 확인할 수 없는 연결은 차단합니다',409)
            if d['issues'] and len(body.discrepancy_reason.strip())<12:
                fail('불일치 원인에 대한 12자 이상의 확인 사유가 필요합니다',422)
            existing=existing_link(c,rid,user['org_id'])
            if existing:
                if existing['source_type']==body.source_type and existing['source_id']==body.source_id:
                    return {'id':existing['id'], 'reused':True, 'issues':json.loads(existing['comparison_json'])['issues'],
                            'source_changed':existing['comparison_digest']!=d['comparison_digest']}
                fail('이미 다른 내부 거래와 연결한 증빙은 재연결할 수 없습니다',409)
            key=ident()
            c.execute('''INSERT INTO evidence_links_v65(id,org_id,record_id,source_type,source_id,
                       comparison_json,comparison_digest,discrepancy_reason,reviewed_by,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?)''',
                      (key,user['org_id'],rid,body.source_type,body.source_id,
                       json.dumps({k:v for k,v in d.items() if k!='comparison_digest'},ensure_ascii=False,sort_keys=True),
                       d['comparison_digest'],body.discrepancy_reason.strip(),user['id'],now()))
            audit(c,user,'evidence_reconciliation',key,'link',
                  {'record_id':rid,'source_type':body.source_type,'source_id':body.source_id,
                   'issues':[x['field'] for x in d['issues']], 'accounting_changed':False})
            return {'id':key,'reused':False,'issues':d['issues'],
                    'accounting_changed':False,'payment_created':False,'inventory_stock_changed':False}

    @app.get('/api/evidence/records/{rid}/reconciliation')
    def record_reconciliation(rid:str,user=Depends(current_user)):
        with conn() as c:
            record=get_record(c,rid,user)
            link=existing_link(c,rid,user['org_id'])
            if not link:return {'linked':False,'record_id':record['id']}
            snapshot=json.loads(link['comparison_json'])
            source=read_source(c,link['source_type'],link['source_id'],user['org_id'])
            fresh=comparison(c,record,link['source_type'],source,retrieve_items,money)
            return {'linked':True,'record_id':rid,'source_type':link['source_type'],
                    'source_id':link['source_id'],'comparison_at_link':snapshot,
                    'issues_at_link':snapshot['issues'],
                    'discrepancy_reason':link['discrepancy_reason'],
                    'source_changed':link['comparison_digest']!=fresh['comparison_digest'],
                    'current_comparison':fresh,
                    'immutable':True}
