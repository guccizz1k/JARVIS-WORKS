"""V6.6 explicitly reviewed multi-line evidence snapshots.

Records are advisory documents; recording evidence lines never posts inventory,
accounting, invoices, receivables or payments. Immutable after creation.
"""
from __future__ import annotations

import hashlib
import json
import re
from fastapi import Depends
from pydantic import BaseModel, ConfigDict, Field, field_validator
from .security_hardening import unseal_json


class Line(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=150)
    product_code: str = Field(default='', max_length=80)
    quantity: int = Field(strict=True, ge=1, le=100_000)
    unit_price: int = Field(strict=True, ge=0, le=1_000_000_000)

    @field_validator('name', 'product_code')
    @classmethod
    def no_controls(cls, value, info):
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise ValueError('제어문자는 허용되지 않습니다')
        if info.field_name == 'name' and not value.strip():
            raise ValueError('품목명은 비어 있을 수 없습니다')
        return value


class ConfirmLines(BaseModel):
    model_config = ConfigDict(extra='forbid')
    original_checked: bool = Field(default=False)
    lines: list[Line] = Field(min_length=1, max_length=40)


def install_schema(conn):
    with conn() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS evidence_lines_v66 (
          id TEXT PRIMARY KEY,
          org_id TEXT NOT NULL REFERENCES organizations(id),
          record_id TEXT NOT NULL REFERENCES evidence_records_v64(id),
          position INTEGER NOT NULL CHECK(position>=0 AND position<40),
          name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 150),
          product_code TEXT NOT NULL DEFAULT '',
          quantity INTEGER NOT NULL CHECK(quantity BETWEEN 1 AND 100000),
          unit_price INTEGER NOT NULL CHECK(unit_price BETWEEN 0 AND 1000000000),
          reviewed_by TEXT NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL,
          UNIQUE(record_id,position)
        );
        CREATE INDEX IF NOT EXISTS idx_evidence_lines_v66_org ON evidence_lines_v66(org_id,record_id);
        CREATE TRIGGER IF NOT EXISTS trg_v66_lines_tenant BEFORE INSERT ON evidence_lines_v66
        BEGIN
          SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM evidence_records_v64 e WHERE e.id=NEW.record_id AND e.org_id=NEW.org_id
              AND e.kind='sales' AND e.source_kind IN ('sales_slip','trade_statement')
          ) THEN RAISE(ABORT,'record_tenant_or_type_invalid') END;
          SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM users u WHERE u.id=NEW.reviewed_by AND u.org_id=NEW.org_id
          ) THEN RAISE(ABORT,'reviewer_tenant_invalid') END;
          SELECT CASE WHEN EXISTS (
            SELECT 1 FROM evidence_links_v65 l WHERE l.record_id=NEW.record_id AND l.org_id=NEW.org_id
          ) THEN RAISE(ABORT,'already_reconciled') END;
        END;
        CREATE TRIGGER IF NOT EXISTS trg_v66_lines_no_update BEFORE UPDATE ON evidence_lines_v66
        BEGIN SELECT RAISE(ABORT,'immutable_evidence_lines'); END;
        CREATE TRIGGER IF NOT EXISTS trg_v66_lines_no_delete BEFORE DELETE ON evidence_lines_v66
        BEGIN SELECT RAISE(ABORT,'immutable_evidence_lines'); END;
        ''')


def snapshot(c, rid, org):
    return [dict(r) for r in c.execute('''SELECT name,product_code,quantity,unit_price,position
        FROM evidence_lines_v66 WHERE record_id=? AND org_id=? ORDER BY position''', (rid, org))]


def register_routes(app, *, conn, transaction, current_user, get_row, ident, now, audit, fail):
    def permitted(c, rid, user):
        record = get_row(c, 'evidence_records_v64', rid, user['org_id'])
        if user['role'] != 'admin':
            source = c.execute('''SELECT uploaded_by FROM evidence_previews_v64
                WHERE id=? AND org_id=?''', (record['preview_id'], user['org_id'])).fetchone()
            if not source or source['uploaded_by'] != user['id']:
                fail('업로더 또는 관리자만 조회할 수 있습니다',403)
        return record

    @app.get('/api/evidence/records/{rid}/line-items')
    def get_line_items(rid: str, user=Depends(current_user)):
        with conn() as c:
            permitted(c,rid,user)
            lines=snapshot(c,rid,user['org_id'])
            return {'lines':lines,'confirmed':bool(lines),'immutable':True,'official_accounting':False}

    @app.get('/api/evidence/records/{rid}/line-suggestions')
    def line_suggestions(rid: str, user=Depends(current_user)):
        with conn() as c:
            record=permitted(c,rid,user)
            if record['kind']!='sales' or record['source_kind'] not in ('sales_slip','trade_statement'):
                return {'lines':[],'source':None,'automatic_approval':False}
            preview=c.execute('SELECT proposed_json FROM evidence_previews_v64 WHERE id=? AND org_id=?',
                              (record['preview_id'],user['org_id'])).fetchone()
            doc=unseal_json(preview['proposed_json']) if preview else {}
            suggested=doc.get('suggested_lines',[])
            return {'lines':suggested[:40] if isinstance(suggested,list) else [],
                    'source':doc.get('suggested_lines_source'),
                    'automatic_approval':False,'original_checked_required':True}

    @app.post('/api/evidence/records/{rid}/line-items',status_code=201)
    def confirm_line_items(rid: str, body: ConfirmLines, user=Depends(current_user)):
        if not body.original_checked:
            fail('원본문서와 전체 품목을 대조한 후 확인하세요',422)
        with transaction() as c:
            record=permitted(c,rid,user)
            if record['kind']!='sales' or record['source_kind'] not in ('sales_slip','trade_statement'):
                fail('매출전표 및 매출 거래명세표에서만 품목별 대조를 지원합니다',422)
            existing=snapshot(c,rid,user['org_id'])
            proposal=[{'position':i,**line.model_dump()} for i,line in enumerate(body.lines)]
            if existing:
                # Retries can read the already approved snapshot, but cannot mutate it.
                if existing == proposal:
                    return {'reused':True,'lines':existing,'immutable':True}
                fail('품목 대조 내역은 최초 확인 후 변경할 수 없습니다',409)
            if c.execute('SELECT 1 FROM evidence_links_v65 WHERE record_id=? AND org_id=?',
                         (rid,user['org_id'])).fetchone():
                fail('이미 거래에 연결된 증빙의 품목을 변경할 수 없습니다',409)
            for i,line in enumerate(body.lines):
                c.execute('''INSERT INTO evidence_lines_v66
                   (id,org_id,record_id,position,name,product_code,quantity,unit_price,reviewed_by,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)''',
                   (ident(),user['org_id'],rid,i,line.name,line.product_code,line.quantity,
                    line.unit_price,user['id'],now()))
            audit(c,user,'document_evidence',rid,'confirm_lines',
                  {'count':len(body.lines),'gross_amount_unchanged':record['gross_amount'],
                   'payment_created':False,'inventory_changed':False})
            return {'reused':False,'lines':snapshot(c,rid,user['org_id']),
                    'immutable':True,'accounting_changed':False}
