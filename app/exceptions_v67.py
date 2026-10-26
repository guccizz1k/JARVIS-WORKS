"""V6.7 auditable human-only discrepancy triage.

An investigation or document-check event is NOT accounting approval, a money
movement, an inventory update, or a resolution of underlying discrepancies.
"""
from __future__ import annotations
import hashlib
import json
from typing import Literal
from fastapi import Depends
from pydantic import BaseModel, ConfigDict, Field
from .reconciliation_v65 import comparison, SOURCE_TABLES
from .reconciliation_lines_v66 import snapshot as line_snapshot


class Review(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    expected_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    status: Literal['investigating','document_checked']
    original_checked: Literal[True]
    note: str = Field(min_length=12,max_length=500)


def fingerprint(payload):
    return hashlib.sha256(json.dumps(payload,sort_keys=True,ensure_ascii=False,
                                    separators=(',',':')).encode()).hexdigest()


def install_schema(conn):
    with conn() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS reconciliation_reviews_v67 (
          id TEXT PRIMARY KEY,
          org_id TEXT NOT NULL REFERENCES organizations(id),
          record_id TEXT NOT NULL REFERENCES evidence_records_v64(id),
          status TEXT NOT NULL CHECK(status IN ('investigating','document_checked')),
          evidence_digest TEXT NOT NULL,
          note TEXT NOT NULL,
          reviewed_by TEXT NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL,
          previous_hash TEXT NOT NULL,
          event_hash TEXT NOT NULL UNIQUE
        );
        CREATE INDEX IF NOT EXISTS idx_reconciliation_reviews_v67 ON
          reconciliation_reviews_v67(org_id,record_id,created_at);
        CREATE TRIGGER IF NOT EXISTS trg_v67_review_tenant BEFORE INSERT ON reconciliation_reviews_v67
        BEGIN
          SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM evidence_records_v64 r WHERE r.id=NEW.record_id AND r.org_id=NEW.org_id
          ) THEN RAISE(ABORT,'review_record_tenant_mismatch') END;
          SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM users u WHERE u.id=NEW.reviewed_by AND u.org_id=NEW.org_id
          ) THEN RAISE(ABORT,'review_user_tenant_mismatch') END;
        END;
        CREATE TRIGGER IF NOT EXISTS trg_v67_no_review_update BEFORE UPDATE ON reconciliation_reviews_v67
        BEGIN SELECT RAISE(ABORT,'immutable_review_event'); END;
        CREATE TRIGGER IF NOT EXISTS trg_v67_no_review_delete BEFORE DELETE ON reconciliation_reviews_v67
        BEGIN SELECT RAISE(ABORT,'immutable_review_event'); END;
        ''')


def register_routes(app, *, conn, transaction, current_user, get_row, retrieve_items,
                    money, ident, now, fail, audit):
    def get_record(c, rid, user):
        row = get_row(c,'evidence_records_v64',rid,user['org_id'])
        if user['role'] != 'admin':
            r = c.execute('SELECT uploaded_by FROM evidence_previews_v64 WHERE id=? AND org_id=?',
                          (row['preview_id'],user['org_id'])).fetchone()
            if not r or r['uploaded_by'] != user['id']:
                fail('업로더 또는 관리자만 검토할 수 있습니다',403)
        return row

    def inspect(c, record, org):
        linked=c.execute('''SELECT * FROM evidence_links_v65 WHERE record_id=? AND org_id=?''',
                         (record['id'],org)).fetchone()
        issues=[]
        source_changed=False
        fresh_digest=None
        if linked:
            issues=json.loads(linked['comparison_json']).get('issues',[])
            table=SOURCE_TABLES[linked['source_type']]
            src=c.execute(f'SELECT * FROM {table} WHERE id=? AND org_id=?',
                          (linked['source_id'],org)).fetchone()
            if src:
                fresh=comparison(c,record,linked['source_type'],src,retrieve_items,money)
                fresh_digest=fresh['comparison_digest']
                source_changed=fresh_digest!=linked['comparison_digest']
            else:
                source_changed=True
        supported=record['kind']=='sales' and record['source_kind'] in ('sales_slip','trade_statement')
        pending = ('linked_with_issues' if issues or source_changed else 'linked') if linked else (
            'unlinked' if supported else 'unsupported_direction')
        base={'record_id':record['id'],'kind':record['kind'],'source_kind':record['source_kind'],
              'record_amount':record['gross_amount'],'linked':bool(linked),
              'linked_source_type':linked['source_type'] if linked else None,
              'linked_source_id':linked['source_id'] if linked else None,
              'linked_digest':linked['comparison_digest'] if linked else None,
              'fresh_digest':fresh_digest,
              'evidence_line_digest':fingerprint(line_snapshot(c,record['id'],org)),
              'issues':issues,'source_changed':source_changed,'case_status':pending}
        return {**base,'expected_digest':fingerprint(base)}

    @app.get('/api/evidence/reconciliation/exceptions')
    def exceptions(user=Depends(current_user)):
        with conn() as c:
            clause='' if user['role']=='admin' else ' AND p.uploaded_by=?'
            params=(user['org_id'],) if user['role']=='admin' else (user['org_id'],user['id'])
            rows=c.execute('''SELECT e.* FROM evidence_records_v64 e
                JOIN evidence_previews_v64 p ON p.id=e.preview_id AND p.org_id=e.org_id
                WHERE e.org_id=?'''+clause+''' ORDER BY e.created_at DESC,e.rowid DESC LIMIT 100''',params).fetchall()
            result=[]
            for row in rows:
                current=inspect(c,row,user['org_id'])
                prev=c.execute('''SELECT id,status,created_at FROM reconciliation_reviews_v67
                    WHERE record_id=? AND org_id=? ORDER BY rowid DESC LIMIT 1''',
                    (row['id'],user['org_id'])).fetchone()
                if prev:current['last_review'] = dict(prev)
                else:current['last_review']=None
                # Checked means an operator inspected it; it does not mean the discrepancy disappeared.
                current['needs_attention']=current['case_status']!='linked' or current['source_changed']
                result.append(current)
            return {'items':result,'needs_attention':sum(x['needs_attention'] for x in result),
                    'total':len(result),'limit':100,'auto_resolved':False,
                    'note':'검토 이벤트는 불일치를 삭제하거나 거래/회계/재고를 변경하지 않습니다.'}

    @app.get('/api/evidence/records/{rid}/review-history')
    def history(rid:str,user=Depends(current_user)):
        with conn() as c:
            get_record(c,rid,user)
            events=[dict(x) for x in c.execute('''SELECT id,status,evidence_digest,note,
                reviewed_by,created_at,previous_hash,event_hash FROM reconciliation_reviews_v67
                WHERE record_id=? AND org_id=? ORDER BY rowid''',(rid,user['org_id']))]
            valid=True
            previous='0'*64
            for evt in events:
                h=fingerprint({k:v for k,v in evt.items() if k!='event_hash'})
                if evt['previous_hash']!=previous or evt['event_hash']!=h:valid=False
                previous=evt['event_hash']
            return {'events':events,'chain_integrity_valid':valid,'not_accounting_approval':True}

    @app.post('/api/evidence/records/{rid}/review-event',status_code=201)
    def add_review(rid:str, body:Review, user=Depends(current_user)):
        with transaction() as c:
            record=get_record(c,rid,user)
            current=inspect(c,record,user['org_id'])
            if body.expected_digest!=current['expected_digest']:
                fail('거래 또는 증빙 상태가 변경되었습니다. 다시 확인하세요',409)
            last=c.execute('''SELECT * FROM reconciliation_reviews_v67
                WHERE record_id=? AND org_id=? ORDER BY rowid DESC LIMIT 1''',
                (rid,user['org_id'])).fetchone()
            if last and last['status']==body.status and last['evidence_digest']==body.expected_digest and last['note']==body.note:
                return {'id':last['id'],'reused':True,'status':last['status'],'unresolved':current['case_status']!='linked'}
            previous=last['event_hash'] if last else '0'*64
            evt={'id':ident(),'status':body.status,'evidence_digest':body.expected_digest,
                 'note':body.note,'reviewed_by':user['id'],'created_at':now(),
                 'previous_hash':previous}
            evt_hash=fingerprint(evt)
            c.execute('''INSERT INTO reconciliation_reviews_v67
                (id,org_id,record_id,status,evidence_digest,note,reviewed_by,created_at,previous_hash,event_hash)
                VALUES(?,?,?,?,?,?,?,?,?,?)''',
                (evt['id'],user['org_id'],rid,body.status,body.expected_digest,body.note,
                 user['id'],evt['created_at'],previous,evt_hash))
            audit(c,user,'evidence_reconciliation',rid,'review_event',
                  {'status':body.status,'snapshot_digest':body.expected_digest,'no_business_mutation':True})
            return {'id':evt['id'],'reused':False,'status':body.status,
                    'unresolved':current['case_status']!='linked','official_accounting_posted':False}
