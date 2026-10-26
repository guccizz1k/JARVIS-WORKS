"""V6.9 — reviewed internal invoice adjustments; no statutory credit-note issuance.

Approved returns/discounts/freight affect *internal receivable* only; all money
is integer KRW. VAT follows the invoice's single VAT mode and rounds once on
adjusted subtotal, not independently per adjustment. Nonstandard tax treatments
are deliberately unsupported. This is not a tax/accounting posting engine.
"""
from __future__ import annotations

import hashlib
import json
from typing import Literal
from fastapi import Depends
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Proposal(BaseModel):
    model_config = ConfigDict(extra='forbid',str_strip_whitespace=True)
    kind: Literal['return','discount','freight']
    request_key: str = Field(min_length=12,max_length=100,pattern=r'^[a-zA-Z0-9_-]{12,100}$')
    item_id: str = Field(default='',max_length=100)
    quantity: int = Field(default=0,strict=True,ge=0,le=100_000)
    amount: int = Field(default=0,strict=True,ge=0,le=10**12)
    reason: str = Field(min_length=12,max_length=500)
    original_checked: Literal[True]

    @model_validator(mode='after')
    def shape(self):
        if self.kind=='return':
            if not self.item_id or not self.quantity or self.amount:
                raise ValueError('반품은 품목 ID와 반품 수량만 입력해야 합니다')
        elif self.item_id or self.quantity or self.amount<1:
            raise ValueError('할인·운임은 금액만 입력해야 합니다')
        return self


class Decision(BaseModel):
    model_config = ConfigDict(extra='forbid',str_strip_whitespace=True)
    approve: bool
    expected_digest: str = Field(pattern=r'^[a-f0-9]{64}$')
    original_checked: Literal[True]
    note: str = Field(min_length=12,max_length=500)


def install_schema(conn):
    with conn() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS invoice_adjustments_v69 (
          id TEXT PRIMARY KEY,
          org_id TEXT NOT NULL REFERENCES organizations(id),
          invoice_id TEXT NOT NULL REFERENCES invoices(id),
          request_key TEXT NOT NULL,
          kind TEXT NOT NULL CHECK(kind IN ('return','discount','freight')),
          item_id TEXT NOT NULL DEFAULT '',
          quantity INTEGER NOT NULL DEFAULT 0 CHECK(quantity BETWEEN 0 AND 100000),
          amount INTEGER NOT NULL DEFAULT 0 CHECK(amount BETWEEN 0 AND 1000000000000),
          reason TEXT NOT NULL,
          created_by TEXT NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL,
          UNIQUE(org_id,invoice_id,request_key)
        );
        CREATE INDEX IF NOT EXISTS idx_v69_adjustment_invoice
          ON invoice_adjustments_v69(org_id,invoice_id,created_at);
        CREATE TABLE IF NOT EXISTS invoice_adjustment_decisions_v69 (
          id TEXT PRIMARY KEY,
          org_id TEXT NOT NULL REFERENCES organizations(id),
          adjustment_id TEXT NOT NULL UNIQUE REFERENCES invoice_adjustments_v69(id),
          decision TEXT NOT NULL CHECK(decision IN ('approved','rejected')),
          decided_by TEXT NOT NULL REFERENCES users(id),
          note TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_v69_decision_org ON invoice_adjustment_decisions_v69(org_id);
        CREATE TRIGGER IF NOT EXISTS v69_adjustment_insert_guard BEFORE INSERT ON invoice_adjustments_v69
        BEGIN
          SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM invoices WHERE id=NEW.invoice_id AND org_id=NEW.org_id)
            THEN RAISE(ABORT,'invoice_tenant_invalid') END;
          SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM users WHERE id=NEW.created_by AND org_id=NEW.org_id)
            THEN RAISE(ABORT,'creator_tenant_invalid') END;
          SELECT CASE WHEN NEW.kind='return' AND NOT EXISTS (
            SELECT 1 FROM invoice_items WHERE id=NEW.item_id AND invoice_id=NEW.invoice_id)
            THEN RAISE(ABORT,'return_item_invalid') END;
          SELECT CASE WHEN NEW.kind!='return' AND (NEW.item_id!='' OR NEW.quantity!=0 OR NEW.amount<=0)
            THEN RAISE(ABORT,'adjustment_shape_invalid') END;
          SELECT CASE WHEN NEW.kind='return' AND (NEW.quantity<=0 OR NEW.amount!=0)
            THEN RAISE(ABORT,'return_shape_invalid') END;
        END;
        CREATE TRIGGER IF NOT EXISTS v69_decision_insert_guard BEFORE INSERT ON invoice_adjustment_decisions_v69
        BEGIN
          SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM invoice_adjustments_v69
            WHERE id=NEW.adjustment_id AND org_id=NEW.org_id)
            THEN RAISE(ABORT,'decision_tenant_invalid') END;
          SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM users WHERE id=NEW.decided_by
            AND org_id=NEW.org_id AND role='admin')
            THEN RAISE(ABORT,'decision_admin_invalid') END;
        END;
        CREATE TRIGGER IF NOT EXISTS v69_adjustment_immutable_update BEFORE UPDATE ON invoice_adjustments_v69
        BEGIN SELECT RAISE(ABORT,'immutable_adjustment'); END;
        CREATE TRIGGER IF NOT EXISTS v69_adjustment_immutable_delete BEFORE DELETE ON invoice_adjustments_v69
        BEGIN SELECT RAISE(ABORT,'immutable_adjustment'); END;
        CREATE TRIGGER IF NOT EXISTS v69_decision_immutable_update BEFORE UPDATE ON invoice_adjustment_decisions_v69
        BEGIN SELECT RAISE(ABORT,'immutable_decision'); END;
        CREATE TRIGGER IF NOT EXISTS v69_decision_immutable_delete BEFORE DELETE ON invoice_adjustment_decisions_v69
        BEGIN SELECT RAISE(ABORT,'immutable_decision'); END;
        ''')


def adjustments(c, invoice_id, org):
    return [dict(r) for r in c.execute('''SELECT a.*,d.decision,d.note AS decision_note,
        d.decided_by,d.created_at AS decided_at FROM invoice_adjustments_v69 a
        LEFT JOIN invoice_adjustment_decisions_v69 d ON d.adjustment_id=a.id AND d.org_id=a.org_id
        WHERE a.invoice_id=? AND a.org_id=? ORDER BY a.created_at,a.rowid''',(invoice_id,org))]


def settlement(c,invoice,items,money):
    """Return an approved-only current internal balance; never change source invoice."""
    rows=adjustments(c,invoice['id'],invoice['org_id'])
    approved=[x for x in rows if x['decision']=='approved']
    item_map={x['id']:x for x in items}
    returned={}
    returns=discount=freight=0
    for a in approved:
        if a['kind']=='return':
            item=item_map.get(a['item_id'])
            if item is None:
                raise ValueError('approved return has missing invoice item')
            returned[a['item_id']]=returned.get(a['item_id'],0)+a['quantity']
            if returned[a['item_id']]>item['quantity']:
                raise ValueError('approved return exceeds invoiced quantity')
            returns+=a['quantity']*item['unit_price']
        elif a['kind']=='discount':discount+=a['amount']
        elif a['kind']=='freight':freight+=a['amount']
    base=money(items,invoice['vat_mode'])
    subtotal=base['subtotal']-returns-discount+freight
    if subtotal<0:raise ValueError('adjustments make invoice subtotal negative')
    vat=(subtotal+5)//10 if invoice['vat_mode']=='taxable' else 0
    total=subtotal+vat
    paid=c.execute('SELECT COALESCE(SUM(amount),0) FROM payments WHERE invoice_id=? AND org_id=? AND reversed_at IS NULL',
                   (invoice['id'],invoice['org_id'])).fetchone()[0]
    return {'original':base,'returns_subtotal':returns,'discount_subtotal':discount,
            'freight_subtotal':freight,'adjusted_subtotal':subtotal,'adjusted_vat':vat,
            'adjusted_total':total,'paid':paid,'balance':total-paid,
            'approved_adjustments':len(approved),'pending_adjustments':sum(x['decision'] is None for x in rows),
            'unsupported_tax_treatment':'single_invoice_vat_mode_only',
            'statutory_credit_note_issued':False,'accounting_posted':False}


def state_digest(snapshot):
    # Bind approval to pending adjustment and already approved settlement state.
    return hashlib.sha256(json.dumps(snapshot,ensure_ascii=False,sort_keys=True,
        separators=(',',':')).encode('utf8')).hexdigest()


def register_routes(app,*,conn,transaction,current_user,get_row,retrieve_items,money,ident,now,audit,fail,need_admin):
    def view(c,invoice_id,org):
        invoice=get_row(c,'invoices',invoice_id,org)
        items=retrieve_items(c,'invoice',invoice_id)
        lines=adjustments(c,invoice_id,org)
        base=settlement(c,invoice,items,money)
        payload={'invoice_id':invoice_id,'items':[(x['id'],x['name'],x['quantity'],x['unit_price']) for x in items],
                 'rows':[(x['id'],x['kind'],x['item_id'],x['quantity'],x['amount'],x['decision']) for x in lines],
                 'paid':base['paid'],'total':base['adjusted_total'],'vat_mode':invoice['vat_mode']}
        return invoice,items,lines,base,state_digest(payload)

    @app.get('/api/invoices/{invoice_id}/adjustments')
    def list_adjustments(invoice_id:str,user=Depends(current_user)):
        with conn() as c:
            _,_,lines,summary,digest=view(c,invoice_id,user['org_id'])
            return {'adjustments':lines,'settlement':summary,'expected_digest':digest,
                    'note':'관리자 승인 이후에만 내부 미수금에 반영; 공식 수정세금계산서·환불·재고수불은 별도'}

    @app.post('/api/invoices/{invoice_id}/adjustments',status_code=201)
    def propose(invoice_id:str,body:Proposal,user=Depends(current_user)):
        with transaction() as c:
            invoice,items,lines,_,_=view(c,invoice_id,user['org_id'])
            for line in lines:
                if line['request_key']==body.request_key:
                    fields=(line['kind'],line['item_id'],line['quantity'],line['amount'],line['reason'])
                    req=(body.kind,body.item_id,body.quantity,body.amount,body.reason)
                    if fields!=req:fail('요청 ID가 이미 다른 내용으로 사용됐습니다',409)
                    return {'id':line['id'],'reused':True,'status':line['decision'] or 'pending'}
            if sum(x['decision'] is None for x in lines)>=20:
                fail('검토 대기 조정은 청구서당 20건으로 제한됩니다',409)
            if len(lines)>=200:fail('청구서당 조정 요청 한도에 도달했습니다',409)
            if body.kind=='return':
                item=next((x for x in items if x['id']==body.item_id),None)
                if not item:fail('청구서에 없는 품목은 반품할 수 없습니다',422)
                if body.quantity>item['quantity']:fail('반품 수량이 원청구 수량을 초과합니다',422)
            key=ident()
            c.execute('''INSERT INTO invoice_adjustments_v69
                (id,org_id,invoice_id,request_key,kind,item_id,quantity,amount,reason,created_by,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
                (key,user['org_id'],invoice_id,body.request_key,body.kind,body.item_id,
                 body.quantity,body.amount,body.reason,user['id'],now()))
            audit(c,user,'invoice_adjustment',key,'propose',{'invoice_id':invoice_id,'kind':body.kind})
            return {'id':key,'reused':False,'status':'pending','invoice_unchanged':True}

    @app.post('/api/invoices/{invoice_id}/adjustments/{adjustment_id}/decision')
    def decide(invoice_id:str,adjustment_id:str,body:Decision,user=Depends(current_user)):
        need_admin(user)
        with transaction() as c:
            invoice,items,lines,current,digest=view(c,invoice_id,user['org_id'])
            row=next((x for x in lines if x['id']==adjustment_id),None)
            if not row:fail('조정 요청을 찾을 수 없습니다',404)
            if row['decision'] is not None:fail('이미 승인 또는 반려된 조정 요청입니다',409)
            if digest!=body.expected_digest:fail('청구서·조정·입금 정보가 변경됐습니다. 다시 조회하세요',409)
            if body.approve:
                approved=[x for x in lines if x['decision']=='approved']
                if row['kind']=='return':
                    item=next(x for x in items if x['id']==row['item_id'])
                    previous=sum(x['quantity'] for x in approved if x['kind']=='return' and x['item_id']==row['item_id'])
                    if previous+row['quantity']>item['quantity']:
                        fail('누적 반품 수량이 원청구 수량을 초과합니다',409)
                    delta=-row['quantity']*item['unit_price']
                elif row['kind']=='discount':delta=-row['amount']
                else:delta=row['amount']
                next_subtotal=current['adjusted_subtotal']+delta
                if next_subtotal<0:fail('할인·반품으로 공급가액이 음수가 됩니다',409)
                next_total=next_subtotal+((next_subtotal+5)//10 if invoice['vat_mode']=='taxable' else 0)
                if next_total<current['paid']:
                    fail('확정 입금액보다 청구 총액이 작아집니다. 환불 검토가 필요합니다',409)
                # A rejected adjustment never affects the invoice.
            decision='approved' if body.approve else 'rejected'
            c.execute('''INSERT INTO invoice_adjustment_decisions_v69
                (id,org_id,adjustment_id,decision,decided_by,note,created_at)
                VALUES(?,?,?,?,?,?,?)''',
                (ident(),user['org_id'],adjustment_id,decision,user['id'],body.note,now()))
            audit(c,user,'invoice_adjustment',adjustment_id,decision,{'invoice_id':invoice_id})
            _,_,_,updated,_=view(c,invoice_id,user['org_id'])
            return {'id':adjustment_id,'decision':decision,'settlement':updated,
                    'statutory_credit_note_issued':False,'inventory_changed':False}
