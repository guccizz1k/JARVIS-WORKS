"""Isolated V22.3 order change and administrator acknowledgement.

Uses protected OrderChange validation and the original order-diff semantics.
All mutations are compare-and-swap within the existing IMMEDIATE transaction;
main.py, the order schema, ledgers, and approved original UI remain unchanged.
"""
import hashlib
import json
import re

from fastapi import Depends
from pydantic import BaseModel, ConfigDict, Field

from . import main as core

ORDER_FIELDS=('id','org_id','customer_id','quote_id','customer_name_snapshot',
              'doc_no','title','status','review_state','vat_mode','due_date',
              'created_at','updated_at')
ITEM_FIELDS=('id','source_quote_item_id','name','quantity','unit_price','position')
QUOTE_ITEM_FIELDS=('id','name','quantity','unit_price','position')


class OrderRevision(BaseModel):
    model_config=ConfigDict(extra='forbid')
    fingerprint:str=Field(pattern=r'^[a-f0-9]{64}$',min_length=64,max_length=64)
    updated:core.OrderChange


class OrderAcknowledgement(BaseModel):
    model_config=ConfigDict(extra='forbid')
    fingerprint:str=Field(pattern=r'^[a-f0-9]{64}$',min_length=64,max_length=64)
    confirm:bool=Field()


def _context(db,order_id,org_id):
    row=core.get_row(db,'orders',order_id,org_id)
    if row['status'] not in ('received','processing'):
        core.fail('진행 중인 수주만 변경하거나 확인할 수 있습니다',409)
    order=core.detail_doc(db,'order',row)
    items=[{key:item[key] for key in ITEM_FIELDS} for item in order['items']]
    source=[{key:item[key] for key in QUOTE_ITEM_FIELDS}
            for item in core.retrieve_items(db,'quote',row['quote_id'])]
    summary={key:order[key] for key in ORDER_FIELDS}
    summary['items']=items
    summary['quote_items']=source
    summary['money']=order['money']
    changes=core.order_diff(db,row)
    summary['differences']=changes
    if len(items)>core.MAX_ITEMS or len(source)>core.MAX_ITEMS:
        core.fail('검토 가능한 품목 수를 초과했습니다',409)
    # Includes immutable source references and all mutable order rows. Opaque
    # source-document metadata is hashed, never returned to client.
    canonical={'order':dict(row),'items':items,'quote_items':source}
    digest=hashlib.sha256(json.dumps(canonical,sort_keys=True,
              ensure_ascii=False,separators=(',',':')).encode('utf-8')).hexdigest()
    return summary,digest


def _same(summary,updated):
    return (summary['due_date']==updated.due_date.isoformat()
            and len(summary['items'])==len(updated.items)
            and all(all((
              existing['source_quote_item_id']==item.source_quote_item_id,
              existing['name']==item.name,
              existing['quantity']==item.quantity,
              existing['unit_price']==item.unit_price))
              for existing,item in zip(summary['items'],updated.items)))


def _response(db,order_id,org_id):
    doc,digest=_context(db,order_id,org_id)
    return {'order':doc,'fingerprint':digest}


def register_routes(app):
    @app.get('/api/review/orders/{order_id}/edit-context')
    def order_edit_context(order_id:str,user=Depends(core.current_user)):
        if not re.fullmatch(r'[a-f0-9]{32}',order_id):
            core.fail('수주를 찾을 수 없습니다',404)
        with core.conn() as db:
            return _response(db,order_id,user['org_id'])

    @app.post('/api/review/orders/{order_id}/update')
    def order_edit(order_id:str,body:OrderRevision,
                   user=Depends(core.current_user)):
        if not re.fullmatch(r'[a-f0-9]{32}',order_id):
            core.fail('수주를 찾을 수 없습니다',404)
        with core.transaction() as db:
            before,digest=_context(db,order_id,user['org_id'])
            if digest!=body.fingerprint:
                core.fail('수주 원본이 변경되었습니다. 다시 조회하세요',409)
            if db.execute('SELECT 1 FROM invoices WHERE order_id=?',
                          (order_id,)).fetchone():
                core.fail('청구서 발행 후 수주 금액은 수정할 수 없습니다',409)
            valid_ids={i['id'] for i in before['quote_items']}
            seen=[]
            for item in body.updated.items:
                if item.source_quote_item_id is not None:
                    if item.source_quote_item_id not in valid_ids:
                        core.fail('원본 견적 품목이 유효하지 않습니다')
                    seen.append(item.source_quote_item_id)
            if len(set(seen))!=len(seen):
                core.fail('원본 견적 품목은 중복 참조할 수 없습니다')
            if _same(before,body.updated):
                return {'order':before,'fingerprint':digest,'changed':False}
            changed=db.execute("""UPDATE orders SET due_date=?,updated_at=?
                WHERE id=? AND org_id=? AND status IN ('received','processing')""",
                (body.updated.due_date.isoformat(),core.now(),order_id,user['org_id'])).rowcount
            if changed!=1:
                core.fail('수주 상태가 변경되었습니다',409)
            db.execute('DELETE FROM order_items WHERE order_id=?',(order_id,))
            for position,item in enumerate(body.updated.items):
                db.execute('INSERT INTO order_items VALUES(?,?,?,?,?,?,?)',
                    (core.ident(),order_id,item.source_quote_item_id,
                     item.name,item.quantity,item.unit_price,position))
            source_order=core.get_row(db,'orders',order_id,user['org_id'])
            requires_review=bool(core.order_diff(db,source_order))
            db.execute('UPDATE orders SET review_state=? WHERE id=? AND org_id=?',
                       ('pending' if requires_review else 'clean',
                        order_id,user['org_id']))
            after,_=_context(db,order_id,user['org_id'])
            core.audit(db,user,'order',order_id,'edit',{
                'reason':body.updated.change_reason,
                'before':{'items':before['items'],'money':before['money'],
                          'due_date':before['due_date']},
                'after':{'items':after['items'],'money':after['money'],
                         'due_date':after['due_date']},
                'requires_review':requires_review,'review_cas':True})
            response=_response(db,order_id,user['org_id'])
            response['changed']=True
            return response

    @app.post('/api/review/orders/{order_id}/acknowledge')
    def order_acknowledge(order_id:str,body:OrderAcknowledgement,
                          user=Depends(core.current_user)):
        core.need_admin(user)
        if not re.fullmatch(r'[a-f0-9]{32}',order_id):
            core.fail('수주를 찾을 수 없습니다',404)
        if body.confirm is not True:
            core.fail('명시적 확인이 필요합니다',422)
        with core.transaction() as db:
            before,digest=_context(db,order_id,user['org_id'])
            if digest!=body.fingerprint:
                core.fail('수주 변경 내역이 달라졌습니다. 다시 조회하세요',409)
            differences=before['differences']
            if before['review_state']!='pending' or not differences:
                core.fail('확인이 필요한 변경 사항이 없습니다',409)
            count=db.execute("""UPDATE orders SET review_state='acknowledged',
                updated_at=? WHERE id=? AND org_id=? AND review_state='pending'""",
                (core.now(),order_id,user['org_id'])).rowcount
            if count!=1:
                core.fail('검토 상태가 달라졌습니다. 다시 조회하세요',409)
            core.audit(db,user,'order',order_id,'acknowledge',{
                'differences':differences,'review_cas':True})
            return _response(db,order_id,user['org_id'])
