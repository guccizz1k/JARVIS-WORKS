"""V22.3 isolated owner-review draft quotation edit with atomic CAS.

Preserves app.main, original business schema, approved UI and ledger. Edits
only authenticated tenant-owned DRAFT quotations using the protected QuoteBody
validation and its existing immutable downstream transition rules.
"""
import hashlib
import json
import re

from fastapi import Depends
from pydantic import BaseModel, ConfigDict, Field

from . import main as core

ITEM_FIELDS=('id','name','quantity','unit_price','position')
QUOTE_FIELDS=('id','org_id','customer_id','customer_name_snapshot','doc_no',
              'title','status','vat_mode','updated_at')


class QuoteRevision(BaseModel):
    model_config=ConfigDict(extra='forbid')
    expected_sha256: str = Field(pattern=r'^[a-f0-9]{64}$',min_length=64,max_length=64)
    updated: core.QuoteBody


def _snapshot(db,quote_id,org_id):
    quote=core.get_row(db,'quotes',quote_id,org_id)
    if quote['status']!='draft':
        core.fail('초안 견적서만 수정할 수 있습니다',409)
    doc=core.detail_doc(db,'quote',quote)
    rows=[{key:item[key] for key in ITEM_FIELDS} for item in doc['items']]
    public={key:doc[key] for key in QUOTE_FIELDS}
    public['items']=rows
    public['money']=doc['money']
    canonical={key:public[key] for key in QUOTE_FIELDS}
    canonical['items']=rows
    digest=hashlib.sha256(json.dumps(canonical,sort_keys=True,
                ensure_ascii=False,separators=(',',':')).encode('utf-8')).hexdigest()
    return public,digest,doc


def _input_equal(snapshot,body):
    return (snapshot['customer_id']==body.customer_id
            and snapshot['title']==body.title
            and snapshot['vat_mode']==body.vat_mode
            and len(snapshot['items'])==len(body.items)
            and all(snapshot['items'][i]['name']==v.name
              and snapshot['items'][i]['quantity']==v.quantity
              and snapshot['items'][i]['unit_price']==v.unit_price
              for i,v in enumerate(body.items)))


def register_routes(app):
    @app.get('/api/review/quotes/{quote_id}/edit-context')
    def review_quote_context(quote_id:str,user=Depends(core.current_user)):
        if not re.fullmatch(r'[a-f0-9]{32}',quote_id):
            core.fail('견적서를 찾을 수 없습니다',404)
        with core.conn() as db:
            snapshot,digest,_=_snapshot(db,quote_id,user['org_id'])
            return {'quote':snapshot,'fingerprint':digest}

    @app.post('/api/review/quotes/{quote_id}/update')
    def review_quote_update(quote_id:str,body:QuoteRevision,
                            user=Depends(core.current_user)):
        if not re.fullmatch(r'[a-f0-9]{32}',quote_id):
            core.fail('견적서를 찾을 수 없습니다',404)
        with core.transaction() as db:
            snapshot,digest,before=_snapshot(db,quote_id,user['org_id'])
            if body.expected_sha256 != digest:
                core.fail('견적서가 다른 창에서 변경됐습니다. 다시 조회하세요',409)
            core.customer_exists(db,user['org_id'],body.updated.customer_id)
            if _input_equal(snapshot,body.updated):
                return {'quote':snapshot,'fingerprint':digest,'changed':False}
            customer=core.get_row(db,'customers',body.updated.customer_id,user['org_id'])
            updated_at=core.now()
            count=db.execute('''UPDATE quotes SET customer_id=?,
                    customer_name_snapshot=?,title=?,vat_mode=?,updated_at=?
                    WHERE id=? AND org_id=? AND status='draft' ''',
                (body.updated.customer_id,customer['name'],body.updated.title,
                 body.updated.vat_mode,updated_at,quote_id,user['org_id'])).rowcount
            if count!=1:
                core.fail('초안 견적서만 수정할 수 있습니다',409)
            db.execute('DELETE FROM quote_items WHERE quote_id=?',(quote_id,))
            for position,item in enumerate(body.updated.items):
                db.execute('INSERT INTO quote_items VALUES(?,?,?,?,?,?)',
                    (core.ident(),quote_id,item.name,item.quantity,item.unit_price,position))
            new,digest_after,after=_snapshot(db,quote_id,user['org_id'])
            core.audit(db,user,'quote',quote_id,'edit',{
                'before':{'title':before['title'],'customer':before['customer_name_snapshot'],
                          'items':before['items'],'money':before['money']},
                'after':{'title':after['title'],'customer':after['customer_name_snapshot'],
                         'items':after['items'],'money':after['money']},
                'review_cas':True})
            return {'quote':new,'fingerprint':digest_after,'changed':True}
