"""Isolated, tenant-scoped optimistic concurrency for customer edits.

Does not change app.main or protected SQLite schema. All updates are explicit,
recheck the original five fields under BEGIN IMMEDIATE, and audit only field names.
"""
import re
import sqlite3

from fastapi import Depends
from pydantic import BaseModel, ConfigDict

from . import main as core


_FIELDS = ('name', 'business_number', 'contact_name', 'email', 'phone')


class CustomerRevision(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected: core.CustomerBody
    updated: core.CustomerBody


def register_routes(app):
    @app.post('/api/review/customers/{customer_id}/update')
    def update_customer_review(customer_id: str, body: CustomerRevision,
                               user=Depends(core.current_user)):
        if not re.fullmatch(r'[a-f0-9]{32}',customer_id):
            core.fail('거래처를 찾을 수 없습니다',404)
        before_expected=body.expected.model_dump()
        requested=body.updated.model_dump()
        with core.transaction() as db:
            before=core.get_row(db,'customers',customer_id,user['org_id'])
            if any(before[key] != before_expected[key] for key in _FIELDS):
                core.fail('다른 창에서 거래처가 변경됐습니다. 다시 조회하세요',409)
            changed=[key for key in _FIELDS if before[key]!=requested[key]]
            if not changed:
                return before
            try:
                count=db.execute('''UPDATE customers SET name=?,business_number=?,
                    contact_name=?,email=?,phone=?
                    WHERE id=? AND org_id=?''',
                    tuple(requested[key] for key in _FIELDS)+
                    (customer_id,user['org_id'])).rowcount
            except sqlite3.IntegrityError:
                core.fail('같은 이름의 거래처가 이미 등록되어 있습니다',409)
            if count!=1:
                core.fail('거래처를 찾을 수 없습니다',404)
            core.audit(db,user,'customer',customer_id,'edit',{
                'changed_fields':changed, 'privacy':'contact values omitted',
                'review_cas':True})
            return core.get_row(db,'customers',customer_id,user['org_id'])
