"""V16.1 balance preview negative contracts, intentionally no financial mutation."""
from copy import deepcopy

import pytest
from fastapi import HTTPException

from app.pg_invoice_balance_v161 import _preview

INV="7"*32
ORDER="c"*32
ORG="a"*32
CUSTOMER="0"*32
ITEM="3"*32


class FinCursor:
    def __init__(self):
        self.invoice=(INV,ORDER,"open","taxable",CUSTOMER)
        self.order=(ORDER,CUSTOMER,"taxable")
        self.items=[("Synthetic line A",2,3500,0,ITEM)]
        self.source=("Synthetic line A",2,3500,0)
        self.payments=[("5"*32,3000,None),("9"*32,900,"revoked")]
        self.rows=None
        self.sql=[]
    def execute(self,statement,params):
        self.sql.append((statement,params))
        if "FROM jw_dev.invoices" in statement:
            self.rows=[self.invoice] if self.invoice else []
        elif "FROM jw_dev.orders" in statement:
            self.rows=[self.order] if self.order else []
        elif "FROM jw_dev.invoice_items" in statement:
            self.rows=self.items
        elif "FROM jw_dev.order_items" in statement:
            self.rows=[self.source] if self.source else []
        elif "FROM jw_dev.payments" in statement:
            self.rows=self.payments
        else:
            raise AssertionError("Unexpected SQL query "+statement)
        if "FROM jw_dev.invoices" in statement or "FROM jw_dev.orders" in statement:
            assert params[1]==ORG
    def fetchone(self):
        return self.rows[0] if self.rows else None
    def fetchall(self):
        return list(self.rows)


def test_taxable_reversed_balance_is_read_only():
    c=FinCursor()
    result=_preview(c,INV,ORG)
    assert (result["gross_krw"],result["recorded_active_payments_krw"],
            result["unpaid_balance_krw"])==(7700,3000,4700)
    assert result["reversed_record_count"]==1
    assert result["source_item_links_verified"] is True
    assert all(result[k] is False for k in
               ("bank_reconciliation_verified","delivery_physically_verified",
                "payment_posted_by_this_api","invoice_posted_by_this_api"))
    assert all(not any(word in query.upper() for word in
                       ("INSERT INTO", "UPDATE ", "DELETE FROM", "DROP TABLE"))
               for query,_ in c.sql)


@pytest.mark.parametrize("target,value",[
    ("invoice",None),
    ("order",None),
    ("order",(ORDER,"8"*32,"taxable")),
    ("order",(ORDER,CUSTOMER,"exempt")),
    ("invoice",(INV,ORDER,"open","invalid",CUSTOMER)),
    ("items",[]),
    ("items",[("Widget",0,3500,0,ITEM)]),
    ("items",[("Widget",2,-1,0,ITEM)]),
    ("items",[("Widget",2,3500,3,ITEM)]),
    ("source",None),
    ("source",("Synthetic line A",3,3500,0)),
    ("payments",[("5"*32,7800,None)]),
    ("payments",[("5"*32,-1,None)]),
])
def test_invalid_finance_inputs_fail_closed(target,value):
    c=FinCursor()
    setattr(c,target,value)
    with pytest.raises(HTTPException) as exc:
        _preview(c,INV,ORG)
    assert exc.value.status_code in (404,409)


def test_exempt_payment_exactly_settled_not_bank_reconciled():
    c=FinCursor()
    c.invoice=(INV,ORDER,"open","exempt",CUSTOMER)
    c.order=(ORDER,CUSTOMER,"exempt")
    c.payments=[("5"*32,7000,None)]
    result=_preview(c,INV,ORG)
    assert result["vat_krw"]==0
    assert result["unpaid_balance_krw"]==0
    assert result["bank_reconciliation_verified"] is False


def test_unlinked_manual_invoice_item_does_not_claim_source_verified():
    c=FinCursor()
    c.items=[("manual entry",2,3500,0,None)]
    assert _preview(c,INV,ORG)["source_item_links_verified"] is False


def test_hard_cap_on_recorded_payments():
    c=FinCursor()
    c.payments=[("5"*32,1,None)]*101
    with pytest.raises(HTTPException) as exc:
        _preview(c,INV,ORG)
    assert exc.value.status_code==409


def test_hard_cap_on_invoice_line_items():
    c=FinCursor()
    c.items=[("Synthetic line A",2,3500,i,None) for i in range(41)]
    with pytest.raises(HTTPException) as exc:
        _preview(c,INV,ORG)
    assert exc.value.status_code==409
