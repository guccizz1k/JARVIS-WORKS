"""V18.7 hostile bank response contract and non-authority proof."""
from copy import deepcopy

import pytest

from scripts.review.kftc_bank_page_v187 import (
    BankPageRejected, parse_untrusted_bank_page,
)

ACCOUNT="123456789012345678901234"


def good():
    return {
        "rsp_code":"A0000","bank_rsp_code":"000",
        "fintech_use_num":ACCOUNT,
        "api_tran_id":"kftc-example-transaction-001",
        "bank_tran_id":"F123456789U4BC34239Z",
        "page_record_cnt":"1",
        "next_page_yn":"N",
        "res_list":[{"tran_date":"20261030","tran_time":"101500",
                     "inout_type":"입금","tran_amt":"450000"}],
    }


OUTER=(
    ("rsp_code","A9999"),
    ("rsp_code",None),
    ("bank_rsp_code","901"),
    ("fintech_use_num","0"*24),
    ("fintech_use_num","123"),
    ("api_tran_id",None),
    ("api_tran_id","A"*41),
    ("bank_tran_id",None),
    ("bank_tran_id","B"*21),
    ("page_record_cnt","0"),
    ("page_record_cnt","26"),
    ("page_record_cnt",None),
    ("page_record_cnt",1),
    ("next_page_yn","MAYBE"),
    ("next_page_yn",True),
    ("res_list",None),
    ("res_list",{"not":"array"}),
    ("res_list",[good()["res_list"][0]]*26),
)
ENTRY=(
    ("tran_date","20260230"),
    ("tran_date","20261301"),
    ("tran_date","2026-10-30"),
    ("tran_date","2026X031"),
    ("tran_time","240000"),
    ("tran_time","11X500"),
    ("tran_time","123"),
    ("inout_type","credit"),
    ("inout_type","이체"),
    ("inout_type",None),
    ("tran_amt","0"),
    ("tran_amt","-100"),
    ("tran_amt","1.5"),
    ("tran_amt",100),
    ("tran_amt",None),
    ("tran_amt","9"*13),
)

@pytest.mark.parametrize(("field","value"),OUTER,
    ids=[f"outer-fail-{i+1:02}" for i in range(len(OUTER))])
def test_bad_provider_message_never_parses(field,value):
    d=good()
    d[field]=value
    with pytest.raises(BankPageRejected):
        parse_untrusted_bank_page(d,ACCOUNT)

@pytest.mark.parametrize(("field","value"),ENTRY,
    ids=[f"entry-fail-{i+1:02}" for i in range(len(ENTRY))])
def test_bad_transaction_never_parses(field,value):
    d=good()
    d["res_list"][0][field]=value
    with pytest.raises(BankPageRejected):
        parse_untrusted_bank_page(d,ACCOUNT)


def test_valid_page_only_parses_not_reconciles():
    page=parse_untrusted_bank_page(good(),ACCOUNT)
    assert len(page.entries)==1 and page.entries[0].amount_krw==450000
    assert page.entries[0].direction=="입금"
    assert page.has_more is False and page.cursor==""
    assert page.provider_transport_verified is False
    assert page.corporate_account_authorized is False
    assert page.bank_reconciliation_verified is False
    assert page.financial_settlement_verified is False


def test_payment_amount_duplicate_never_silently_dedupes():
    data=good()
    data["res_list"]*=2
    data["page_record_cnt"]="2"
    page=parse_untrusted_bank_page(data,ACCOUNT)
    assert len(page.entries)==2
    assert page.entries[0]==page.entries[1]
    assert not page.bank_reconciliation_verified


def test_pagination_requires_trace_and_cannot_assume_complete_history():
    data=good()
    data["next_page_yn"]="Y"
    with pytest.raises(BankPageRejected):
        parse_untrusted_bank_page(data,ACCOUNT)
    data["befor_inquiry_trace_info"]="trace123456"
    page=parse_untrusted_bank_page(data,ACCOUNT)
    assert page.has_more and page.cursor=="trace123456"
    assert not page.financial_settlement_verified


def test_zero_transactions_and_untrusted_input_are_safe():
    data=good()
    data["res_list"]=[]
    data["page_record_cnt"]="0"
    assert parse_untrusted_bank_page(data,ACCOUNT).entries==()
    for bad in (None,[],"{}",1,False):
        with pytest.raises(BankPageRejected):
            parse_untrusted_bank_page(bad,ACCOUNT)
    for account in (None,"",0,"x"*24,"0"*23):
        with pytest.raises(BankPageRejected):
            parse_untrusted_bank_page(good(),account)
