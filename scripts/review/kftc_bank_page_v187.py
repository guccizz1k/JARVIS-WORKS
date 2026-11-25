"""V18.7 read-only parsing contract for KFTC account transaction-list pages.

Follows the published *individual account inquiry* response contract:
https://developers.kftc.or.kr/dev/openapi/open-banking/transaction

NO bank access, no token issuance, no corporate API assumption, no
settlement authorization or PostgreSQL mutation. An arbitrary JSON object
is NEVER proof that it originated from a licensed banking institution.
The official corporate-account POST interface requires separate review.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Any

class BankPageRejected(ValueError):
    """Fixed non-sensitive parsing rejection."""


@dataclass(frozen=True)
class BankEntry:
    date: str
    time: str
    direction: str
    amount_krw: int


@dataclass(frozen=True)
class ParsedBankPage:
    entries: tuple[BankEntry,...]
    has_more: bool
    cursor: str
    provider_transport_verified: bool=False
    corporate_account_authorized: bool=False
    bank_reconciliation_verified: bool=False
    financial_settlement_verified: bool=False


def _txt(obj: Any, maxlen: int, label: str) -> str:
    if type(obj) is not str or not 1<=len(obj)<=maxlen:
        raise BankPageRejected("INVALID_"+label)
    if any(ord(x)<32 or ord(x)==127 for x in obj):
        raise BankPageRejected("INVALID_"+label)
    return obj


def _date(raw: Any) -> str:
    d=_txt(raw,8,"TRANSACTION_DATE")
    if not re.fullmatch(r"[0-9]{8}",d):
        raise BankPageRejected("INVALID_TRANSACTION_DATE")
    try:datetime.strptime(d,"%Y%m%d")
    except ValueError:raise BankPageRejected("INVALID_TRANSACTION_DATE") from None
    return d


def _time(raw: Any) -> str:
    t=_txt(raw,6,"TRANSACTION_TIME")
    if not re.fullmatch(r"[0-9]{6}",t):
        raise BankPageRejected("INVALID_TRANSACTION_TIME")
    try:datetime.strptime(t,"%H%M%S")
    except ValueError:raise BankPageRejected("INVALID_TRANSACTION_TIME") from None
    return t


def _amount(raw: Any) -> int:
    val=_txt(raw,12,"TRANSACTION_AMOUNT")
    if not re.fullmatch(r"[0-9]{1,12}",val):
        raise BankPageRejected("INVALID_TRANSACTION_AMOUNT")
    n=int(val)
    if n<=0:raise BankPageRejected("INVALID_TRANSACTION_AMOUNT")
    return n


def parse_untrusted_bank_page(payload: Any, expected_fintech_use_num: str) -> ParsedBankPage:
    """Fail closed. This only validates shape, NOT source provenance."""
    if type(payload) is not dict:
        raise BankPageRejected("INVALID_BANK_RESPONSE")
    number=_txt(expected_fintech_use_num,24,"FINTECH_USE_NUM")
    if not re.fullmatch(r"[0-9]{24}",number):
        raise BankPageRejected("INVALID_FINTECH_USE_NUM")
    if payload.get("rsp_code")!="A0000" or payload.get("bank_rsp_code")!="000":
        raise BankPageRejected("BANK_API_OR_PROVIDER_ERROR")
    if payload.get("fintech_use_num")!=number:
        raise BankPageRejected("ACCOUNT_REFERENCE_MISMATCH")
    _txt(payload.get("api_tran_id"),40,"API_TRAN_ID")
    _txt(payload.get("bank_tran_id"),20,"BANK_TRAN_ID")
    rows=payload.get("res_list")
    if type(rows) is not list or len(rows)>25:
        raise BankPageRejected("INVALID_PAGE_SIZE")
    reported=_txt(payload.get("page_record_cnt"),2,"PAGE_RECORD_COUNT")
    if not re.fullmatch(r"(?:0|[1-9][0-9]?)",reported) or int(reported)!=len(rows):
        raise BankPageRejected("PAGE_RECORD_COUNT_MISMATCH")
    if payload.get("next_page_yn") not in ("Y","N"):
        raise BankPageRejected("INVALID_PAGINATION_FLAG")
    more=payload["next_page_yn"]=="Y"
    trace=payload.get("befor_inquiry_trace_info","")
    if more:
        trace=_txt(trace,20,"PAGINATION_TRACE")
        if not re.fullmatch(r"[a-zA-Z0-9]{1,20}",trace):
            raise BankPageRejected("INVALID_PAGINATION_TRACE")
    elif trace not in ("",None) and (
            type(trace) is not str or len(trace)>20):
        raise BankPageRejected("INVALID_PAGINATION_TRACE")
    results=[]
    for row in rows:
        if type(row) is not dict:raise BankPageRejected("INVALID_BANK_ENTRY")
        direction=row.get("inout_type")
        if direction not in ("입금","출금"):
            raise BankPageRejected("INVALID_TRANSACTION_DIRECTION")
        results.append(BankEntry(_date(row.get("tran_date")),
                                 _time(row.get("tran_time")),
                                 direction,_amount(row.get("tran_amt"))))
    # Do NOT deduplicate rows by date/amount: legitimate bank transactions can
    # coincide and the documented per-row record lacks a strong unique ID.
    # Do NOT return merchant/payer/printed content or infer invoice matching.
    return ParsedBankPage(tuple(results),more,trace if more else "")

