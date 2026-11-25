"""Offline evidence review binding, not an OCR engine or posting authority."""
import hashlib
import hmac
import json
import re
from datetime import date

HEX=re.compile(r"[0-9a-f]{64}")
ID=re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
FIELDS=frozenset(("document_kind","counterparty_id","document_date","reference_number","subtotal","vat","gross_amount"))
KINDS=frozenset(("quote","purchase_order","delivery_statement","invoice","transaction_statement"))
MAX_BYTES=10*1024*1024

class ReviewBlocked(ValueError):pass

def require(ok,reason):
    if not ok:raise ReviewBlocked(reason)

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(",",":")).encode()).hexdigest()

def review_document(*,tenant,source_bytes,registered_sha256,observations):
    """Caller must resolve tenant, source bytes and registered hash server-side.
    Observations are untrusted OCR/model candidates, never executable commands.
    No input strings or raw document content returned.
    """
    require(type(tenant) is str and ID.fullmatch(tenant),"DOC_SCOPE")
    require(type(source_bytes) is bytes and 0<len(source_bytes)<=MAX_BYTES,"DOC_SIZE")
    require(type(registered_sha256) is str and HEX.fullmatch(registered_sha256),"DOC_HASH")
    actual=hashlib.sha256(source_bytes).hexdigest()
    require(hmac.compare_digest(actual,registered_sha256),"DOC_SOURCE_CHANGED")
    require(type(observations) in (list,tuple) and 1<=len(observations)<=128,"DOC_OBSERVATION_COUNT")
    values={};positions={};invalid=set();issues=set()
    for entry in observations:
        require(type(entry) is dict and set(entry)=={"field","value","page"},"DOC_OBSERVATION_SHAPE")
        field,value,page=entry["field"],entry["value"],entry["page"]
        require(type(field) is str and field in FIELDS,"DOC_UNKNOWN_FIELD")
        require(type(page) is int and 1<=page<=1000,"DOC_PAGE")
        if field in ("subtotal","vat","gross_amount"):
            valid=type(value) is int and 0<=value<=10**12
        elif field=="document_kind":
            valid=type(value) is str and value in KINDS
        elif field=="document_date":
            valid=type(value) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}",value) is not None
            if valid:
                try:date.fromisoformat(value)
                except ValueError:valid=False
        else:
            valid=type(value) is str and ID.fullmatch(value) is not None
        if not valid:
            # Invalid observations also affect the proof; never echo their raw values.
            require(value is None or type(value) in (str,int,bool), "DOC_VALUE_TYPE")
            require(type(value) is not str or len(value)<=1024,"DOC_VALUE_LIMIT")
            require(type(value) is not int or abs(value)<=10**15,"DOC_VALUE_LIMIT")
            invalid.add((field,page,digest(value)))
            issues.add("INVALID_"+field.upper());continue
        values.setdefault(field,set()).add(value)
        positions.setdefault(field,set()).add((page,value))
    for field in FIELDS:
        if not values.get(field):issues.add("MISSING_"+field.upper())
        elif len(values[field])!=1:issues.add("CONFLICT_"+field.upper())
    if all(len(values.get(k,()))==1 for k in ("subtotal","vat","gross_amount")):
        a,b,c=(next(iter(values[k])) for k in ("subtotal","vat","gross_amount"))
        if a+b!=c or c<=0:issues.add("AMOUNT_MISMATCH")
    proof={"version":1,"tenant":tenant,"source_sha256":actual,
           "candidates":{k:sorted(v) for k,v in values.items()},
           "page_candidates":{k:sorted(v) for k,v in positions.items()},"invalid_candidates":sorted(invalid),"issues":sorted(issues)}
    return {"source_sha256":actual,"review_sha256":digest(proof),
            "status":"MANUAL_CORRECTION_REQUIRED" if issues else "ORIGINAL_REVIEW_REQUIRED",
            "issues":sorted(issues),"field_count":sum(len(v)==1 for v in values.values()),
            "requires_human_review":True,"posting_authorized":False,"confidence":None}
