"""Strict labelled text PDF and restricted XLSX observation adapters.
No OCR or inferred values; candidates are not posting authority.
XLSX parser must be the existing strict app.erp_migration_xlsx.parse_xlsx.
"""
import io, re, hashlib
from datetime import date
from review_gates import Blocked, need, digest
FIELDS={'document_kind','counterparty_id','document_date','reference_number','subtotal','vat','gross_amount'}
KINDS={'quote','purchase_order','delivery_statement','invoice','transaction_statement'}
MAX_BYTES=1024*1024

def source(raw,registered):
    need(type(raw) is bytes and 0<len(raw)<=MAX_BYTES and digest(registered),'DOC_SOURCE')
    need(hashlib.sha256(raw).hexdigest()==registered,'DOC_SOURCE_CHANGED')

def observation(field,value,page):
    need(field in FIELDS and type(value) is str and len(value)<=128,'DOC_FIELD')
    if field in ('subtotal','vat','gross_amount'):
        need(re.fullmatch(r'0|[1-9][0-9]{0,12}',value) is not None,'DOC_AMOUNT_FORMAT')
        value=int(value);need(value<=10**12,'DOC_AMOUNT_LIMIT')
    elif field=='document_kind':need(value in KINDS,'DOC_KIND')
    elif field=='document_date':
        need(re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}',value) is not None,'DOC_DATE')
        try:date.fromisoformat(value)
        except ValueError:raise Blocked('DOC_DATE') from None
    else:need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',value) is not None,'DOC_ID')
    return {'field':field,'value':value,'page':page}

def pdf_observations(raw,registered):
    import pdfplumber
    source(raw,registered);need(raw.startswith(b'%PDF-'),'DOC_FORMAT')
    result=[]; chars=0
    try:
        with pdfplumber.open(io.BytesIO(raw)) as pdf:
            need(1<=len(pdf.pages)<=20,'DOC_PAGE_LIMIT')
            for i,page in enumerate(pdf.pages,1):
                text=page.extract_text() or ''; chars+=len(text)
                need(chars<=64000,'DOC_TEXT_LIMIT')
                need(bool(text.strip()),'DOC_SCAN_OR_EMPTY_PAGE')
                for line in text.splitlines():
                    if not line.strip():continue
                    m=re.fullmatch(r'([a-z_]+): ([^\r\n]+)',line)
                    need(m is not None and m[1] in FIELDS,'DOC_UNSUPPORTED_LAYOUT')
                    result.append(observation(m[1],m[2],i))
                    need(len(result)<=128,'DOC_OBSERVATION_COUNT')
    except Blocked:raise
    except Exception:raise Blocked('DOC_PDF_PARSE') from None
    need(bool(result),'DOC_OBSERVATION_COUNT');return result

def xlsx_observations(raw,registered,*,strict_parser):
    source(raw,registered)
    try:header,rows=strict_parser(raw)
    except Exception:raise Blocked('DOC_XLSX_PARSE') from None
    need(header==('field','value') and type(rows) is tuple and 1<=len(rows)<=128,'DOC_XLSX_LAYOUT')
    need(all(type(r) is tuple and len(r)==2 and all(type(v) is str for v in r) for r in rows),'DOC_XLSX_LAYOUT')
    return [observation(f,v,1) for f,v in rows]

def review_candidates(*,tenant,raw,registered,format,review_document,strict_parser=None):
    if format=='pdf': obs=pdf_observations(raw,registered)
    elif format=='xlsx':obs=xlsx_observations(raw,registered,strict_parser=strict_parser)
    else:raise Blocked('DOC_FORMAT')
    return review_document(tenant=tenant,source_bytes=raw,registered_sha256=registered,observations=obs)
