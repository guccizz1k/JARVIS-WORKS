"""Label-anchored Korean/English header extraction; no inferred or corrected digits.
Text candidates only; missing/ambiguous fields remain human review.
"""
import re
from datetime import date
from review_gates import Blocked,need

LABELS={
 '문서종류':'document_kind','문서 종류':'document_kind','document_kind':'document_kind',
 '거래처코드':'counterparty_id','거래처 코드':'counterparty_id','counterparty_id':'counterparty_id',
 '작성일':'document_date','문서일자':'document_date','document_date':'document_date',
 '문서번호':'reference_number','문서 번호':'reference_number','reference_number':'reference_number',
 '공급가액':'subtotal','subtotal':'subtotal','부가세':'vat','부가가치세':'vat','vat':'vat',
 '합계금액':'gross_amount','합계 금액':'gross_amount','총액':'gross_amount','gross_amount':'gross_amount'}
KINDS={'견적서':'quote','발주서':'purchase_order','납품서':'delivery_statement','청구서':'invoice','거래명세서':'transaction_statement',**{x:x for x in ('quote','purchase_order','delivery_statement','invoice','transaction_statement')}}
AMOUNTS={'subtotal','vat','gross_amount'}

def value(field,s):
    s=s.strip()
    if field in AMOUNTS:
        s=re.sub(r'\s*원$','',s)
        if re.fullmatch(r'(?:0|[1-9][0-9]{0,12}|[1-9][0-9]{0,2}(?:,[0-9]{3}){1,4})',s):
            n=int(s.replace(',',''));return n if n<=10**12 else None
    elif field=='document_kind':return KINDS.get(s)
    elif field=='document_date':
        m=re.fullmatch(r'(20[0-9]{2})[./-]([0-9]{2})[./-]([0-9]{2})',s)
        if m and s[4]==s[7]:
            try:return date(*map(int,m.groups())).isoformat()
            except ValueError:return None
    elif re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',s):return s
    return None

def observations(pages,*,allow_empty=False):
    need(type(pages) is list and 1<=len(pages)<=20,'OCR_PAGE_LIMIT')
    need(all(type(t) is str for t in pages) and sum(map(len,pages))<=64000,'OCR_TEXT_LIMIT')
    out=[]
    # Delimiters mandatory; do not accidentally consume line item numbers or unrelated totals.
    for i,text in enumerate(pages,1):
        for line in text.splitlines():
            m=re.fullmatch(r'\s*([^:：]{1,32})\s*[:：]\s*(.*?)\s*',line)
            if not m:continue
            field=LABELS.get(m[1].strip())
            if field is None:continue
            out.append({'field':field,'value':value(field,m[2]),'page':i})
            need(len(out)<=128,'OCR_OBSERVATION_LIMIT')
    need(bool(out) or allow_empty,'OCR_NO_LABELLED_FIELDS')
    return out
