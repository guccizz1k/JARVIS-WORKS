"""V7.0 deterministic OCR/document quality checks (advisory only).

No model confidence is fabricated: flags express observed parse/consistency facts,
not probability of correctness. Raw identification data is never written to this
assessment. Evidence confirmation still requires human original-file review.
"""
from __future__ import annotations
import re
from datetime import date

FIELD_NAMES={
    'document_kind':'문서 유형', 'counterparty':'거래처',
    'document_date':'거래일', 'gross_amount':'총금액',
    'subtotal':'공급가액', 'vat':'부가세',
    'reference_number':'문서번호', 'business_number':'사업자등록번호',
    'sku':'품목코드', 'quantity':'수량', 'unit':'단위',
}


def is_valid_business_number(raw: str) -> bool:
    """Korean 10-digit business registration number checksum; NOT registry proof."""
    digits=re.sub(r'[\s-]', '',str(raw))
    if not re.fullmatch(r'[0-9]{10}',digits):return False
    d=[int(x) for x in digits]
    weights=(1,3,7,1,3,7,1,3,5)
    total=sum(d[i]*weights[i] for i in range(9))+(d[8]*5)//10
    return (10-total%10)%10==d[9]


def parse_date(raw: str):
    m=re.fullmatch(r'\s*([0-9]{4})(?:[./-]|년\s*)([0-9]{1,2})(?:[./-]|월\s*)([0-9]{1,2})(?:일)?\s*',str(raw))
    if not m:return None
    try:return date(*(int(x) for x in m.groups())).isoformat()
    except ValueError:return None


def parse_amount(raw: str):
    if raw is None:return None
    text=re.sub(r'[\s,원₩]', '',str(raw))
    if not re.fullmatch(r'[0-9]{1,12}',text):return None
    return int(text)


def masked_excerpt(raw: str) -> str:
    """Best-effort PII masking in a UI excerpt; not a formal DLP guarantee."""
    result=str(raw)[:1600]
    # Korean resident identity numbers, email addresses, mobile and business IDs.
    result=re.sub(r'(?<!\d)[0-9]{6}\s*-\s*[1-8][0-9]{6}(?!\d)', '[주민등록번호 숨김]',result)
    result=re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b','[이메일 숨김]',result)
    result=re.sub(r'(?<!\d)01[016789][\s-]?[0-9]{3,4}[\s-]?[0-9]{4}(?!\d)','[휴대전화 숨김]',result)
    result=re.sub(r'(?<!\d)[0-9]{3}-[0-9]{2}-[0-9]{5}(?!\d)','[사업자번호 숨김]',result)
    result=re.sub(r'((?:사업자번호|사업자등록번호|사업자등록증번호)\s*[:：\t]\s*)([0-9]{10})(?!\d)',r'\1[사업자번호 숨김]',result)
    return result


def assess_evidence(fields:dict, conflicts:list[str], kind:str|None, method:str, raw_text:str='') -> dict:
    # Parse assessment only: the OCR engine does not supply calibrated probability.
    statuses={};issues=[]
    for key,label in FIELD_NAMES.items():
        raw=fields.get(key)
        if key in conflicts:statuses[key]='conflict';issues.append(label+' 값 충돌')
        elif raw is None or str(raw).strip()=='':statuses[key]='missing'
        elif key=='document_date' and parse_date(raw) is None:
            statuses[key]='invalid';issues.append(label+' 형식 또는 실제 날짜 오류')
        elif key in ('gross_amount','subtotal','vat','quantity') and (parse_amount(raw) is None or (key not in ('vat','subtotal') and parse_amount(raw)==0) or (key=='gross_amount' and (parse_amount(raw) or 0)>1_000_000_000)):
            statuses[key]='invalid';issues.append(label+' 숫자 인식 오류')
        elif key=='business_number' and not is_valid_business_number(raw):
            statuses[key]='invalid';issues.append('사업자등록번호 자리수/체크섬 오류 (실제 등록 여부는 검증하지 않음)')
        else:statuses[key]='extracted'
    statuses['document_kind']='conflict' if 'document_kind' in conflicts else ('extracted' if kind else 'missing')
    required=('counterparty','document_date','sku','quantity') if kind=='inventory_sheet' else ('counterparty','document_date','gross_amount')
    for key in required:
        if statuses[key]!='extracted':issues.append(FIELD_NAMES[key]+' 직접 확인 필요')
    if not kind:issues.append('문서 유형 직접 확인 필요')
    a,b,c=(parse_amount(fields.get(k)) for k in ('subtotal','vat','gross_amount'))
    arithmetic='unavailable'
    if a is not None and b is not None and c is not None:
        arithmetic='consistent' if a+b==c else 'inconsistent'
        if arithmetic=='inconsistent':issues.append('공급가액 + 부가세와 총금액 불일치')
    elif any(fields.get(k) not in (None,'') for k in ('subtotal','vat')):
        issues.append('금액 교차 검증에 필요한 값 누락 또는 인식 실패')
    return {
        'field_statuses':statuses,
        'arithmetic':arithmetic,
        'business_number_masked':'[사업자번호 숨김]' if fields.get('business_number') else None,
        'business_number_format_valid':is_valid_business_number(fields['business_number']) if fields.get('business_number') else None,
        'review_priority':'manual_entry_required' if issues else 'review_required',
        'issues':list(dict.fromkeys(issues)),
        'needs_manual_review':True,
        'calibrated_confidence':None,
        'safe_excerpt':masked_excerpt(raw_text),
        'method':method,
    }
