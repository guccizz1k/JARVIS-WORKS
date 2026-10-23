"""V7.0 OCR safety/quality regression, all data generated and fictitious."""
from __future__ import annotations
import io
from datetime import date
import pytest
from openpyxl import Workbook
from app.evidence_v64_worker import extract,text_fields,to_date,kind_guess
from app.evidence_quality_v70 import assess_evidence,is_valid_business_number,masked_excerpt


def workbook(entries):
    w=Workbook();s=w.active
    for k,v in entries:s.append([k,v])
    b=io.BytesIO();w.save(b);return b.getvalue()


def valid_business_number(prefix='999999999'):
    d=[int(x) for x in prefix];weights=[1,3,7,1,3,7,1,3,5]
    return prefix+str((10-(sum(a*b for a,b in zip(d,weights))+d[8]*5//10)%10)%10)


def test_business_checksum_valid_and_invalid():
    n=valid_business_number()
    assert is_valid_business_number(n)
    assert is_valid_business_number(n[:3]+'-'+n[3:5]+'-'+n[5:])
    assert not is_valid_business_number(n[:-1]+str((int(n[-1])+1)%10))
    assert not is_valid_business_number('999-99-ABCDE')
    assert not is_valid_business_number('9999999999') if n!='9999999999' else True


def test_business_number_is_validated_but_not_returned_raw():
    n=valid_business_number()
    r=extract('document.xlsx',workbook([('문서종류','영수증'),('거래처','가상기업'),('거래일','2026-10-21'),('총금액','12,000원'),('사업자등록번호',n)]))
    assert r['quality']['business_number_format_valid'] is True
    assert n not in str(r)
    assert '[사업자번호 숨김]' in r['ocr_text_excerpt']
    assert r['fields']['gross_amount']==12000
    assert r['quality']['calibrated_confidence'] is None
    assert r['quality']['needs_manual_review'] is True


def test_conflicting_amount_never_select_last_value():
    raw=workbook([('문서종류','영수증'),('거래처','가상상사'),('거래일','2026-10-21'),('총금액','11,000'),('총합계','110,000')])
    r=extract('duplicate.xlsx',raw)
    assert r['fields']['gross_amount'] is None
    assert r['quality']['field_statuses']['gross_amount']=='conflict'
    assert r['quality']['review_priority']=='manual_entry_required'
    assert any('충돌' in x for x in r['warnings'])


def test_conflicting_doc_kind_never_force_kind_from_keywords():
    raw=workbook([('문서종류','영수증'),('문서구분','매출전표'),('거래처','가상상사'),('거래일','2026-10-21'),('총금액',11000)])
    r=extract('conflict.xlsx',raw)
    assert r['document_kind'] is None
    assert r['quality']['field_statuses']['document_kind']=='conflict'
    assert r['proposed_record_type'] is None


def test_amount_and_invalid_number_are_not_trusted():
    entries=[('문서종류','영수증'),('거래처','가상상사'),('거래일','2026-10-21'),('공급가액',10000),('부가세',1000),('총금액',10010)]
    r=extract('wrong-sum.xlsx',workbook(entries))
    assert r['quality']['arithmetic']=='inconsistent'
    assert any('불일치' in x for x in r['quality']['issues'])
    entries[-1]=('총금액','1O,000')
    r=extract('ocr-confusable.xlsx',workbook(entries))
    assert r['fields']['gross_amount'] is None
    assert r['quality']['field_statuses']['gross_amount']=='invalid'


@pytest.mark.parametrize('string,expected',[
 ('2026-10-21','2026-10-21'), ('2026.10.21','2026-10-21'),
 ('2026년 10월 21일','2026-10-21'), ('2026/2/29',None),
 ('2026-13-01',None), ('2026-10-21 junk',None),
])
def test_date_exact_and_no_guess(string,expected):
    assert to_date(string)==expected


def test_mask_pii_in_preview_excerpt():
    excerpt=masked_excerpt('메일: test@example.com\n휴대전화: 010-2222-3333\n주민번호: 990101-1234567\n사업자번호: 999-99-99999')
    for word in ('test@example.com','010-2222-3333','990101-1234567','999-99-99999'):assert word not in excerpt


def test_bad_business_number_triggers_manual_review():
    data={'document_date':'2026-10-21','counterparty':'가상기업','gross_amount':'1100','business_number':'1234567890'}
    quality=assess_evidence(data,[],'receipt','xlsx')
    assert not quality['business_number_format_valid']
    assert quality['review_priority']=='manual_entry_required'


def test_quality_ignores_missing_optional_business_number():
    q=assess_evidence({'counterparty':'가상기업','document_date':'2026-10-21','gross_amount':'1000'},[],'receipt','xlsx')
    assert q['review_priority']=='review_required'
    assert q['business_number_format_valid'] is None


def test_api_flags_present_and_confirmation_is_not_automatic(api):
    r=api.c.post('/api/evidence/preview',files={'file':('qa.xlsx',workbook([('문서종류','영수증'),('거래처','가상기업'),('거래일','2026-10-21'),('총금액','11,000')]))},headers=api.auth)
    assert r.status_code==201,r.text
    assert r.json()['document']['quality']['needs_manual_review']
    assert r.json()['confirmation_required']
    assert api.get('/evidence/dashboard').json()['total_confirmed']==0
