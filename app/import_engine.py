"""Strict, offline, deterministic extraction for a documented business order template.

No OCR and no probabilistic guesses. Unknown or inconsistent documents fail closed.
Original bytes are not persisted; a reviewed, structured preview is persisted separately.
"""
from __future__ import annotations

import io
import re
import zipfile
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

import pdfplumber
from openpyxl import load_workbook

MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_ROWS = 40
MAX_PDF_PAGES = 8
FIELDS = {
    'document_kind': ('문서종류', '문서구분'),
    'company': ('거래처', '수주처', '고객사', '발주처', '회사명', '발주회사', '구매사', '고객업체'),
    'business_number': ('사업자등록번호', '사업자번호'),
    'ordered_at': ('수주일', '발주일', '주문일', '발행일자', '발행일', '발주일자', '주문일자'),
    'quote_date': ('견적일', '견적일자', '견적작성일', '견적발행일', '견적작성일자'),
    'due_date': ('납기일', '납품예정일', '납품일', '납기예정일', '납품기한'),
    'title': ('제목', '발주명', '건명'),
    'vat_mode': ('과세구분', '부가세구분', '세금구분'),
    'subtotal': ('공급가액', '공급가액합계'),
    'vat': ('부가세', '부가가치세'),
    'total': ('총금액', '총합계', '합계금액', '최종합계'),
    'reference_number': ('발주번호', '주문번호', '수주번호', '원본문서번호', '견적번호'),
    'project_name': ('프로젝트명', '프로젝트', '현장명'),
    'delivery_address': ('납품장소', '납품주소', '인도장소'),
    'buyer_contact': ('수주담당자', '발주담당자', '담당자'),
    'payment_terms': ('결제조건', '지급조건'),
    'remarks': ('특기사항', '비고', '요청사항'),
    'currency': ('통화', '화폐'),
    'valid_until': ('견적유효일','견적유효기한','견적만료일','유효기간종료일'),
}
COLUMNS = {
    'name': ('품목', '품목명', '상품명', '제품명', '제품', '상품'),
    'quantity': ('수량', '발주수량', '주문수량', '요청수량'),
    'unit_price': ('단가', '공급단가', '주문단가'),
    'line_total': ('금액', '품목합계', '공급금액', '금액합계'),
}
OPTIONAL_COLUMNS = {
    'sku': ('품목코드', '상품코드', '제품코드'),
    'spec': ('규격', '사양'),
    'unit': ('단위', '수량단위'),
}
OPTIONAL_FIELD_LIMITS = {'reference_number':70,'project_name':120,'delivery_address':200,
                         'buyer_contact':80,'payment_terms':200,'remarks':500,'valid_until':20}


class DocumentError(ValueError):
    pass

def norm(s):
    return re.sub(r'[\s:：()（）\[\]・·_-]+', '', str(s or '')).casefold()

def unique_key(key, dictionary):
    for field, candidates in dictionary.items():
        if norm(key) in {norm(x) for x in candidates}:
            return field
    return None

def number(raw, label, *, allow_zero=False):
    if isinstance(raw, bool) or raw is None: raise DocumentError(f'{label}: 값이 없거나 숫자가 아닙니다')
    if isinstance(raw, float):
        if not raw.is_integer():raise DocumentError(f'{label}: 소수 수량·원화는 지원하지 않습니다')
        raw = int(raw)
    t=str(raw).strip().replace('₩','').replace('원','').strip()
    if ',' in t and not re.fullmatch(r'[0-9]{1,3}(?:,[0-9]{3})+',t):
        raise DocumentError(f'{label}: 자릿수 구분 쉼표가 잘못되었습니다. 예: 1,000')
    t=t.replace(',','')
    if not re.fullmatch(r'[0-9]+',t):raise DocumentError(f'{label}: 0 이상 정수만 허용합니다')
    v=int(t)
    if v<0 or (not allow_zero and v==0):raise DocumentError(f'{label}: 유효한 양수가 필요합니다')
    return v

def to_date(value, label):
    try:
        if isinstance(value, datetime): d=value.date()
        elif isinstance(value, date):d=value
        else:
            value=str(value).strip()
            if not re.fullmatch(r'\d{4}[-./]\d{1,2}[-./]\d{1,2}',value):raise ValueError('invalid format')
            d=date(*map(int,re.split(r'[-./]',value)))
        if not (date(2000,1,1) <= d <= date(2100,12,31)):raise ValueError('out of range')
        return d.isoformat()
    except (ValueError, TypeError) as exc:raise DocumentError(f'{label}: YYYY-MM-DD 형식의 실제 날짜가 필요합니다') from exc

def clean_text(raw, label, max_length):
    if raw is None or not isinstance(raw,(str,int)) or len(str(raw).strip())==0:raise DocumentError(f'{label}: 필수 항목이 없습니다')
    value=str(raw).strip()
    if len(value)>max_length or any(ord(x)<32 for x in value):raise DocumentError(f'{label}: 허용되지 않는 문자 또는 길이입니다')
    return value

def document_type(value):
    kind=norm(value)
    if kind in ('발주서','수주서','주문서'):return 'order'
    if kind in ('견적서','가격견적서'):return 'quote'
    raise DocumentError('지원하지 않는 문서 종류입니다. 견적서·발주서·수주서·주문서만 인식합니다')


def normalize_meta(meta, *, allow_missing=False):
    kind=document_type(meta.get('document_kind'))
    # Never conflate an external quote date with an order acceptance date.
    quote_date_raw=meta.get('quote_date')
    if kind=='quote' and meta.get('ordered_at') is not None:
        if meta.get('_ordered_at_label') not in ('발행일자','발행일') or quote_date_raw is not None:
            raise DocumentError('견적서에 수주일/발주일 또는 서로 다른 날짜 항목이 있습니다. 원본을 확인하세요')
        quote_date_raw=meta['ordered_at']
    if kind=='order' and meta.get('quote_date') is not None:
        raise DocumentError('발주 문서에 견적일이 섞여 있습니다. 문서 종류·날짜를 확인하세요')
    fillable=('company','quote_date') if kind=='quote' else ('company','ordered_at','due_date')
    needed=('document_kind','company','quote_date','vat_mode','subtotal','vat','total') if kind=='quote' else (
        'document_kind','company','ordered_at','due_date','vat_mode','subtotal','vat','total')
    values={**meta,'quote_date':quote_date_raw}
    missing=[x for x in needed if (values.get(x) is None or not str(values.get(x)).strip()) and not (allow_missing and x in fillable)]
    if missing:raise DocumentError('필수 정보 누락: '+', '.join(missing))
    mode=norm(meta['vat_mode'])
    if mode in ('과세','과세10%','10%','taxable'):mode='taxable'
    elif mode in ('면세','영세','0%','exempt'):mode='exempt'
    else:raise DocumentError('과세 구분을 정확히 지정해야 합니다 (과세 또는 면세)')
    out={
      'document_kind':clean_text(meta['document_kind'],'문서종류',20),
      'record_type':kind,
      'company':clean_text(meta['company'],'거래처',120) if str(meta.get('company') or '').strip() else None,
      'business_number':str(meta.get('business_number') or '').strip(),
      'ordered_at':to_date(meta['ordered_at'],'수주일') if kind=='order' and str(meta.get('ordered_at') or '').strip() else None,
      'quote_date':to_date(quote_date_raw,'견적일') if kind=='quote' and str(quote_date_raw or '').strip() else None,
      'due_date':to_date(meta['due_date'],'납기일') if kind=='order' and str(meta.get('due_date') or '').strip() else None,
      'title':clean_text(meta.get('title') or ('파일 자동 등록 견적' if kind=='quote' else '파일 자동 등록 발주'),'문서 제목',150),
      'vat_mode':mode,
      'stated_subtotal':number(meta['subtotal'],'공급가액',allow_zero=True),
      'stated_vat':number(meta['vat'],'부가세',allow_zero=True),
      'stated_total':number(meta['total'],'총금액',allow_zero=True),
    }
    if len(out['business_number'])>20:raise DocumentError('사업자번호가 너무 깁니다')
    if 'currency' in meta and norm(meta['currency']) not in ('krw','원','대한민국원'):
        raise DocumentError('원화(KRW)가 아닌 문서는 자동 등록할 수 없습니다')
    out['additional_fields']={field:clean_text(meta[field],field,limit)
                              for field,limit in OPTIONAL_FIELD_LIMITS.items() if field in meta and meta[field] is not None and str(meta[field]).strip()}
    if kind=='quote' and meta.get('due_date') is not None and str(meta['due_date']).strip():
        expected_delivery=to_date(meta['due_date'],'견적상 납품예정일')
        if out['quote_date'] and expected_delivery < out['quote_date']:
            raise DocumentError('견적상 납품예정일이 견적일보다 빠릅니다')
        out['additional_fields']['expected_delivery_date']=expected_delivery
    if 'valid_until' in out['additional_fields']:
        if kind!='quote':raise DocumentError('발주에 견적 유효기한이 포함되어 있습니다. 원본을 확인하세요')
        out['additional_fields']['valid_until']=to_date(out['additional_fields']['valid_until'],'견적유효일')
        if out['quote_date'] and out['additional_fields']['valid_until'] < out['quote_date']:
            raise DocumentError('견적 유효기한은 견적일보다 빠를 수 없습니다')
    out['currency']='KRW'
    if not allow_missing and any(out[x] is None for x in fillable):
        raise DocumentError('거래처와 문서 날짜 등의 필수 항목을 기입해야 합니다')
    if kind=='order' and out['due_date'] and out['ordered_at'] and out['due_date']<out['ordered_at']:
        raise DocumentError('납기일이 수주일보다 빠릅니다')
    return out

def normalize_items(raw_items):
    if not (1<=len(raw_items)<=MAX_ROWS):raise DocumentError('품목은 1~40개여야 합니다')
    items=[]
    for i,x in enumerate(raw_items,1):
        item={'name':clean_text(x.get('name'),f'{i}행 품목',150),
              'quantity':number(x.get('quantity'),f'{i}행 수량'),
              'unit_price':number(x.get('unit_price'),f'{i}행 단가',allow_zero=True)}
        if item['quantity']>100_000 or item['unit_price']>1_000_000_000:
            raise DocumentError(f'{i}행 수량 또는 단가가 허용 범위를 초과했습니다')
        stated=number(x.get('line_total'),f'{i}행 금액',allow_zero=True)
        computed=item['quantity']*item['unit_price']
        if stated!=computed:raise DocumentError(f'{i}행 금액 불일치: 원본 {stated:,}원 / 재계산 {computed:,}원')
        item['line_total']=computed
        for field,limit in (('sku',80),('spec',150),('unit',20)):
            raw=x.get(field)
            item[field]=clean_text(raw,f'{i}행 {field}',limit) if raw is not None and str(raw).strip() else ''
        items.append(item)
    return items

def quantity_by_unit(items):
    totals={}
    for item in items:
        unit=item.get('unit') or '단위 미기재'
        totals[unit]=totals.get(unit,0)+item['quantity']
    return totals

def verify(meta, rows, *, allow_missing=False):
    meta=normalize_meta(meta, allow_missing=allow_missing)
    items=normalize_items(rows)
    subtotal=sum(x['line_total'] for x in items)
    vat=(subtotal+5)//10 if meta['vat_mode']=='taxable' else 0
    total=subtotal+vat
    if (subtotal,vat,total)!=(meta['stated_subtotal'],meta['stated_vat'],meta['stated_total']):
        raise DocumentError('문서 합계 불일치: 공급가액/부가세/총금액 중 재계산과 다른 항목이 있습니다')
    return {'document_kind':meta['document_kind'],'record_type':meta['record_type'],'quote_date':meta['quote_date'],'company':meta['company'],'business_number':meta['business_number'],
            'ordered_at':meta['ordered_at'],'due_date':meta['due_date'],
            'title':meta['title'],'vat_mode':meta['vat_mode'],
            'items':items,'money':{'subtotal':subtotal,'vat':vat,'total':total},
            'item_count':len(items),'ordered_quantity':sum(x['quantity'] for x in items),
            'quantity_by_unit':quantity_by_unit(items),'additional_fields':meta['additional_fields'],
            'currency':meta['currency'],
            'missing_fields':[x for x in (('company','quote_date') if meta['record_type']=='quote' else ('company','ordered_at','due_date')) if meta[x] is None],
            'user_filled_fields':[]}

def read_table(matrix):
    header=None; rows=[]
    for idx, row in enumerate(matrix):
        vals=list(row or [])
        keys=[unique_key(x,COLUMNS) for x in vals]
        if all(x in keys for x in COLUMNS):
            # Unknown item columns might contain prices, discounts or contractual terms.
            # Never silently discard an extra source column from a recognized table.
            for label in vals:
                if label is not None and str(label).strip() and not (unique_key(label,COLUMNS) or unique_key(label,OPTIONAL_COLUMNS)):
                    raise DocumentError(f'인식되지 않은 품목 열: {str(label)[:30]}. 양식 매핑이 필요합니다')
            if header is not None:raise DocumentError('품목 표 헤더가 여러 개입니다')
            if len(set(x for x in keys if x))!=4:raise DocumentError('품목 표 헤더 중복')
            header={k:keys.index(k) for k in COLUMNS}
            for field,aliases in OPTIONAL_COLUMNS.items():
                positions=[i for i,x in enumerate(vals) if norm(x) in {norm(y) for y in aliases}]
                if len(positions)>1:raise DocumentError(f'품목표에 {field} 열이 중복됩니다')
                if positions:header[field]=positions[0]
            start=idx+1
            break
    if header is None:raise DocumentError('품목·수량·단가·금액 4개 열의 표를 찾지 못했습니다')
    for row_idx,row in enumerate(matrix[start:],start):
        vals=list(row or [])
        cells={k:vals[v] if v<len(vals) else None for k,v in header.items()}
        if all(x is None or str(x).strip()=='' for x in cells.values()):
            if rows and any(any(v is not None and str(v).strip() for v in (rr or [])) for rr in matrix[row_idx+1:]):
                raise DocumentError('품목 사이 빈 행이 있어 품목 누락 위험으로 등록을 차단합니다')
            continue
        # Totals row at the bottom, never interpret it as an item.
        if norm(cells['name']) in ('합계','총합계','공급가액','총금액','부가세'):
            # Preserve accuracy: never silently ignore later nonempty items.
            remainder=matrix[row_idx+1:]
            if any(any(v is not None and str(v).strip() for v in (rr or [])) for rr in remainder):
                raise DocumentError('합계 행 뒤에 데이터가 있습니다. 숨겨진 품목 누락 위험으로 등록을 차단합니다')
            break
        if not cells['name'] or cells['quantity'] is None or cells['unit_price'] is None or cells['line_total'] is None:
            raise DocumentError('품목표에 일부 값이 비어 있는 행이 있습니다')
        rows.append(cells)
        if len(rows)>MAX_ROWS:raise DocumentError('품목은 최대 40행입니다')
    if not rows:raise DocumentError('품목 데이터가 없습니다')
    return rows

def excel_extract(raw, *, allow_missing=False):
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            parts=z.infolist()
            if len(parts)>1500 or sum(x.file_size for x in parts)>30*1024*1024:
                raise DocumentError('압축 해제 시 용량 또는 항목이 과도한 엑셀입니다')
            if any(x.file_size>20*1024*1024 for x in parts):raise DocumentError('압축 내 파일이 너무 큽니다')
            if any('vbaProject' in x.filename or 'externalLinks/' in x.filename for x in parts):
                raise DocumentError('매크로 또는 외부 링크 문서는 지원하지 않습니다')
        wb=load_workbook(io.BytesIO(raw),read_only=False,data_only=False,keep_links=False)
    except DocumentError:raise
    except Exception as exc:raise DocumentError('유효한 .xlsx 파일이 아닙니다') from exc
    try:
        if len(wb.worksheets)!=1:raise DocumentError('시트가 여러 개이면 문서 선택이 모호합니다. 시트 하나로 저장하세요')
        ws=wb.worksheets[0]
        if ws.sheet_state!='visible':raise DocumentError('숨김 시트는 허용하지 않습니다')
        if ws.max_row>250 or ws.max_column>35:raise DocumentError('문서 크기 또는 표 구조가 허용 범위를 벗어났습니다')
        for row in ws:
            for cell in row:
                if cell.value is not None and (ws.row_dimensions[cell.row].hidden or ws.column_dimensions[cell.column_letter].hidden):
                    raise DocumentError('숨겨진 행/열에 데이터가 있습니다. 원본 확인을 위해 등록을 차단합니다')
                if cell.data_type=='f':raise DocumentError(f'{cell.coordinate}: 계산식은 캐시값이 오래되었을 수 있습니다. 값으로 붙여넣은 파일만 허용합니다')
        cells=[[x.value for x in row] for row in ws]
        meta={}
        header_idx=next((i for i,row in enumerate(cells) if set(COLUMNS).issubset(
            {unique_key(x,COLUMNS) for x in row})),None)
        if header_idx is None:raise DocumentError('품목 표 헤더를 찾지 못했습니다')
        for row in cells[:header_idx]:
            for j,value in enumerate(row[:-1]):
                key=unique_key(value,FIELDS)
                if key and row[j+1] is not None and str(row[j+1]).strip():
                    if key in meta and str(meta[key])!=str(row[j+1]):raise DocumentError(f'{key}: 문서에 중복된 서로 다른 값이 있습니다')
                    meta[key]=row[j+1]
                    if key=='ordered_at':meta['_ordered_at_label']=norm(value)
                elif j==0 and isinstance(value,str) and value.strip() and row[j+1] is not None and str(row[j+1]).strip() and not key:
                    # An unrecognized source field may be commercially significant; never silently discard it.
                    raise DocumentError(f'지원하지 않는 추가 항목: {value[:30]}. 양식 매핑 후 다시 등록하세요')
        return verify(meta,read_table(cells),allow_missing=allow_missing)
    finally:wb.close()

def pdf_extract(raw, *, allow_missing=False):
    try:
        with pdfplumber.open(io.BytesIO(raw)) as pdf:
            if len(pdf.pages)<1 or len(pdf.pages)>MAX_PDF_PAGES:raise DocumentError('PDF는 1~8페이지여야 합니다')
            meta={};table_list=[]
            for p in pdf.pages:
                text=p.extract_text() or ''
                if not text.strip():raise DocumentError('스캔·이미지 PDF는 아직 지원하지 않습니다. 검색 가능한 PDF를 사용하세요')
                for line in text.splitlines():
                    m=re.match(r'^\s*([^:：]{1,25})\s*[:：]\s*(.+?)\s*$',line)
                    if not m:continue
                    key=unique_key(m.group(1),FIELDS)
                    if not key:
                        raise DocumentError(f'지원하지 않는 PDF 추가 항목: {m.group(1).strip()[:30]}. 양식 매핑이 필요합니다')
                    if key:
                        value=m.group(2).strip()
                        if key in meta and str(meta[key])!=value:raise DocumentError(f'{key}: PDF에서 중복된 서로 다른 값이 있습니다')
                        meta[key]=value
                        if key=='ordered_at':meta['_ordered_at_label']=norm(m.group(1))
                for tab in p.extract_tables():
                    header_labels={unique_key(x,COLUMNS) for row in tab[:5] for x in row}
                    if set(COLUMNS).issubset(header_labels):table_list.append(tab)
            if len(table_list)!=1:raise DocumentError('PDF 품목 표를 하나로 특정할 수 없습니다. 표가 있는 검색 가능한 PDF가 필요합니다')
            return verify(meta,read_table(table_list[0]),allow_missing=allow_missing)
    except DocumentError:raise
    except Exception as exc:raise DocumentError('PDF 문서를 안전하게 해석하지 못했습니다') from exc

def extract(filename: str, raw: bytes, *, allow_missing=False):
    if not raw or len(raw)>MAX_FILE_SIZE:raise DocumentError('파일은 비어 있지 않은 5MB 이하이어야 합니다')
    suffix=Path(filename).suffix.lower()
    if suffix=='.xlsx':
        if not raw.startswith(b'PK\x03\x04'):raise DocumentError('파일 내용이 .xlsx 형식과 다릅니다')
        result=excel_extract(raw,allow_missing=allow_missing)
    elif suffix=='.pdf':
        if not raw.startswith(b'%PDF-'):raise DocumentError('파일 내용이 PDF 형식과 다릅니다')
        result=pdf_extract(raw,allow_missing=allow_missing)
    else:raise DocumentError('첫 버전은 .xlsx 및 텍스트 기반 .pdf만 지원합니다')
    result['filename']=Path(filename).name[:150]
    result['format']=suffix[1:]
    return result


def supplement_review(document: dict, fields: dict) -> dict:
    """Fill only missing/source-unfilled identity and date fields; keep all extracted amounts immutable."""
    fillable=('company','quote_date') if document.get('record_type')=='quote' else ('company','ordered_at','due_date')
    if not fields or any(x not in fillable for x in fields):
        raise DocumentError('원본에서 누락된 거래처·문서 날짜만 보완할 수 있습니다')
    filled=set(document.get('user_filled_fields') or [])
    missing=set(document.get('missing_fields') or [])
    for key in fields:
        if key not in missing and key not in filled:
            raise DocumentError(f'{key}: 원본에서 인식된 값은 변경할 수 없습니다. 원본을 수정한 뒤 다시 올려주세요')
    changed=dict(document)
    for key,value in fields.items():
        if not isinstance(value,str) or not value.strip():
            raise DocumentError(f'{key}: 빈 값으로 보완할 수 없습니다')
        if key=='company':changed[key]=clean_text(value,'거래처',120)
        elif key=='ordered_at':changed[key]=to_date(value,'수주일')
        elif key=='quote_date':changed[key]=to_date(value,'견적일')
        else:changed[key]=to_date(value,'납기일')
        filled.add(key)
    if changed.get('ordered_at') and changed.get('due_date') and changed['due_date']<changed['ordered_at']:
        raise DocumentError('납기일이 수주일보다 빠릅니다')
    changed['user_filled_fields']=sorted(filled)
    changed['missing_fields']=[k for k in fillable if not changed.get(k)]
    # Financial values and source items are not taken from user input; verify stored totals again.
    stated={'document_kind':changed['document_kind'],'company':changed['company'],
            'ordered_at':changed['ordered_at'],'quote_date':changed.get('quote_date'),'due_date':changed['due_date'],
            'vat_mode':changed['vat_mode'],'subtotal':changed['money']['subtotal'],
            'vat':changed['money']['vat'],'total':changed['money']['total'],
            'business_number':changed['business_number'], 'title':changed['title']}
    for key,val in changed.get('additional_fields',{}).items():
        if key=='expected_delivery_date' and changed.get('record_type')=='quote':
            stated['due_date']=val
        else:stated[key]=val
    rows=[dict(x) for x in changed['items']]
    result=verify(stated,rows,allow_missing=True)
    for k in ('filename','format','user_filled_fields','missing_fields'):
        if k in changed:result[k]=changed[k]
    return result
