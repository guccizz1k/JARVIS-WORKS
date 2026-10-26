"""V6.4 offline evidence parser. Untrusted bytes; invoked only by a resource-limited worker.

OCR is not a financial authority. This function returns suggestions only, no ledger writes.
"""
from __future__ import annotations
import base64
import io
import json
import re
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path
from zipfile import ZipFile

MAX_BYTES = 5 * 1024 * 1024
MAX_PIXELS = 12_000_000
MAX_PDF_PAGES = 4

class EvidenceError(ValueError): pass

LABELS = {
 'document_kind': ['문서종류','문서구분','증빙종류'],
 'business_number': ['사업자번호','사업자등록번호','사업자등록증번호'],
 'counterparty': ['거래처','상호','판매자','공급자','공급받는자','매입처','업체명'],
 'document_date': ['거래일','발행일','발행일자','작성일','결제일','입고일','기준일'],
 'gross_amount': ['총금액','결제금액','합계금액','총합계','지출금액','공급대가','합계'],
 'subtotal': ['공급가액','공급가액합계'],
 'vat': ['부가세','부가가치세'],
 'reference_number': ['문서번호','영수증번호','승인번호','거래번호','전표번호'],
 'sku': ['품목코드','상품코드','재고코드','SKU'],
 'quantity': ['재고수량','현재고','실사수량','수량'],
 'unit': ['단위'],
}
TYPES = {
 '영수증':'receipt', '카드영수증':'receipt', '지출영수증':'receipt',
 '매출전표':'sales_slip', '매입전표':'purchase_slip',
 '거래명세표':'trade_statement', '거래명세서':'trade_statement',
 '재고표':'inventory_sheet','재고현황':'inventory_sheet','재고현황표':'inventory_sheet',
}
DEFAULT_RECORD = {'receipt':'expense','sales_slip':'sales','purchase_slip':'purchase',
                  'trade_statement':None,'inventory_sheet':'inventory_snapshot'}

def clean(s,limit=120):
 s=str(s or '').strip()
 if len(s)>limit or any(ord(c)<32 and c not in '\n\t' for c in s):raise EvidenceError('문서 필드의 길이 또는 제어문자가 허용 범위를 넘었습니다')
 return s

def text_fields(text):
 vals={}; conflicts=[]
 for line in text.splitlines()[:180]:
  m=re.match(r'^\s*([^:\t：]{1,22})\s*[:：\t]\s*(\S.*?)\s*$',line)
  if not m:continue
  key=re.sub(r'\s+','',m.group(1)).casefold()
  hits=[k for k,names in LABELS.items() if key in [re.sub(r'\s+','',x).casefold() for x in names]]
  if len(hits)!=1:continue
  name=hits[0];value=clean(m.group(2),180)
  # Conflicting OCR cells must never be resolved by last-value-wins.
  if name in vals and vals[name]!=value:conflicts.append(name)
  if name not in conflicts:vals[name]=value
 for name in conflicts:vals.pop(name,None)
 return vals,sorted(set(conflicts))

def kind_guess(text, fields):
 value=re.sub(r'\s+','',fields.get('document_kind',''))
 if value in TYPES:return TYPES[value], 'explicit'
 matched=[v for k,v in TYPES.items() if k in text]
 matched=set(matched)
 if len(matched)==1:return matched.pop(),'keyword'
 return None,'ambiguous' if matched else 'unknown'

def to_positive_int(value):
 if value is None:return None
 value=re.sub(r'[\s,원₩]', '',str(value))
 if not re.fullmatch(r'[0-9]{1,12}',value):return None
 x=int(value)
 return x if x>0 else None

def to_date(value):
 if value is None:return None
 m=re.fullmatch(r'\s*([0-9]{4})(?:[./-]|년\s*)([0-9]{1,2})(?:[./-]|월\s*)([0-9]{1,2})(?:일)?\s*',str(value))
 if not m:return None
 try:return date(*map(int,m.groups())).isoformat()
 except ValueError:return None

def ocr_image(raw):
 from PIL import Image,ImageOps,UnidentifiedImageError
 try:
  with Image.open(io.BytesIO(raw)) as im:
   if im.width*im.height>MAX_PIXELS or im.width<50 or im.height<50:
    raise EvidenceError('사진의 해상도가 허용 범위를 벗어났습니다')
   # Normalize input and strip metadata. A dedicated temporary directory is erased on exit.
   image=ImageOps.exif_transpose(im).convert('RGB')
   with tempfile.TemporaryDirectory(prefix='jw-ocr-') as temp:
    image.save(Path(temp)/'input.png',format='PNG')
    try:
     p=subprocess.run(['tesseract',str(Path(temp)/'input.png'),'stdout','-l','kor+eng','--psm','6'],
                      stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,check=False)
    except FileNotFoundError as exc:raise EvidenceError('OCR 엔진이 설치되지 않았습니다') from exc
    except subprocess.TimeoutExpired as exc:raise EvidenceError('OCR 제한시간 초과') from exc
    if p.returncode!=0 or len(p.stdout)>160_000:raise EvidenceError('OCR 분석 실패')
    return p.stdout.decode('utf-8',errors='replace')[:12000]
 except (UnidentifiedImageError,OSError) as exc:raise EvidenceError('지원하지 않는 이미지 파일입니다') from exc

def parse_xlsx(raw):
 from openpyxl import load_workbook
 try:
  with ZipFile(io.BytesIO(raw)) as z:
   names=z.namelist()
   if len(names)>1200 or sum(e.file_size for e in z.infolist())>30*1024*1024 or any('externalLinks/' in n or 'vbaProject' in n for n in names):
    raise EvidenceError('보안상 제한된 XLSX 구조입니다')
  wb=load_workbook(io.BytesIO(raw),read_only=False,data_only=False,keep_links=False)
  try:
   if len(wb.worksheets)!=1 or wb.worksheets[0].sheet_state!='visible':raise EvidenceError('XLSX는 보이는 단일 시트만 지원합니다')
   ws=wb.worksheets[0]
   if ws.max_row>200 or ws.max_column>20:raise EvidenceError('표 크기가 초과되었습니다')
   rows=[]
   for row in ws:
    if ws.row_dimensions[row[0].row].hidden:raise EvidenceError('숨긴 행이 있는 문서는 검토할 수 없습니다')
    cells=[]
    for c in row:
     if c.data_type=='f':raise EvidenceError('수식이 포함된 파일은 값으로 변환한 후 다시 업로드하세요')
     if ws.column_dimensions[c.column_letter].hidden and c.value is not None:raise EvidenceError('숨긴 열에 값이 있습니다')
     cells.append(clean(c.value,180) if c.value is not None else '')
    if any(cells):rows.append(' : '.join(cells[:2]))
   return '\n'.join(rows)
  finally:wb.close()
 except EvidenceError:raise
 except Exception as exc:raise EvidenceError('XLSX 분석 실패') from exc

def xlsx_line_suggestions(raw):
 """V6.8 safe *candidate only* rows from explicit XLSX table headings.

 Does not approve or post business records. Caller has already run parse_xlsx,
 which rejects formulas, hidden cells and unsafe workbook structures.
 """
 from openpyxl import load_workbook
 columns={
  'name':{'품목','품목명','품명','상품명','제품명'},
  'quantity':{'수량','납품수량','주문수량'},
  'unit_price':{'단가','판매단가','공급단가'},
  'product_code':{'품목코드','상품코드','제품코드','SKU'},
  'line_amount':{'금액','공급가액','품목금액'},
 }
 wb=load_workbook(io.BytesIO(raw),read_only=False,data_only=False,keep_links=False)
 try:
  ws=wb.worksheets[0]
  headers=None;start=0
  for row in ws.iter_rows(min_row=1,max_row=min(ws.max_row,35),max_col=min(ws.max_column,20)):
   found={};duplicate=False
   for cell in row:
    h=re.sub(r'\s+','',str(cell.value or '')).casefold()
    keys=[k for k,aliases in columns.items() if h in {a.casefold() for a in aliases}]
    if keys:
     if keys[0] in found:duplicate=True;break
     found[keys[0]]=cell.column-1
   if not duplicate and {'name','quantity','unit_price'}<=found.keys():
    headers=found;start=row[0].row+1;break
  if headers is None:return [],[]
  result=[];issues=[]
  for row in ws.iter_rows(min_row=start,max_row=ws.max_row,max_col=min(ws.max_column,20)):
   name=clean(row[headers['name']].value or '',150).strip()
   if not name:continue
   if re.sub(r'\s+','',name) in ('합계','총계','소계','계','부가세','VAT'):
    break
   q=to_positive_int(row[headers['quantity']].value)
   price_str=str(row[headers['unit_price']].value if row[headers['unit_price']].value is not None else '')
   price=re.sub(r'[\s,원₩]', '',price_str)
   if not q or q>100_000 or not re.fullmatch(r'\d{1,10}',price) or int(price)>1_000_000_000:
    issues.append('표에 해석할 수 없는 수량·단가가 있습니다. 품목은 수동으로 검토하세요')
    return [],issues
   code=clean(row[headers['product_code']].value or '',80) if 'product_code' in headers else ''
   if 'line_amount' in headers:
    raw_sum=row[headers['line_amount']].value
    val=re.sub(r'[\s,원₩]', '',str(raw_sum if raw_sum is not None else ''))
    if not re.fullmatch(r'\d{1,16}',val) or int(val)!=q*int(price):
     issues.append('표의 품목별 금액과 수량×단가가 일치하지 않습니다. 수동 확인이 필요합니다')
     return [],issues
   result.append({'name':name,'product_code':code,'quantity':q,'unit_price':int(price)})
   if len(result)>40:
    return [],['품목 후보가 40개를 초과합니다. 직접 검토하세요']
  if not result:return [],[]
  issues.append('XLSX 품목 후보는 자동 확정되지 않습니다. 원본 확인 후 품목별 승인 필요')
  return result,issues
 finally:wb.close()

def parse_pdf(raw):
 import fitz
 try:
  doc=fitz.open(stream=raw,filetype='pdf')
  try:
   if not 1<=len(doc)<=MAX_PDF_PAGES:raise EvidenceError('PDF는 1~4페이지만 지원합니다')
   text=[];methods=[]
   for page in doc:
    raw_text=page.get_text(sort=True)
    if len(raw_text.strip())>25:
     text.append(raw_text);methods.append('pdf_text')
    else:
     pix=page.get_pixmap(matrix=fitz.Matrix(1.6,1.6),alpha=False)
     if pix.width*pix.height>MAX_PIXELS:raise EvidenceError('PDF 렌더링 해상도 초과')
     text.append(ocr_image(pix.tobytes('png')));methods.append('ocr')
   return '\n'.join(text), 'ocr' if 'ocr' in methods else 'pdf_text'
  finally:doc.close()
 except EvidenceError:raise
 except Exception as exc:raise EvidenceError('PDF 분석 실패') from exc

def extract(filename, raw):
 if not 0<len(raw)<=MAX_BYTES:raise EvidenceError('5MB 이하의 파일만 가능합니다')
 suffix=Path(filename).suffix.lower()
 if suffix=='.pdf':
  if not raw.startswith(b'%PDF-'):raise EvidenceError('PDF 확장자와 실제 파일 형식이 다릅니다')
  text,method=parse_pdf(raw)
 elif suffix=='.xlsx':
  if not raw.startswith(b'PK\x03\x04'):raise EvidenceError('XLSX 확장자와 실제 파일 형식이 다릅니다')
  text=parse_xlsx(raw);method='xlsx'
 elif suffix in ('.png','.jpg','.jpeg','.webp'):
  if not (raw.startswith(b'\x89PNG\r\n\x1a\n') or raw.startswith(b'\xff\xd8\xff') or raw.startswith(b'RIFF') and raw[8:12]==b'WEBP'):
   raise EvidenceError('이미지 확장자와 파일 형식이 다릅니다')
  text=ocr_image(raw);method='ocr'
 else:raise EvidenceError('지원되는 파일은 PNG, JPEG, WEBP, PDF, XLSX입니다')
 if not text.strip():raise EvidenceError('문자를 인식하지 못했습니다. 품질이 높은 문서를 이용하세요')
 suggested_lines, line_warnings = xlsx_line_suggestions(raw) if suffix=='.xlsx' else ([],[])
 fields,conflicts=text_fields(text)
 kind,confidence=kind_guess(text,fields)
 if 'document_kind' in conflicts:kind,confidence=None,'ambiguous'
 subtotal=to_positive_int(fields.get('subtotal'))
 vat=to_positive_int(fields.get('vat')) if fields.get('vat')!='0' else 0
 gross=to_positive_int(fields.get('gross_amount'))
 from .evidence_quality_v70 import assess_evidence
 quality=assess_evidence(fields,conflicts,kind,method,text)
 warning=list(line_warnings)+quality['issues']
 if conflicts:warning.append('같은 필드에 다른 값 존재: '+', '.join(conflicts))
 if kind is None:warning.append('문서 유형 확인 필요')
 if method=='ocr':warning.append('OCR은 정확도가 보장되지 않습니다. 원본과 모든 항목을 직접 대조하세요')
 if gross is not None and subtotal is not None and vat is not None and gross!=subtotal+vat:
  warning.append('공급가액+부가세와 총액 불일치. 원본 확인 및 정정 필요')
 if not fields.get('counterparty'):warning.append('거래처 누락')
 if to_date(fields.get('document_date')) is None:warning.append('거래 날짜 누락 또는 인식 실패')
 if gross is None and kind!='inventory_sheet':warning.append('금액 누락 또는 인식 실패')
 return {'document_kind':kind,'kind_inference':confidence,'proposed_record_type':DEFAULT_RECORD.get(kind),
         'method':method,'filename':Path(filename).name[:150],
         'quality':quality,
         'fields':{'counterparty':fields.get('counterparty','')[:120],
                   'document_date':to_date(fields.get('document_date')),
                   'gross_amount':gross,'subtotal':subtotal,'vat':vat,
                   'reference_number':fields.get('reference_number','')[:80],
                   'sku':fields.get('sku','')[:80],
                   'quantity':to_positive_int(fields.get('quantity')),
                   'unit':fields.get('unit','')[:20]},
         'warnings':warning,'suggested_lines':suggested_lines,
         'suggested_lines_source':'xlsx_table_unverified' if suggested_lines else None,
         'ocr_text_excerpt':quality['safe_excerpt'],
         'source_sha_note':'원본은 저장되지 않으며 검토 후 데이터만 기록됩니다'}

def main():
 # Apply limits inside this dedicated child process. Python preexec_fn inside a
 # threaded FastAPI server can deadlock after fork; do not use it in the parent.
 if sys.platform != 'win32':
  import resource
  resource.setrlimit(resource.RLIMIT_CPU,(45,46))
  resource.setrlimit(resource.RLIMIT_AS,(900*1024*1024,900*1024*1024))
  resource.setrlimit(resource.RLIMIT_FSIZE,(4*1024*1024,4*1024*1024))
  resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 try:
  payload=json.loads(sys.stdin.buffer.read(7_100_000))
  raw=base64.b64decode(payload['base64'],validate=True)
  result=extract(payload['filename'],raw)
  sys.stdout.write(json.dumps({'result':result},ensure_ascii=False))
 except EvidenceError as exc:
  sys.stdout.write(json.dumps({'error':str(exc)},ensure_ascii=False))
 except Exception:
  sys.stdout.write(json.dumps({'error':'문서 분석 오류. 문서를 확인하거나 OCR 엔진 설치 상태를 점검하세요'},ensure_ascii=False))

if __name__=='__main__':main()
