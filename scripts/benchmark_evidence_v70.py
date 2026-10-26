#!/usr/bin/env python3
"""Synthetic-only deterministic benchmark (NO customer documents, no PII).

Usage: python scripts/benchmark_evidence_v70.py --out /tmp/v70_bench.json
Run with PYTHONPATH pointing to a baseline app to compare a previous revision.
"""
import argparse
import io
import json
import time
from collections import defaultdict
from pathlib import Path
from PIL import Image,ImageDraw,ImageFont
from openpyxl import Workbook
from app.evidence_v64_worker import extract

FONT=Path('/usr/share/fonts/truetype/nanum/NanumGothic.ttf')
KIND={'receipt':'영수증','sales_slip':'매출전표','purchase_slip':'매입전표','trade_statement':'거래명세표'}
FIELDS=('document_kind','counterparty','document_date','gross_amount')


def sample_xlsx(rows):
 wb=Workbook();ws=wb.active
 for row in rows:ws.append(list(row))
 b=io.BytesIO();wb.save(b);return b.getvalue()


def sample_png(rows):
 im=Image.new('RGB',(1250,540),'white')
 pen=ImageDraw.Draw(im)
 font=ImageFont.truetype(str(FONT),42)
 for idx,(key,val) in enumerate(rows):
  pen.text((50,25+idx*112),f'{key}: {val}',font=font,fill='black')
 b=io.BytesIO();im.save(b,format='PNG');return b.getvalue()


def cases():
 # Controlled synthetic fixtures only. Repeats and corruptions are intentional.
 for i in range(40):
  kind=list(KIND)[i%4];vendor=f'합성기업{i:03d}';day=f'2026-10-{i%28+1:02d}';total=10000+i*193
  rows=[('문서종류',KIND[kind]),('거래처',vendor),('거래일',day),('총금액',total)]
  expected={'document_kind':kind,'counterparty':vendor,'document_date':day,'gross_amount':total}
  if i%10==3:
   rows.append(('총합계',total+1000))
   expected['gross_amount']=None  # high-risk conflict must abstain
  if i%10==7:
   rows[-1]=('총금액',str(total).replace('0','O',1))
   expected['gross_amount']=None  # OCR-like ambiguous characters must abstain
  if i%10==9:
   rows[2]=('거래일','2026-02-30')
   expected['document_date']=None
  yield ('synth-%02d.xlsx'%i,sample_xlsx(rows),expected)
 # A tiny OCR smoke sample. It cannot establish real-world accuracy.
 for i in range(3):
  kind='receipt';vendor=f'합성인쇄상사{i}';day='2026-10-21';total=11000+i*500
  rows=[('문서종류',KIND[kind]),('거래처',vendor),('거래일',day),('총금액',total)]
  yield ('synth-ocr-%02d.png'%i,sample_png(rows),
         {'document_kind':kind,'counterparty':vendor,'document_date':day,'gross_amount':total})


def run():
 counts=defaultdict(lambda:{'tp':0,'fp':0,'fn':0,'abstention_ok':0,'abstention_fail':0})
 methods=defaultdict(lambda:{'cases':0,'strict_all_match':0})
 examples=[];start=time.monotonic()
 for name,raw,expected in cases():
  try:
   res=extract(name,raw)
   method=res['method'];matched=True
   for key in FIELDS:
    actual=res['document_kind'] if key=='document_kind' else res['fields'].get(key)
    truth=expected[key]
    if truth is None:
     if actual is None:counts[key]['abstention_ok']+=1
     else:counts[key]['abstention_fail']+=1
    else:
     if actual==truth:counts[key]['tp']+=1
     elif actual is None:counts[key]['fn']+=1
     else:
      counts[key]['fp']+=1;counts[key]['fn']+=1
    matched=matched and actual==truth
   methods[method]['cases']+=1
   methods[method]['strict_all_match']+=int(matched)
   if not matched:examples.append({'fixture':name,'method':method,'result':'mismatch'})
  except Exception as exc:
   methods['error']['cases']+=1
   examples.append({'fixture':name,'method':'error','result':type(exc).__name__})
 report={'dataset':'SYNTHETIC ONLY — not customer OCR accuracy',
         'benchmark_time_seconds':round(time.monotonic()-start,2),
         'methods':dict(methods), 'fields':{},
         'mismatch_fixtures':examples,
         'warnings':['No real-business documents; OCR results cannot be generalized.',
                     'Abstention means leaving an uncertain field blank; no automated approval.']}
 for key,c in counts.items():
  tp,fp,fn=c['tp'],c['fp'],c['fn']
  report['fields'][key]={**c,
   'precision':round(tp/(tp+fp),4) if tp+fp else None,
   'recall':round(tp/(tp+fn),4) if tp+fn else None}
 return report

if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--out',required=True)
 opts=a.parse_args();r=run();p=Path(opts.out);p.parent.mkdir(parents=True,exist_ok=True)
 p.write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf8')
 print(json.dumps({'out':str(p),'seconds':r['benchmark_time_seconds'],'methods':r['methods'],'fields':r['fields']},ensure_ascii=False))
