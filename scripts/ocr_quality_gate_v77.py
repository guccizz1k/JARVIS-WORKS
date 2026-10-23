"""Offline consented-field OCR evaluation (aggregate only; never logs raw fields).

Input is a human-labeled JSON file prepared offline. No network upload or OCR
model quality guarantee. Never apply simulated accuracy to production claims.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import unicodedata

FIELDS=('counterparty','business_number','document_number','date','item_name','quantity','unit_price','supply_amount','vat_amount','total_amount')
MAX_DOCS=500
MAX_BYTES=1_000_000

class EvaluationBlocked(ValueError):pass


def normalize(value):
    if value is None:return ''
    if isinstance(value,bool) or not isinstance(value,(str,int,float)):
        raise EvaluationBlocked('Invalid scalar field type')
    value=unicodedata.normalize('NFKC',str(value)).strip()
    return ' '.join(value.split())


def distance(a,b):
    # O(min(len(a),len(b))) memory, bounded lengths verified before use.
    prev=list(range(len(b)+1))
    for i,ch in enumerate(a,1):
        row=[i]
        for j,other in enumerate(b,1):
            row.append(min(row[-1]+1,prev[j]+1,prev[j-1]+(ch!=other)))
        prev=row
    return prev[-1]


def evaluate(rows, *, dataset='offline_labeled'):
    if not isinstance(rows,list) or not rows or len(rows)>MAX_DOCS:
        raise EvaluationBlocked('Labeled dataset must have 1..500 entries')
    result={key:{'evaluated':0,'exact':0,'tp':0,'fp':0,'fn':0,'substitutions':0,'ref_chars':0,'abstentions':0} for key in FIELDS}
    for row in rows:
        if not isinstance(row,dict) or set(row)!= {'expected','predicted'}:
            raise EvaluationBlocked('Invalid row structure')
        exp,pred=row['expected'],row['predicted']
        if not isinstance(exp,dict) or not isinstance(pred,dict):
            raise EvaluationBlocked('Invalid field mapping')
        if set(exp)-set(FIELDS) or set(pred)-set(FIELDS):
            raise EvaluationBlocked('Unsupported field name')
        if not exp:
            raise EvaluationBlocked('No labeled fields')
        for key,ev in exp.items():
            expected=normalize(ev); actual=normalize(pred.get(key))
            if len(expected)>500 or len(actual)>500:
                raise EvaluationBlocked('Field exceeds length cap')
            stats=result[key]
            stats['evaluated']+=1
            stats['exact']+=int(expected==actual)
            stats['ref_chars']+=len(expected)
            stats['substitutions']+=distance(expected,actual)
            if not actual:stats['abstentions']+=1
            if expected and actual==expected:stats['tp']+=1
            elif expected and not actual:stats['fn']+=1
            elif expected and actual!=expected:stats['fn']+=1;stats['fp']+=1
            elif not expected and actual:stats['fp']+=1
    public={}
    for key,v in result.items():
        if not v['evaluated']:continue
        precision=(v['tp']/(v['tp']+v['fp'])) if v['tp']+v['fp'] else None
        recall=(v['tp']/(v['tp']+v['fn'])) if v['tp']+v['fn'] else None
        public[key]={
            'samples':v['evaluated'],
            'exact_match_rate':round(v['exact']/v['evaluated'],4),
            'precision':round(precision,4) if precision is not None else None,
            'recall':round(recall,4) if recall is not None else None,
            'character_error_rate':round(v['substitutions']/v['ref_chars'],4) if v['ref_chars'] else None,
            'abstentions':v['abstentions'],
            'incorrect_nonempty_predictions':v['fp'],
        }
    return {'dataset':dataset,'documents':len(rows),'fields':public,
            'synthetic_or_consent_document_source_unverified':True,
            'production_quality_approved':False,
            'limits':'Aggregate labeled comparisons; no inference about real customer OCR without representative source evidence'}


def from_manifest(path:Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_BYTES:
        raise EvaluationBlocked('Unsafe or oversize local manifest')
    content=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(content,dict) or set(content)!={'rows','dataset'} or content['dataset'] not in ('synthetic','consented_real'):
        raise EvaluationBlocked('Invalid dataset declaration')
    return evaluate(content['rows'],dataset=content['dataset'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Aggregate OCR field evaluation: NO data upload, NO production certification')
    parser.add_argument('--manifest',required=True,type=Path)
    args=parser.parse_args()
    print(json.dumps(from_manifest(args.manifest),ensure_ascii=False,indent=2))
