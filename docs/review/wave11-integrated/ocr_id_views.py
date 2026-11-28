"""Compare independently read ID crops to full-page OCR candidates.
Geometry comes from the primary engine's TSV; no automatic digit/letter repair.
If a crop cannot be resolved, record invalid evidence rather than silently accept.
"""
import csv,io,re
from korean_observations import LABELS,value
from review_gates import need

IDS={'counterparty_id','reference_number'}
def id_boxes(tsv,width,height):
    need(type(tsv) is str and len(tsv)<=250000,'OCR_TSV_LIMIT')
    reader=csv.DictReader(io.StringIO(tsv),delimiter='\t');lines={}
    need(reader.fieldnames==['level','page_num','block_num','par_num','line_num','word_num','left','top','width','height','conf','text'],'OCR_TSV_SHAPE')
    for r in reader:
        if r['level']!='5':continue
        need(len(lines)<=1000,'OCR_TSV_LINES')
        try:
            key=tuple(int(r[k]) for k in ('page_num','block_num','par_num','line_num'))
            x,y,w,h=(int(r[k]) for k in ('left','top','width','height'))
        except (ValueError,TypeError):raise ValueError('OCR_TSV_GEOMETRY') from None
        # OCR occasionally reports overlapping boxes; never crop outside image.
        need(0<=x<width and 0<=y<height and w>0 and h>0 and x+w<=width and y+h<=height,'OCR_TSV_GEOMETRY')
        t=r['text'];need(type(t) is str and len(t)<=512,'OCR_TSV_TEXT')
        lines.setdefault(key,[]).append((t,x,y,w,h))
    out=[]
    for row in lines.values():
        # Only a standalone delimiter or a delimiter at the end of a word is eligible.
        idx=next((i for i,e in enumerate(row) if ':' in e[0] or '：' in e[0]),None)
        if idx is None:continue
        words=row[:idx+1];last=words[-1][0];m=re.fullmatch(r'([^:：]*)[:：]',last)
        if not m:continue
        label=''.join(x[0] for x in words[:-1])+m[1];field=LABELS.get(label)
        if field not in IDS:continue
        rest=row[idx+1:]
        if not rest:continue
        x=min(e[1] for e in rest);y=min(e[2] for e in rest);x2=max(e[1]+e[3] for e in rest);y2=max(e[2]+e[4] for e in rest)
        if x2-x<=512 and y2-y<=256:out.append((field,(x,y,x2,y2)))
        need(len(out)<=8,'OCR_ID_CROP_LIMIT')
    return out

def add_id_views(primary,boxes,read_crop):
    result=list(primary)
    for f in IDS:
        present=[r for r in primary if r['field']==f];matches=[b for k,b in boxes if k==f]
        if not present:continue
        if len(matches)!=1 or len(present)!=1:
            result.append(dict(field=f,value=None,page=1));continue
        for mode in (7,8):
            raw=read_crop(matches[0],mode)
            v=value(f,raw) if type(raw) is str else None
            result.append(dict(field=f,value=v,page=1))
    need(len(result)<=128,'OCR_OBSERVATION_LIMIT');return result
