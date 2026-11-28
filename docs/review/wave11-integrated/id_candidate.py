"""Separate exact-boundary OCR proposals. Never replace conflicting review evidence."""
from korean_observations import value
from review_gates import need

IDS=('counterparty_id','reference_number')
def propose(primary,boxes,read_exact):
    out=[]; count=0
    for field in IDS:
        matches=[b for k,b in boxes if k==field]
        existing=[r for r in primary if r['field']==field]
        if not existing:continue
        if len(matches)!=1 or len(existing)!=1:
            out.append(dict(field=field,value=None,page=1));continue
        reads=[read_exact(matches[0],view) for view in ('gray','binary')]
        vals=[value(field,x) if type(x) is str else None for x in reads]
        if vals[0] is not None and vals[0]==vals[1]:
            out.append(dict(field=field,value=vals[0],page=1));count+=1
        else:out.append(dict(field=field,value=None,page=1))
    need(count<=2,'OCR_ID_CANDIDATE_COUNT')
    # Replace only the *separate preview*; original observations are never mutated.
    return [dict(r) for r in primary if r['field'] not in {x['field'] for x in out}]+out,count
