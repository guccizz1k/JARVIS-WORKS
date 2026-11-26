"""Offline, read-only reconciliation of completed NARUV retention journal.
Requires independently obtained original receipts and journal SHA-256 pin.
No network, file mutations or production authorization.
"""
import hashlib
import json
import re

DAY=86400000
HEX=re.compile(r'[0-9a-f]{64}')

def need(ok, code):
    if not ok: raise ValueError(code)

def unique_object(pairs):
    result={}
    for k,v in pairs:
        need(k not in result,'DUPLICATE_JSON_KEY')
        result[k]=v
    return result

def reconcile(raw, pin, expected):
    """Return NEW receipt mapping, never modify the original receipt mapping."""
    need(type(raw) is bytes and 0<len(raw)<=262144 and raw.endswith(b'\n'),'JOURNAL_FORMAT')
    need(type(pin) is str and HEX.fullmatch(pin) and hashlib.sha256(raw).hexdigest()==pin,'JOURNAL_PIN')
    need(type(expected) is dict and len(expected)==22,'RECEIPT_COUNT')
    try: lines=[json.loads(x,object_pairs_hook=unique_object) for x in raw.splitlines()]
    except (UnicodeError,json.JSONDecodeError): raise ValueError('JOURNAL_JSON') from None
    need(len(lines)==46 and type(lines[0]) is dict and set(lines[0])=={'stage','items'} and lines[0]['stage']=='plan','JOURNAL_PLAN')
    plan=lines[0]['items'];need(type(plan) is list and len(plan)==22,'PLAN_COUNT')
    names=[];ids=set();amended={}
    for i,p in enumerate(plan):
        need(type(p) is dict and set(p)=={'name','id','old','target','upload_ms','sha256'},'PLAN_FIELDS')
        n=p['name'];fid=p['id'];old=p['old'];ts=p['upload_ms'];target=p['target'];digest=p['sha256']
        need(type(n) is str and n in expected and n not in amended and type(fid) is str and fid not in ids,'PLAN_IDENTITY')
        r=expected[n]
        need(r['file_id']==fid and r['sha256']==digest and type(digest) is str and HEX.fullmatch(digest) and type(old) is int and old==r['retain_until_ms'],'ORIGINAL_RECEIPT_BINDING')
        need(type(ts) is int and type(target) is int and 0<ts<old<target and target==ts+30*DAY and 0<target-old<=1000,'RETENTION_DELTA')
        need(lines[1+i*2]=={'stage':'attempt',**p} and lines[2+i*2]=={'stage':'verified',**p},'JOURNAL_CHAIN')
        names.append(n);ids.add(fid);amended[n]=dict(r,retain_until_ms=target)
    need(names==sorted(expected),'PLAN_ORDER')
    need(lines[-1]=={'stage':'complete','verified':22,'shortfall_count':0},'JOURNAL_COMPLETE')
    return amended

def legal_hold_state(row):
    h=row.get('legalHold')
    need(type(h) is dict and h.get('isClientAuthorizedToRead') is True and 'value' in h,'HOLD_UNKNOWN')
    v=h['value'];need(v is None or (type(v) is str and v in ('on','off')),'HOLD_UNKNOWN')
    return 'unset' if v is None else v

def check_live_metadata(rows, expected, bucket_id, now):
    need(type(rows) is list and len(rows)==len(expected)==22,'LIVE_COUNT')
    need(type(now) is int and now>0,'LIVE_CLOCK')
    seen=set();ids=set();holds={'unset':0,'off':0,'on':0}
    for r in rows:
        n=r.get('fileName');fid=r.get('fileId');rec=expected.get(n)
        need(rec is not None and n not in seen and fid not in ids and fid==rec['file_id'] and r.get('bucketId')==bucket_id and r.get('action')=='upload','LIVE_IDENTITY')
        seen.add(n);ids.add(fid)
        ts=r.get('uploadTimestamp');t=rec['retain_until_ms'];length=r.get('contentLength');sha1=r.get('contentSha1')
        need(type(length) is int and 0<length<=32*1024*1024 and type(sha1) is str and re.fullmatch('[0-9a-f]{40}',sha1),'LIVE_FILE_METADATA')
        need(type(ts) is int and 0<ts<=now<t and t==ts+30*DAY,'LIVE_RETENTION_TIME')
        need(r.get('fileRetention')=={'isClientAuthorizedToRead':True,'value':{'mode':'compliance','retainUntilTimestamp':t}},'LIVE_RETENTION')
        need(r.get('serverSideEncryption')=={'mode':'SSE-B2','algorithm':'AES256'},'LIVE_ENCRYPTION')
        holds[legal_hold_state(r)]+=1
    return {'metadata_verified':22,'strict_30day_shortfall_count':0,'legal_hold':holds,'ciphertext_reverified':False,'restore_verified':False,'production_authorized':False}

def review_corrected_metadata(raw, pin, original_receipts, rows, bucket_id, now):
    """Validate correction evidence before reviewing supplied metadata; no provider auth."""
    corrected=reconcile(raw,pin,original_receipts)
    return dict(check_live_metadata(rows,corrected,bucket_id,now),journal_sha256=pin)

def plan_upload_retention(planned_at_ms, max_upload_ms, max_clock_skew_ms):
    """Proposed bounded upload allowance; verify provider timestamp after upload."""
    need(type(planned_at_ms) is int and 0<planned_at_ms<=10**14,'UPLOAD_CLOCK')
    need(type(max_upload_ms) is int and 1<=max_upload_ms<=120000,'UPLOAD_BUDGET')
    need(type(max_clock_skew_ms) is int and 0<=max_clock_skew_ms<=60000,'UPLOAD_SKEW')
    return planned_at_ms+30*DAY+max_upload_ms+max_clock_skew_ms

def verify_upload_retention(upload_ms, retain_until_ms, now):
    """Never accept a tolerance below 30 days; no retention mutations."""
    need(all(type(x) is int for x in (upload_ms,retain_until_ms,now)) and 0<upload_ms<=now<retain_until_ms,'UPLOAD_TIME')
    need(retain_until_ms>=upload_ms+30*DAY,'UPLOAD_RETENTION_SHORTFALL')
    return True
