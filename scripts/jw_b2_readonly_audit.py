"""Owner-only B2 audit. Existing receipts and pinned read-only API helpers; no mutations."""
import hashlib, json, os, re, resource, subprocess, sys
from pathlib import Path
from urllib.parse import urlencode

REF='32a4d4f4e77932c12eb1c189c166a28958f961b6:scripts/jw_b2_worm30.py'
BLOB='7c7cdf45bdb6feaea6843e0d6dea5b9c4db86a95'
GROUPS=(('jw-v223/approved-30d-20261124/','.jw-b2-worm30-20261124.jsonl','7b87c985452ee4d3a00049971380414ef436646516fa9d745ef878e267188147'),('jw-v223/rekey-30d-20261124/','.jw-b2-rekey-worm30-20261124.jsonl','d5c6d89f31487158630f6e3f18ce578248883cd95a7e2b0eaac0a38d365e5ee9'))
AUDIT=('JW_B2_AUDIT_KEY_ID','JW_B2_AUDIT_APPLICATION_KEY')
REQUIRED={'listBuckets','listFiles','readFiles','readFileRetentions','readBucketRetentions','readBucketEncryption'}
ALLOWED=REQUIRED|{'readFileLegalHolds','readBuckets','listAllBucketNames'}
DAY=86400000

def need(ok,code):
    if not ok: raise ValueError(code)

def sha(b): return hashlib.sha256(b).hexdigest()
def blob(b): return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def scope(ids): return sha(('JW-WORM-OWNER-SCOPE-V1\n'+'\n'.join(sorted(ids))+'\n').encode())

def parse_receipt(raw,prefix,pin):
    rows=[json.loads(line) for line in raw.splitlines()]
    need(len(rows)==34 and rows[-1]=={'stage':'complete','verified':11,'owner_scope_sha256':pin},'RECEIPT_COMPLETE')
    out={}
    for i in range(0,33,3):
        a,b,c=rows[i:i+3];name=c.get('name');fid=c.get('file_id');digest=c.get('sha256');until=c.get('retain_until_ms')
        need(type(name) is str and re.fullmatch(re.escape(prefix)+r'[a-f0-9]{40}\.jwpgbk',name) and name not in out,'RECEIPT_NAME')
        need(type(fid) is str and 0<len(fid)<=256 and type(digest) is str and re.fullmatch('[a-f0-9]{64}',digest) and type(until) is int and until>0,'RECEIPT_FIELDS')
        need(a=={'stage':'attempt','name':name,'sha256':digest,'retain_until_ms':until} and b=={'stage':'ack','name':name,'file_id':fid} and c=={'stage':'verified','name':name,'file_id':fid,'sha256':digest,'retain_until_ms':until},'RECEIPT_CHAIN')
        out[name]=c
    need(len({r['file_id'] for r in out.values()})==11 and scope([name[len(prefix):-7] for name in out])==pin,'RECEIPT_SCOPE')
    return out

def inspect_rows(rows,expected,bid,now):
    need(type(rows) is list and len(rows)==len(expected)==22,'INVENTORY_COUNT')
    seen=set();ids=set();short=0;hold_known=0
    for row in rows:
        name=row.get('fileName');fid=row.get('fileId');r=expected.get(name)
        need(r is not None and name not in seen and fid not in ids and fid==r['file_id'] and row.get('bucketId')==bid and row.get('action')=='upload','INVENTORY_IDENTITY')
        seen.add(name);ids.add(fid)
        n=row.get('contentLength');digest=row.get('contentSha1');ts=row.get('uploadTimestamp')
        need(type(n) is int and 0<n<=32*1024*1024 and type(digest) is str and re.fullmatch('[a-f0-9]{40}',digest) and type(ts) is int and 0<ts<=now,'INVENTORY_METADATA')
        lock=row.get('fileRetention',{});enc=row.get('serverSideEncryption',{});hold=row.get('legalHold',{})
        need(lock.get('isClientAuthorizedToRead') is True and lock.get('value')=={'mode':'compliance','retainUntilTimestamp':r['retain_until_ms']} and r['retain_until_ms']>now,'RETENTION_CHANGED_OR_EXPIRED')
        need(enc=={'mode':'SSE-B2','algorithm':'AES256'},'ENCRYPTION_METADATA')
        short+=int(r['retain_until_ms']-ts<30*DAY)
        hold_known+=int(hold.get('isClientAuthorizedToRead') is True and hold.get('value') in ('on','off'))
    return short,hold_known

def check_bytes(row,receipt,raw,headers):
    n=row['contentLength'];g=row['fileName'].split('/')[-1][:-7]
    need(len(raw)==n and hashlib.sha1(raw).hexdigest()==row['contentSha1'] and sha(raw)==receipt['sha256'] and blob(raw)==g,'CIPHERTEXT_MISMATCH')
    need(headers.get('X-Bz-File-Id')==row['fileId'] and headers.get('X-Bz-Content-Sha1')==row['contentSha1'] and headers.get('X-Bz-File-Retention-Mode')=='compliance' and headers.get('X-Bz-File-Retention-Retain-Until-Timestamp')==str(receipt['retain_until_ms']),'DOWNLOAD_METADATA')
    return g+':'+sha(raw)+':'+str(n)

def audit(engine,expected):
    a,s=engine['auth'](*(os.environ[x] for x in AUDIT));allowed=s['allowed'];caps=set(allowed['capabilities']);buckets=allowed['buckets']
    need(len(buckets)==1 and not allowed['namePrefix'] and REQUIRED<=caps<=ALLOWED and sha(buckets[0]['name'].encode())==engine['BUCKET_SHA256'],'AUDIT_SCOPE')
    bid=buckets[0]['id'];bs=engine['call'](a,s,'b2_list_buckets',{'accountId':a['accountId'],'bucketId':bid})['buckets']
    need(len(bs)==1 and bs[0]['bucketId']==bid and bs[0]['bucketName']==buckets[0]['name'] and bs[0]['bucketType']=='allPrivate' and bs[0]['fileLockConfiguration']['value']['isFileLockEnabled'] is True and bs[0]['defaultServerSideEncryption']['value']['mode']=='SSE-B2','BUCKET_SECURITY')
    rows=engine['inventory'](a,s,bid);short,known=inspect_rows(rows,expected,bid,engine['now']());records=[[],[]]
    fields=('fileName','fileId','bucketId','action','contentLength','contentSha1','fileRetention','serverSideEncryption','legalHold','uploadTimestamp')
    for row in rows:
        name=row['fileName'];r=expected[name];fid=row['fileId'];info=engine['call'](a,s,'b2_get_file_info',{'fileId':fid})
        need(all(row.get(k)==info.get(k) for k in fields),'FILE_INFO_DRIFT')
        url=s['downloadUrl']+'/b2api/v4/b2_download_file_by_id?'+urlencode({'fileId':fid})
        raw,h=engine['response'](url,a['authorizationToken'],limit=row['contentLength'])
        record=check_bytes(row,r,raw,h);records[int(name.startswith(GROUPS[1][0]))].append(record)
    after=engine['inventory'](a,s,bid);need(rows==after,'INVENTORY_DRIFT');inspect_rows(after,expected,bid,engine['now']())
    need(all(len(r)==11 for r in records),'GROUP_COUNT')
    agg=lambda r:sha(('NARUV_REKEY_VAULT_READBACK_V1\n'+'\n'.join(sorted(r))+'\n').encode())
    return {'scope':'B2_CIPHERTEXT_READBACK_ONLY','verified':22,'compliance_active':22,'sse_b2':22,'strict_30day_shortfall_count':short,'legal_hold_known_count':known,'original_aggregate_sha256':agg(records[0]),'rekey_aggregate_sha256':agg(records[1]),'restore_verified':False,'key_custody_verified':False,'production_authorized':False}

def main():
    os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    need(os.environ.get('CODESPACES','').lower()=='true','OWNER_CODESPACE_REQUIRED')
    need(all(os.environ.get(x) for x in AUDIT),'AUDIT_CREDENTIALS_REQUIRED')
    env={k:v for k,v in os.environ.items() if k in ('HOME','PATH','LANG','CODESPACES',*AUDIT)}
    os.environ.clear();os.environ.update(env)
    git_env={k:v for k,v in env.items() if k in ('HOME','PATH','LANG')};git_env['GIT_NO_REPLACE_OBJECTS']='1';git_env['GIT_TERMINAL_PROMPT']='0'
    raw=subprocess.check_output(['git','show',REF],env=git_env,stdin=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
    need(blob(raw)==BLOB,'ENGINE_PIN');engine={'__name__':'pinned_b2_readonly'};exec(compile(raw,'pinned_b2_readonly','exec'),engine)
    expected={}
    for prefix,path,pin in GROUPS: expected.update(parse_receipt(engine['secure_read'](Path.home()/path,65536),prefix,pin))
    need(len(expected)==22 and len({v['file_id'] for v in expected.values()})==22,'GROUP_SCOPE')
    result=audit(engine,expected);print(json.dumps(result,sort_keys=True),flush=True)
    return 0 if result['strict_30day_shortfall_count']==0 and result['legal_hold_known_count']==22 else 2

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as e:
        code=str(e) if type(e) is ValueError and re.fullmatch('[A-Z_]{3,80}',str(e)) else type(e).__name__
        print('BLOCKED',code,'NO_REMOTE_WRITE',file=sys.stderr);sys.exit(1)
