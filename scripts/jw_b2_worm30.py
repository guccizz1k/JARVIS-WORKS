import base64, hashlib, json, os, re, stat, subprocess, sys, time, resource
from pathlib import Path
from urllib import request, parse, error
from email.utils import parsedate_to_datetime

PIN='7b87c985452ee4d3a00049971380414ef436646516fa9d745ef878e267188147'
REF='6a386772fe49b4fbfa7a8a0c0aaf352f6a665748:scripts/p1_b2_preupload_integrity_v223.py'
BLOB='c53fd0ead6c6a1f429d8c5520d411eb69b930a1e'
BUCKET_SHA256='818b599eca5772d820b2b04ba3e192b5e40688fb9a715b4b1082d7b5aed2be5c'
PREFIX='jw-v223/approved-30d-20261124/'
CAPS={'writeFiles','writeFileRetentions'}
DAY=86400000
LIMIT=32*1024*1024
KEY=Path.home()/'.jw-b2-writer-20261124.json'
LOG=Path.home()/'.jw-b2-worm30-20261124.jsonl'
AUDIT=('JW_B2_AUDIT_KEY_ID','JW_B2_AUDIT_APPLICATION_KEY')

def check(ok,code):
    if not ok: raise ValueError(code)

def gitsha(b): return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def sha(b): return hashlib.sha256(b).hexdigest()
def now(): return int(time.time()*1000)

def secure_read(p,limit):
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno())
        check(stat.S_ISREG(a.st_mode) and stat.S_IMODE(a.st_mode)==0o600 and a.st_uid==os.getuid() and 0<a.st_size<=limit,'PRIVATE_FILE')
        b=f.read(limit+1); z=os.fstat(f.fileno())
        check(len(b)==a.st_size and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns),'FILE_CHANGED')
    return b

class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self,*a,**kw): return None
OP=request.build_opener(request.ProxyHandler({}),NoRedirect())

def safe_url(url,kind):
    p=parse.urlsplit(url)
    check(p.scheme=='https' and not p.username and not p.password and p.port is None and not p.fragment,'URL_SCHEME')
    if kind=='upload':
        check(re.fullmatch(r'pod-[0-9-]+\.backblaze(?:b2)?\.com',p.hostname or '') and re.fullmatch(r'/b2api/v[1-4]/b2_upload_file(?:/[^?#]*)?',p.path),'UPLOAD_ENDPOINT')
    else:
        check(re.fullmatch(r'(?:api[0-9]*|f[0-9]+)\.backblazeb2\.com',p.hostname or '') and re.fullmatch(r'/b2api/v4/b2_[a-z_]+',p.path),'API_ENDPOINT')
    return url

def response(url,token,data=None,headers=None,limit=1048576,kind='api'):
    h={'Authorization':token}; h.update(headers or {})
    if isinstance(data,dict): data=json.dumps(data).encode(); h['Content-Type']='application/json'
    with OP.open(request.Request(safe_url(url,kind),data=data,headers=h),timeout=45) as r:
        b=r.read(limit+1); check(len(b)<=limit,'RESPONSE_LIMIT'); return b,r.headers

def js(url,token,data=None,headers=None,kind='api'):
    return json.loads(response(url,token,data,headers,kind=kind)[0])

def auth(i,k):
    raw,h=response('https://api.backblazeb2.com/b2api/v4/b2_authorize_account','Basic '+base64.b64encode((i+':'+k).encode()).decode())
    check(abs(now()-int(parsedate_to_datetime(h['Date']).timestamp()*1000))<=60000,'SERVER_CLOCK_SKEW')
    a=json.loads(raw); s=a['apiInfo']['storageApi']; return a,s

def call(a,s,method,params): return js(s['apiUrl']+'/b2api/v4/'+method,a['authorizationToken'],params)

def inventory(a,s,bid):
    v=call(a,s,'b2_list_file_versions',{'bucketId':bid,'maxFileCount':100})
    check(v['nextFileName'] is None and v['nextFileId'] is None and isinstance(v['files'],list),'INVENTORY_INCOMPLETE')
    return v['files']

def receipt(f,entry):
    f.write(json.dumps(entry,separators=(',',':'))+'\n'); f.flush(); os.fsync(f.fileno())

def upload_batch(raws,writer,ws,audit,rs,bid,log):
    check(len(raws)==11 and all(gitsha(raw)==blob for blob,raw in raws.items()),'BATCH_SCOPE')
    check(inventory(audit,rs,bid)==[],'BUCKET_NOT_EMPTY_NO_RETRY')
    result={}
    for blob,raw in sorted(raws.items()):
        check(now()+120000<writer['applicationKeyExpirationTimestamp'],'WRITER_EXPIRING')
        name=PREFIX+blob+'.jwpgbk'; digest=sha(raw); content_sha1=hashlib.sha1(raw).hexdigest()
        u=call(writer,ws,'b2_get_upload_url',{'bucketId':bid})
        check(u['bucketId']==bid,'UPLOAD_BUCKET')
        target=parse.urlsplit(safe_url(u['uploadUrl'],'upload'))
        path_parts=target.path.split('/')
        query_bucket=parse.parse_qs(target.query).get('bucket',[])
        check((len(path_parts)>=6 and path_parts[4]==bid and (not query_bucket or query_bucket==[bid])) or (len(path_parts)==4 and query_bucket==[bid]),'UPLOAD_BUCKET_URL')
        until=now()+30*DAY
        h={'Content-Type':'application/octet-stream','Content-Length':str(len(raw)),'X-Bz-File-Name':parse.quote(name,safe='/'),'X-Bz-Content-Sha1':content_sha1,'X-Bz-File-Retention-Mode':'compliance','X-Bz-File-Retention-Retain-Until-Timestamp':str(until),'X-Bz-Server-Side-Encryption':'AES256'}
        receipt(log,{'stage':'attempt','name':name,'sha256':digest,'retain_until_ms':until})
        up=js(u['uploadUrl'],u['authorizationToken'],raw,h,kind='upload')
        fid=up['fileId']; check(isinstance(fid,str) and bool(fid),'FILE_ID')
        receipt(log,{'stage':'ack','name':name,'file_id':fid})
        check(up['fileName']==name and up['bucketId']==bid and up['contentSha1']==content_sha1 and str(up['contentLength'])==str(len(raw)),'UPLOAD_RESPONSE')
        info=call(audit,rs,'b2_get_file_info',{'fileId':fid})
        lock=info['fileRetention']; enc=info['serverSideEncryption']
        check(info['fileId']==fid and info['fileName']==name and info['bucketId']==bid and info['action']=='upload' and info['contentSha1']==content_sha1 and str(info['contentLength'])==str(len(raw)),'INFO_IDENTITY')
        check(lock['isClientAuthorizedToRead'] is True and lock['value']['mode']=='compliance' and int(lock['value']['retainUntilTimestamp'])==until and abs(until-int(info['uploadTimestamp'])-30*DAY)<=120000,'RETENTION_NOT_PROVEN')
        check(enc['mode']=='SSE-B2' and enc['algorithm']=='AES256','ENCRYPTION_NOT_PROVEN')
        url=rs['downloadUrl']+'/b2api/v4/b2_download_file_by_id?'+parse.urlencode({'fileId':fid})
        got,dh=response(url,audit['authorizationToken'],limit=len(raw))
        check(got==raw and sha(got)==digest and gitsha(got)==blob and dh.get('X-Bz-File-Id')==fid and dh.get('X-Bz-Content-Sha1')==content_sha1,'REMOTE_BYTES_MISMATCH')
        check(dh.get('X-Bz-File-Retention-Mode')=='compliance' and int(dh.get('X-Bz-File-Retention-Retain-Until-Timestamp','0'))==until,'DOWNLOAD_RETENTION')
        check(fid not in result.values(),'DUPLICATE_VERSION')
        result[name]=fid
        receipt(log,{'stage':'verified','name':name,'file_id':fid,'sha256':digest,'retain_until_ms':until})
        print('VERIFIED',len(result),'/11',flush=True)
    inv=inventory(audit,rs,bid)
    check(len(inv)==len(result)==11 and all(x['action']=='upload' and x['bucketId']==bid and result.get(x['fileName'])==x['fileId'] for x in inv) and len({x['fileName'] for x in inv})==11,'FINAL_INVENTORY')
    receipt(log,{'stage':'complete','verified':11,'owner_scope_sha256':PIN})

def worker(payload):
    check(gitsha(payload['source'].encode())==BLOB,'PREUPLOAD_CODE_CHANGED')
    expected=payload['expected']
    check(len(expected)==11 and sha(('JW-WORM-OWNER-SCOPE-V1\n'+'\n'.join(sorted(expected))+'\n').encode())==PIN,'PIN')
    d={'__name__':'audit'}; exec(payload['source'],d)
    check(d['_local_files']()==expected,'SOURCE_CHANGED')
    root=Path.home()/d['ROOT_REL']; raws={}
    paths=list(root.glob('*.jwpgbk'))
    for sub in root.glob('jw_v223_*'):
        if d['_private_dir'](sub): paths.extend(sub.glob('*.jwpgbk'))
    total=0
    for p in paths:
        raw=secure_read(p,LIMIT); g=gitsha(raw); total+=len(raw)
        check(total<=128*1024*1024,'SNAPSHOT_SIZE')
        check(g not in raws and expected.get(g)==sha(raw) and raw[:8] in d['MAGIC'],'SNAPSHOT_MISMATCH'); raws[g]=raw
    check(set(raws)==set(expected) and len(raws)==11 and sum(map(len,raws.values()))<=128*1024*1024,'SNAPSHOT_SCOPE')
    key=json.loads(secure_read(KEY,4096)); w,ws=auth(key['applicationKeyId'],key['applicationKey'])
    check(w['applicationKeyExpirationTimestamp']==key['expirationTimestamp'],'WRITER_EXPIRY_CHANGED'); del key
    a,rs=auth(*(os.environ[x] for x in AUDIT))
    wa=ws['allowed']; ra=rs['allowed']; buckets=wa['buckets']
    check(len(buckets)==1 and sha(buckets[0]['name'].encode())==BUCKET_SHA256 and wa['namePrefix']==PREFIX and set(wa['capabilities'])==CAPS,'WRITER_SCOPE')
    check(now()+120000<w['applicationKeyExpirationTimestamp']<=now()+3600000,'WRITER_EXPIRY')
    bid=buckets[0]['id']; rc=set(ra['capabilities'])
    check(a['accountId']==w['accountId'] and ra['buckets']==buckets and not ra['namePrefix'] and {'listBuckets','listFiles','readFiles','readFileRetentions','readBucketRetentions','readBucketEncryption'}<=rc and not any(x.startswith(('write','delete')) or x=='bypassGovernance' for x in rc),'AUDIT_SCOPE')
    b=call(a,rs,'b2_list_buckets',{'accountId':a['accountId'],'bucketId':bid})['buckets']
    check(len(b)==1 and b[0]['bucketId']==bid and b[0]['bucketName']==buckets[0]['name'] and sha(b[0]['bucketName'].encode())==BUCKET_SHA256 and b[0]['bucketType']=='allPrivate' and b[0]['fileLockConfiguration']['value']['isFileLockEnabled'] is True and b[0]['defaultServerSideEncryption']['value']['mode']=='SSE-B2','BUCKET_SECURITY')
    fd=os.open(LOG,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f: upload_batch(raws,w,ws,a,rs,bid,f)
    print('B2_WORM30_PASS verified=11 upload_versions=11 recovery_key_accessed=false',flush=True)

def parent():
    check(os.environ.get('CODESPACES','').lower()=='true','OWNER_CODESPACE_REQUIRED')
    check(not os.path.lexists(LOG),'PRIOR_ATTEMPT_RECONCILIATION_REQUIRED')
    env={'HOME':str(Path.home()),'PATH':'/usr/local/bin:/usr/bin:/bin','LANG':'C.UTF-8','GIT_TERMINAL_PROMPT':'0'}
    source=subprocess.check_output(['git','show',REF],env=env,timeout=15)
    check(gitsha(source)==BLOB,'PREUPLOAD_CODE_CHANGED')
    d={'__name__':'audit'}; exec(source,d)
    local=d['_local_files'](); info=d['_verify_remote'](local,pinned_scope_digest=PIN)
    check(info['owner_scope_digest']==PIN and info['verified_archive_count']==11,'PIN')
    child=dict(env,**{x:os.environ[x] for x in AUDIT})
    # Separate process receives only the B2 audit credentials and verified source hashes.
    p=subprocess.run([sys.executable,'-I','-S',__file__,'worker'],input=json.dumps({'source':source.decode(),'expected':local}),text=True,env=child)
    return p.returncode

if __name__=='__main__':
    os.umask(0o077); resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    try:
        if sys.argv[1:]==['worker']: worker(json.load(sys.stdin))
        elif sys.argv[1:]==['run']: raise SystemExit(parent())
        else: raise ValueError('MODE')
    except error.HTTPError as e:
        print('BLOCKED_HTTP',e.code,'NO_AUTO_RETRY',flush=True); raise SystemExit(1)
    except Exception as e:
        # Only fixed internal codes; no provider response or credentials.
        code=str(e) if type(e) is ValueError and re.fullmatch(r'[A-Z0-9_]{1,80}',str(e)) else type(e).__name__
        print('BLOCKED',code,'NO_AUTO_RETRY',flush=True); raise SystemExit(1)
