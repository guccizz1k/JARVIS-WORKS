import contextlib, hashlib, hmac, json, re, sys, types, unittest
from pathlib import Path
class HTTPException(Exception):
    def __init__(self,status_code,detail): self.status_code=status_code; self.detail=detail
class MappingBlocked(Exception): pass
class DBError(Exception): pass
sys.modules['psycopg']=types.SimpleNamespace(Error=DBError)
RAW=b'sku,item_name,unit\n002,Bolt,EA\n'
ROWS=[{'id':'002'}]
CANON=json.dumps(ROWS,ensure_ascii=False,sort_keys=True,separators=(',',':'))
DIGEST=('d'*64,hashlib.sha256(CANON.encode()).hexdigest(),'s'*64)
class Test(unittest.TestCase):
    def setUp(self):
        self.active=False; self.phase=0; self.events=[]; self.mode='normal'; self.args=None
        self.ns=dict(HTTPException=HTTPException,MappingBlocked=MappingBlocked,hashlib=hashlib,hmac=hmac,json=json,re=re,_ingest_cursor=self.cursor,make_target_snapshot=self.target,prepare_file_stage=self.prepare,_db_error=lambda e:HTTPException(409,'NARUV_TARGET_CHANGED'))
        exec(compile(Path(__file__).with_name('candidate.py').read_text(),'candidate.py','exec'),self.ns)
    @contextlib.contextmanager
    def cursor(self,token,csrf,prior):
        self.assertFalse(self.active); self.assertEqual((token,csrf,prior),('token','csrf',('actor','org')))
        self.phase+=1
        if self.phase==2 and self.mode=='revoked': raise HTTPException(401,'SESSION_INVALID')
        self.active=True; self.events.append('enter'+str(self.phase))
        try: yield self,'other' if self.phase==2 and self.mode=='org' else 'org'
        finally: self.active=False;self.events.append('exit'+str(self.phase))
    def execute(self,q,args):
        self.assertTrue(self.active)
        if 'read_source' in q: self.assertEqual(self.phase,1);self.events.append('read')
        elif 'store_stage' in q:
            self.assertEqual(self.phase,2); self.events.append('store');self.args=args
            if self.mode=='drift': raise DBError()
        else: self.fail('unknown SQL')
    def fetchone(self):
        if self.phase==1: return None if self.mode=='missing' else ('revision',['001'])
        return ('BAD',) if self.mode=='badstatus' else ('ALREADY_STAGED' if self.mode=='replay' else 'STAGED',)
    def target(self,org,source,entity,revision,ids):
        self.assertFalse(self.active); self.assertEqual((org,source,entity,revision,ids),('org','source','item','revision',['001']))
        return types.SimpleNamespace(snapshot_sha256='s'*64,revision=revision,existing_source_ids=ids)
    def prepare(self,raw,**kwargs):
        self.assertFalse(self.active);self.events.append('parse');self.assertEqual(raw,RAW)
        if self.mode=='parse_error':raise MappingBlocked('FILE_INVALID')
        return types.SimpleNamespace(stage_sha256='d'*64,canonical_rows=ROWS,raw_sha256='r'*64,byte_count=len(raw),preflight=types.SimpleNamespace(rows_sha256='p'*64,row_count=1))
    def call(self,digests=DIGEST):return self.ns['_stage']('token','csrf',('actor','org'),'source','item','csv','stage',digests,RAW)
    def reject(self,mode,status,detail,stored=False):
        self.mode=mode
        with self.assertRaises(HTTPException) as err:self.call()
        self.assertEqual((err.exception.status_code,err.exception.detail),(status,detail));self.assertFalse(self.active);self.assertEqual('store' in self.events,stored)
    def test_normal(self):
        result=self.call();self.assertEqual(self.events,['enter1','read','exit1','parse','enter2','store','exit2']);self.assertEqual(result['status'],'STAGED');self.assertFalse(result['row_import_authorized']);self.assertEqual(self.args[-4:],('revision',['001'],CANON,'csrf'))
    def test_replay(self):self.mode='replay';self.assertEqual(self.call()['status'],'ALREADY_STAGED')
    def test_revoked(self):self.reject('revoked',401,'SESSION_INVALID')
    def test_scope(self):self.reject('org',409,'SESSION_SCOPE_CHANGED')
    def test_drift(self):self.reject('drift',409,'NARUV_TARGET_CHANGED',True)
    def test_missing(self):self.reject('missing',404,'SOURCE_NOT_FOUND')
    def test_parse(self):self.reject('parse_error',422,'FILE_INVALID')
    def test_bad_status(self):self.reject('badstatus',503,'NARUV_TRANSACTION_UNAVAILABLE',True)
    def test_wrong_digest(self):
        with self.assertRaises(HTTPException) as err:self.call(('x'*64,*DIGEST[1:]))
        self.assertEqual(err.exception.status_code,409);self.assertEqual(self.phase,1)
    def test_wrong_canonical(self):
        with self.assertRaises(HTTPException) as err:self.call((DIGEST[0],'x'*64,DIGEST[2]))
        self.assertEqual(err.exception.status_code,409);self.assertEqual(self.phase,1)
    def test_wrong_snapshot(self):
        with self.assertRaises(HTTPException) as err:self.call((*DIGEST[:2],'x'*64))
        self.assertEqual(err.exception.status_code,409);self.assertEqual(self.phase,1)
if __name__=='__main__':unittest.main(verbosity=2)
