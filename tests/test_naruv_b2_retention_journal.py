import copy,hashlib,json,unittest
from app.naruv_b2_retention_journal import reconcile,legal_hold_state,check_live_metadata,DAY,review_corrected_metadata,plan_upload_retention,verify_upload_retention

class TestJournal(unittest.TestCase):
 def setUp(self):
    self.ts=1795500000000;self.now=self.ts+1000;self.expected={};self.plan=[];self.rows=[]
    for i in range(22):
        n=f'backup-{i:02}';f=f'id-{i}';h=hashlib.sha256(n.encode()).hexdigest();old=self.ts+30*DAY-600;t=self.ts+30*DAY
        self.expected[n]={'file_id':f,'sha256':h,'retain_until_ms':old}
        self.plan.append(dict(name=n,id=f,old=old,target=t,upload_ms=self.ts,sha256=h))
        self.rows.append(dict(fileName=n,fileId=f,bucketId='b',action='upload',uploadTimestamp=self.ts,contentLength=10,contentSha1='a'*40,fileRetention={'isClientAuthorizedToRead':True,'value':{'mode':'compliance','retainUntilTimestamp':t}},serverSideEncryption={'mode':'SSE-B2','algorithm':'AES256'},legalHold={'isClientAuthorizedToRead':True,'value':None}))
    self.lines=[{'stage':'plan','items':self.plan}]+[dict(stage=s,**p) for p in self.plan for s in ('attempt','verified')]+[{'stage':'complete','verified':22,'shortfall_count':0}]
 def raw(self):return ('\n'.join(json.dumps(l) for l in self.lines)+'\n').encode()
 def run_reconcile(self):
    raw=self.raw();return reconcile(raw,hashlib.sha256(raw).hexdigest(),self.expected)
 def test_valid(self):
    orig=copy.deepcopy(self.expected);amended=self.run_reconcile();self.assertEqual(self.expected,orig);self.assertEqual(check_live_metadata(self.rows,amended,'b',self.now)['legal_hold']['unset'],22)
 def test_pin(self):
    with self.assertRaisesRegex(ValueError,'JOURNAL_PIN'):reconcile(self.raw(),'0'*64,self.expected)
 def test_partial(self):
    self.lines.pop(-2)
    with self.assertRaises(ValueError):self.run_reconcile()
 def test_receipt_binding(self):
    self.expected['backup-00']['sha256']='0'*64
    with self.assertRaisesRegex(ValueError,'ORIGINAL_RECEIPT_BINDING'):self.run_reconcile()
 def test_wrong_target(self):
    self.plan[0]['target']-=1
    with self.assertRaisesRegex(ValueError,'RETENTION_DELTA'):self.run_reconcile()
 def test_chain(self):
    self.lines[1]['id']='wrong'
    with self.assertRaisesRegex(ValueError,'JOURNAL_CHAIN'):self.run_reconcile()
 def test_duplicate_id(self):
    self.plan[1]['id']=self.plan[0]['id'];self.expected['backup-01']['file_id']=self.plan[0]['id']
    with self.assertRaisesRegex(ValueError,'PLAN_IDENTITY'):self.run_reconcile()
 def test_wrong_complete(self):
    self.lines[-1]['verified']=21
    with self.assertRaisesRegex(ValueError,'JOURNAL_COMPLETE'):self.run_reconcile()
 def test_duplicate_json_key(self):
    raw=self.raw().replace(b'"stage": "plan"',b'"stage": "plan", "stage": "plan"',1)
    with self.assertRaisesRegex(ValueError,'DUPLICATE_JSON_KEY'):reconcile(raw,hashlib.sha256(raw).hexdigest(),self.expected)
 def test_unknown_hold(self):
    for h in ({},{'isClientAuthorizedToRead':False,'value':None},{'isClientAuthorizedToRead':True},{'isClientAuthorizedToRead':True,'value':'bad'}):
        with self.subTest(h=h),self.assertRaisesRegex(ValueError,'HOLD_UNKNOWN'):legal_hold_state({'legalHold':h})
 def test_known_hold(self):
    for v in (None,'off','on'):
        self.assertEqual(legal_hold_state({'legalHold':{'isClientAuthorizedToRead':True,'value':v}}),'unset' if v is None else v)
 def test_live_drift(self):
    amended=self.run_reconcile();self.rows[0]['fileRetention']['value']['retainUntilTimestamp']-=1
    with self.assertRaisesRegex(ValueError,'LIVE_RETENTION'):check_live_metadata(self.rows,amended,'b',self.now)
 def test_live_duplicate(self):
    self.rows[1]=self.rows[0]
    with self.assertRaisesRegex(ValueError,'LIVE_IDENTITY'):check_live_metadata(self.rows,self.run_reconcile(),'b',self.now)
 def test_expired(self):
    with self.assertRaisesRegex(ValueError,'LIVE_RETENTION_TIME'):check_live_metadata(self.rows,self.run_reconcile(),'b',self.ts+30*DAY)
 def test_wrong_encryption(self):
    self.rows[0]['serverSideEncryption']={'mode':'none'}
    with self.assertRaisesRegex(ValueError,'LIVE_ENCRYPTION'):check_live_metadata(self.rows,self.run_reconcile(),'b',self.now)
 def test_review(self):
    raw=self.raw();pin=hashlib.sha256(raw).hexdigest()
    r=review_corrected_metadata(raw,pin,self.expected,self.rows,'b',self.now)
    self.assertEqual(r['metadata_verified'],22)
    self.assertFalse(r['ciphertext_reverified'])
    self.assertEqual(r['journal_sha256'],pin)
 def test_no_trust_on_partial(self):
    self.lines.pop(-2);raw=self.raw()
    with self.assertRaises(ValueError):review_corrected_metadata(raw,hashlib.sha256(raw).hexdigest(),self.expected,self.rows,'b',self.now)
 def test_upload_guard(self):
    t=1795500000000;end=plan_upload_retention(t,120000,60000)
    self.assertTrue(verify_upload_retention(t+180000,end,t+180000))
    with self.assertRaisesRegex(ValueError,'UPLOAD_RETENTION_SHORTFALL'):verify_upload_retention(t+180001,end,t+180001)
    with self.assertRaisesRegex(ValueError,'UPLOAD_RETENTION_SHORTFALL'):verify_upload_retention(t+572,t+30*DAY,t+572)
 def test_invalid(self):
    for a,b,c in ((True,1,0),(1,0,0),(1,120001,0),(1,1,60001),(1,1,True)):
        with self.subTest(a=a,b=b,c=c),self.assertRaises(ValueError):plan_upload_retention(a,b,c)
    for a,b,c in ((True,10,1),(2,10,1),(1,2,2)):
        with self.subTest(a=a,b=b,c=c),self.assertRaises(ValueError):verify_upload_retention(a,b,c)

if __name__=='__main__':unittest.main()
