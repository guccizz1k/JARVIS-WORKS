import copy, hashlib, unittest
from datetime import datetime,timezone,timedelta
from types import SimpleNamespace
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import jw_role_proof_v223 as m

def role(n,superuser=False): return [n,superuser,True,False,False,False,False,False,-1]
ROLES=[role('app'),role('login'),role('reader'),role('postgres',True),role('unrelated')]
EDGES=[['app','login','postgres',False,True,True],['reader','app','postgres',False,True,True]]
def snapshot(): return m.graph(ROLES,EDGES,['app'])

class FakeCursor:
    def __init__(self,c): self.c=c;self.q=''
    def __enter__(self): return self
    def __exit__(self,*a): pass
    def execute(self,q):
        self.q=q;self.c.queries.append(q)
        if q.startswith('BEGIN'): self.c.info.transaction_status=2
        if q=='ROLLBACK': self.c.info.transaction_status=0
        if self.c.fail==q: raise RuntimeError('synthetic')
    def fetchone(self): return self.c.version,'on'
    def fetchall(self): return ROLES if self.q==m.ROLE_SQL else EDGES
class FakeConn:
    def __init__(self): self.autocommit=True;self.info=SimpleNamespace(transaction_status=0);self.queries=[];self.version=170011;self.fail=None
    def cursor(self): return FakeCursor(self)

class GraphTests(unittest.TestCase):
    def test_order(self): self.assertEqual(snapshot(),m.graph(ROLES[::-1],EDGES[::-1],['app']))
    def test_closure(self): self.assertEqual([r[0] for r in snapshot()['roles']],['app','login','postgres','reader'])
    def test_missing(self):
        with self.assertRaisesRegex(m.Blocked,'REQUIRED_ROLE_MISSING'): m.graph(ROLES,EDGES,['missing'])
    def test_duplicate_edge(self):
        with self.assertRaises(m.Blocked): m.graph(ROLES,EDGES+[EDGES[0]],['app'])
    def test_unknown_grantor(self):
        with self.assertRaises(m.Blocked): m.graph(ROLES,[['app','login','missing',False,True,True]],['app'])
    def test_bool_not_int(self):
        r=copy.deepcopy(ROLES);r[0][1]=0
        with self.assertRaises(m.Blocked): m.graph(r,EDGES,['app'])
    def test_pin(self):
        with self.assertRaisesRegex(m.Blocked,'SOURCE_PIN_MISMATCH'): m.compare(snapshot(),snapshot(),'0'*64)
    def test_pass_scope_only(self):
        x=snapshot();r=m.compare(x,x,m.digest(x));self.assertEqual(r['scoped_role_graph'],'PASS');self.assertEqual(r['overall'],'BLOCKED');self.assertFalse(r['activation_allowed'])
    def test_role_mutation(self):
        x=snapshot();y=copy.deepcopy(x);y['roles'][0][7]=True
        self.assertEqual(m.compare(x,y,m.digest(x))['scoped_role_graph'],'FAIL')
    def test_member_mutation(self):
        x=snapshot();y=copy.deepcopy(x);y['memberships'][0][-1]=False
        self.assertFalse(m.compare(x,y,m.digest(x))['membership_edges_equal'])
    def test_noncanonical(self):
        x=snapshot();y=copy.deepcopy(x);y['roles'].reverse()
        with self.assertRaises(m.Blocked): m.compare(x,y,m.digest(x))
    def test_capture(self):
        c=FakeConn();self.assertEqual(m.capture(c,['app']),snapshot());self.assertEqual(c.queries[-1],'ROLLBACK');self.assertNotIn('rolpassword',' '.join(c.queries));self.assertNotIn('pg_authid',' '.join(c.queries))
    def test_rollback_failure_path(self):
        c=FakeConn();c.fail=m.EDGE_SQL
        with self.assertRaises(RuntimeError): m.capture(c,['app'])
        self.assertEqual(c.queries[-1],'ROLLBACK')
    def test_pg_version(self):
        c=FakeConn();c.version=160000
        with self.assertRaises(m.Blocked): m.capture(c,['app'])
        self.assertEqual(c.queries[-1],'ROLLBACK')
    def test_busy_connection(self):
        c=FakeConn();c.info.transaction_status=2
        with self.assertRaises(m.Blocked): m.capture(c,['app'])
        self.assertEqual(c.queries,[])

class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.generate();self.pub=self.key.public_key().public_bytes_raw();self.now=datetime(2026,11,24,8,0,tzinfo=timezone.utc)
        self.p=dict(schema='jw-role-evidence-v1',purpose='current-scoped-role-graph',commit='1'*40,snapshot_sha256=m.digest(snapshot()),archive_scope_sha256='2'*64,challenge='3'*64,observed_at='2026-11-24T08:00:00Z')
        self.args=dict(public_key_pin=hashlib.sha256(self.pub).hexdigest(),expected_commit=self.p['commit'],expected_snapshot=self.p['snapshot_sha256'],expected_scope=self.p['archive_scope_sha256'],expected_challenge=self.p['challenge'],not_before=self.now-timedelta(minutes=5),now=self.now)
        self.sig=self.key.sign(m.evidence_message(self.p))
    def verify(self): return m.verify_attestation(self.p,self.sig,self.pub,**self.args)
    def test_valid_not_full_attestation(self):
        r=self.verify();self.assertEqual(r['pinned_signature'],'PASS');self.assertEqual(r['overall'],'BLOCKED');self.assertFalse(r['activation_allowed'])
    def test_wrong_key(self):
        self.pub=Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        with self.assertRaises(m.Blocked): self.verify()
    def test_signature_tampering(self):
        self.sig=bytes([self.sig[0]^1])+self.sig[1:]
        with self.assertRaises(m.Blocked): self.verify()
    def test_challenge_mismatch(self):
        self.args['expected_challenge']='4'*64
        with self.assertRaises(m.Blocked): self.verify()
    def test_expired(self):
        self.args['not_before']=self.now+timedelta(seconds=1)
        with self.assertRaises(m.Blocked): self.verify()
    def test_future(self):
        self.args['now']=self.now-timedelta(seconds=1)
        with self.assertRaises(m.Blocked): self.verify()
    def test_historical_claim_rejected(self):
        self.p['purpose']='historical-source'
        with self.assertRaises(m.Blocked): self.verify()
    def test_commit_substitution(self):
        self.args['expected_commit']='f'*40
        with self.assertRaises(m.Blocked): self.verify()
    def test_signed_payload_mutation(self):
        self.p['observed_at']='2026-11-24T07:59:59Z'
        with self.assertRaises(m.Blocked): self.verify()
if __name__=='__main__': unittest.main()
