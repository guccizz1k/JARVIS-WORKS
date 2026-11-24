import copy
import unittest
from scripts import jw_current_authz_proof_v223 as m
from scripts import jw_role_proof_v223 as role

def rr(n): return [n,False,True,False,False,False,False,False,-1]
def doc():
    names=[*m.SCOPE,"owner"]
    objects=m.object_rows([["schema",m.SCHEMA,"","owner",True,[]],
        ["relation:r","sample","","owner",False,[["owner",m.SCOPE[0],"SELECT",False]]]])
    return {"schema":"jw-current-authz-v1","scope":m.SCHEMA,
        "role_graph":role.graph([rr(n) for n in names],[],names),
        "objects":objects,"default_acl":[]}
class MetadataTest(unittest.TestCase):
    def test_pass_scoped_only(self):
        a=doc();r=m.compare(a,a,role.digest(a))
        self.assertEqual(r["current_scoped_metadata"],"PASS")
        self.assertFalse(r["activation_allowed"])
    def test_wrong_pin(self):
        a=doc()
        with self.assertRaises(role.Blocked): m.compare(a,a,"0"*64)
    def test_acl_mutation(self):
        a=doc();b=copy.deepcopy(a)
        next(x for x in b["objects"] if x[0]=="relation:r")[5][0][3]=True
        b["objects"]=m.object_rows(b["objects"])
        self.assertFalse(m.compare(a,b,role.digest(a))["equal"]["object_acl_sha256"])
    def test_owner_mutation(self):
        a=doc();b=copy.deepcopy(a);b["objects"][0][3]=m.SCOPE[0]
        b["objects"]=m.object_rows(b["objects"])
        self.assertFalse(m.compare(a,b,role.digest(a))["equal"]["owner_sha256"])
    def test_default_mutation(self):
        a=doc();b=copy.deepcopy(a);b["default_acl"]=m.default_rows([["owner",m.SCHEMA,"r",[]]])
        self.assertFalse(m.compare(a,b,role.digest(a))["equal"]["default_acl_sha256"])
    def test_null_distinction(self):
        a=doc();b=copy.deepcopy(a)
        next(x for x in b["objects"] if x[0]=="schema")[4]=False
        b["objects"]=m.object_rows(b["objects"])
        self.assertFalse(m.compare(a,b,role.digest(a))["equal"]["object_acl_sha256"])
    def test_duplicate(self):
        a=doc()["objects"]
        with self.assertRaises(role.Blocked): m.object_rows(a+[a[0]])
    def test_public_not_named_public(self):
        self.assertNotEqual(m.acl_entries([["owner",None,"SELECT",False]]),m.acl_entries([["owner","PUBLIC","SELECT",False]]))
    def test_scope_incomplete(self):
        a=doc();a["objects"][0][3]="missing";a["objects"]=m.object_rows(a["objects"])
        with self.assertRaises(role.Blocked): m.summary(a)
    def test_dsn_override_rejected(self):
        for q in ("sslmode=verify-full&sslrootcert=/ca&host=other","sslmode=verify-full&sslmode=disable"):
            with self.assertRaisesRegex(role.Blocked,"DSN_OPTIONS_DENIED"): m.source_options("postgresql://user@host/db?"+q,{})
    def test_missing_ack(self):
        with self.assertRaisesRegex(role.Blocked,"OWNER_READONLY_ACK_REQUIRED"): m.capture_current_source({})
    def test_source_endpoint_mismatch(self):
        want=dict(host="db."+("a"*20)+".supabase.co",port="5432",project_ref="a"*20,dbname="postgres",role="reader",schema_fingerprint="a"*32)
        with self.assertRaisesRegex(role.Blocked,"SOURCE_ENDPOINT_MISMATCH"):
            m.source_options("postgresql://reader@db."+("b"*20)+".supabase.co/postgres?sslmode=verify-full&sslrootcert=/ca",want)
