"""Independent scoped PG17 authorization catalog comparison (read-only).
No passwords, credential values, raw role names or ACLs leave the SQL probe.
This is NOT an ACL-restoration engine and cannot attest historical global roles
from a schema-only dump. A normalized restore is never admissible here.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import re
from scripts import jw_independent_equivalence_v223 as eq

FORMAT='JW-PG17-AUTHORIZATION-REFERENCE-V3'
ALGORITHM='JW-PG17-AUTHZ-JSONB-C-SHA256-V1'
SECTIONS=('owners','object_acl','column_acl','default_acl','role_attributes','role_memberships','role_settings','database_acl')
MAX_JSON=65536
MAX_COUNT=100000
SQL=r'''
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL search_path=pg_catalog;
SET LOCAL statement_timeout='40s';
SET LOCAL lock_timeout='2s';
SET LOCAL TimeZone='UTC';
SET LOCAL DateStyle='ISO, YMD';
WITH ns AS (SELECT * FROM pg_namespace WHERE nspname='jw_dev'),
obj(kind,identity,owner,acl,aclkind) AS (
 SELECT 'schema',jsonb_build_array(n.nspname),n.nspowner,n.nspacl,'n'::"char" FROM ns n
 UNION ALL SELECT 'relation',jsonb_build_array(c.relname,c.relkind),c.relowner,c.relacl,
   CASE WHEN c.relkind='S' THEN 's'::"char" ELSE 'r'::"char" END
 FROM pg_class c JOIN ns n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p','v','m','S','f')
 UNION ALL SELECT 'routine',jsonb_build_array(p.proname,pg_get_function_identity_arguments(p.oid)),p.proowner,p.proacl,'f'::"char"
 FROM pg_proc p JOIN ns n ON n.oid=p.pronamespace
 UNION ALL SELECT 'type',jsonb_build_array(t.typname,t.typtype),t.typowner,t.typacl,'T'::"char"
 FROM pg_type t JOIN ns n ON n.oid=t.typnamespace WHERE t.typisdefined
), entries(section,item) AS (
 SELECT 'owners',jsonb_build_array(kind,identity,pg_get_userbyid(owner)) FROM obj
 UNION ALL SELECT 'object_acl',jsonb_build_array(o.kind,o.identity,o.acl IS NULL,
   CASE WHEN a.grantor IS NULL THEN NULL ELSE pg_get_userbyid(a.grantor) END,
   CASE WHEN a.grantee=0 THEN NULL ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable)
 FROM obj o LEFT JOIN LATERAL aclexplode(coalesce(o.acl,acldefault(o.aclkind,o.owner))) a ON true
 UNION ALL SELECT 'column_acl',jsonb_build_array(c.relname,at.attname,at.attacl IS NULL,
   CASE WHEN a.grantor IS NULL THEN NULL ELSE pg_get_userbyid(a.grantor) END,
   CASE WHEN a.grantee=0 THEN NULL ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable)
 FROM pg_class c JOIN ns n ON n.oid=c.relnamespace JOIN pg_attribute at ON at.attrelid=c.oid
 LEFT JOIN LATERAL aclexplode(at.attacl) a ON true
 WHERE c.relkind IN ('r','p','v','m','f') AND at.attnum>0 AND NOT at.attisdropped
 UNION ALL SELECT 'default_acl',jsonb_build_array(pg_get_userbyid(d.defaclrole),d.defaclnamespace=0,d.defaclobjtype,
   CASE WHEN a.grantor IS NULL THEN NULL ELSE pg_get_userbyid(a.grantor) END,
   CASE WHEN a.grantee=0 THEN NULL ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable)
 FROM pg_default_acl d LEFT JOIN LATERAL aclexplode(d.defaclacl) a ON true
 WHERE d.defaclnamespace=0 OR d.defaclnamespace IN (SELECT oid FROM ns)
 UNION ALL SELECT 'role_attributes',jsonb_build_array(r.rolname,r.rolsuper,r.rolinherit,r.rolcreaterole,
   r.rolcreatedb,r.rolcanlogin,r.rolreplication,r.rolbypassrls,r.rolconnlimit,r.rolvaliduntil)
 FROM pg_roles r
 UNION ALL SELECT 'role_memberships',jsonb_build_array(pg_get_userbyid(m.roleid),pg_get_userbyid(m.member),
   pg_get_userbyid(m.grantor),m.admin_option,m.inherit_option,m.set_option) FROM pg_auth_members m
 UNION ALL SELECT 'role_settings',jsonb_build_array(s.setdatabase=0,CASE WHEN s.setrole=0 THEN NULL ELSE pg_get_userbyid(s.setrole) END,
   (SELECT coalesce(jsonb_agg(v ORDER BY v COLLATE "C"),'[]'::jsonb) FROM unnest(s.setconfig) v))
 FROM pg_db_role_setting s WHERE s.setdatabase=0 OR s.setdatabase=(SELECT oid FROM pg_database WHERE datname=current_database())
 UNION ALL SELECT 'database_acl',jsonb_build_array(pg_get_userbyid(d.datdba),d.datacl IS NULL,d.datallowconn,d.datconnlimit,
   CASE WHEN a.grantor IS NULL THEN NULL ELSE pg_get_userbyid(a.grantor) END,
   CASE WHEN a.grantee=0 THEN NULL ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable)
 FROM pg_database d LEFT JOIN LATERAL aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a ON true
 WHERE d.datname=current_database()
), sections(section) AS (VALUES ('owners'),('object_acl'),('column_acl'),('default_acl'),('role_attributes'),('role_memberships'),('role_settings'),('database_acl')),
 summaries AS (SELECT s.section,count(e.item) n,CASE WHEN count(e.item)<=100000 THEN
 encode(sha256(convert_to(coalesce(jsonb_agg(e.item ORDER BY e.item::text COLLATE "C") FILTER (WHERE e.item IS NOT NULL),'[]'::jsonb)::text,'UTF8')),'hex') END digest
 FROM sections s LEFT JOIN entries e USING(section) GROUP BY s.section)
SELECT jsonb_object_agg(section,jsonb_build_array(n,digest)) FROM summaries;
ROLLBACK;
'''

def parse_sections(doc):
    eq.require(type(doc) is dict and set(doc)==set(SECTIONS),'AUTHZ_SECTION_SET')
    out={}
    for k in SECTIONS:
        v=doc[k]
        eq.require(type(v) in (list,tuple) and len(v)==2 and type(v[0]) is int and 0<=v[0]<=MAX_COUNT and eq.valid_hex(v[1]),'AUTHZ_SECTION_INVALID')
        out[k]=tuple(v)
    for k in ('owners','object_acl','column_acl'):
        eq.require(out[k][0]>=eq.TABLES,'AUTHZ_SCHEMA_SCOPE')
    eq.require(out['role_attributes'][0]>0 and out['database_acl'][0]>0,'AUTHZ_GLOBAL_SCOPE')
    return out

def probe(exec_fn, container, db):
    eq.require(eq.valid_hex(container) and type(db) is str and re.fullmatch(r'jw_p1_offline_(?:[0-9]|10)',db) is not None,'AUTHZ_TARGET_INVALID')
    try:
        r=exec_fn(container,['psql','-X','-qAt','-U','postgres','-d',db,'-v','ON_ERROR_STOP=1','-c',SQL],timeout=50)
        eq.require(r.returncode==0 and type(r.stdout) is bytes and 0<len(r.stdout)<=16384,'AUTHZ_PROBE_FAILED')
        return parse_sections(json.loads(r.stdout.decode('ascii'),object_pairs_hook=eq.no_duplicates,parse_constant=eq.reject_constant))
    except eq.Blocked: raise
    except Exception: raise eq.Blocked('AUTHZ_PROBE_FAILED') from None

def load_reference(raw, *, expected_sha, vault, scope, pairs):
    eq.require(type(raw) is bytes and 0<len(raw)<=MAX_JSON,'AUTHZ_REFERENCE_SIZE')
    eq.require(eq.valid_hex(expected_sha) and hmac.compare_digest(hashlib.sha256(raw).hexdigest(),expected_sha),'AUTHZ_REFERENCE_PIN')
    eq.require(eq.valid_hex(vault,eq.GIT) and eq.valid_hex(scope),'AUTHZ_SCOPE_PIN')
    try: doc=json.loads(raw.decode('ascii'),object_pairs_hook=eq.no_duplicates,parse_constant=eq.reject_constant)
    except eq.Blocked: raise
    except Exception: raise eq.Blocked('AUTHZ_REFERENCE_JSON') from None
    eq.require(type(doc) is dict and set(doc)=={'format','algorithm','vault','scope','archives'},'AUTHZ_REFERENCE_FIELDS')
    eq.require(doc['format']==FORMAT and doc['algorithm']==ALGORITHM and doc['vault']==vault and doc['scope']==scope,'AUTHZ_REFERENCE_SCOPE')
    eq.require(type(pairs) in (tuple,list) and len(pairs)==eq.COUNT and all(type(x) in (tuple,list) and len(x)==2 and eq.valid_hex(x[0],eq.GIT) and eq.valid_hex(x[1]) for x in pairs),'AUTHZ_PROVIDER_PAIRS')
    expected=dict(pairs)
    eq.require(len(expected)==eq.COUNT and len(set(expected.values()))==eq.COUNT and hmac.compare_digest(eq.owner_scope(expected),scope),'AUTHZ_PROVIDER_SCOPE')
    eq.require(type(doc['archives']) is list and len(doc['archives'])==eq.COUNT,'AUTHZ_REFERENCE_COUNT')
    refs={}
    for x in doc['archives']:
        eq.require(type(x) is dict and set(x)=={'blob','cipher','sections'},'AUTHZ_ARCHIVE_FIELDS')
        b,c=x['blob'],x['cipher']
        eq.require(eq.valid_hex(b,eq.GIT) and b in expected and b not in refs and eq.valid_hex(c) and hmac.compare_digest(c,expected[b]),'AUTHZ_ARCHIVE_IDENTITY')
        refs[b]=(c,parse_sections(x['sections']))
    return refs

class AuthorizationComparison:
    """Checkpoint comparison only. Not trusted attestation of probe or restore.
    Not wired to the existing normalized restore, which strips ACLs/ownership.
    """
    def __init__(self, refs):
        eq.require(type(refs) is dict and len(refs)==eq.COUNT,'AUTHZ_REFERENCE_COUNT')
        self.refs={}
        for b,v in refs.items():
            eq.require(eq.valid_hex(b,eq.GIT) and type(v) is tuple and len(v)==2 and eq.valid_hex(v[0]),'AUTHZ_ARCHIVE_IDENTITY')
            self.refs[b]=(v[0],parse_sections(v[1]))
        eq.require(len({v[0] for v in self.refs.values()})==eq.COUNT,'AUTHZ_ARCHIVE_IDENTITY')
        self.done=set(); self.failed=False
    def compare(self,blob,cipher,observed):
        try:
            eq.require(not self.failed and eq.valid_hex(blob,eq.GIT) and blob in self.refs and blob not in self.done,'AUTHZ_REPLAY_OR_FAILED')
            target,sections=self.refs[blob]
            eq.require(eq.valid_hex(cipher) and hmac.compare_digest(target,cipher),'AUTHZ_CIPHER_MISMATCH')
            actual=parse_sections(observed)
            for k in SECTIONS:
                eq.require(actual[k][0]==sections[k][0] and hmac.compare_digest(actual[k][1],sections[k][1]),'AUTHZ_'+k.upper()+'_MISMATCH')
            self.done.add(blob)
        except BaseException:
            self.failed=True; raise
    def receipt(self,*,cleanup):
        complete=not self.failed and len(self.done)==eq.COUNT and cleanup=='PASS'
        return {'scoped_authorization_checkpoint_comparison':'PASS_11_SCOPED_AUTHZ_CHECKPOINTS' if complete else 'BLOCKED',
                'matched_archives':len(self.done),'original_owner_acl_equivalence':'NOT_ATTESTED',
                'original_role_membership_equivalence':'NOT_ATTESTED','historical_provenance':'NOT_ATTESTED',
                'credential_equivalence':'NOT_MEASURED_NO_PASSWORDS','rls_effective_enforcement':'NOT_RUN','overall':'BLOCKED'}
