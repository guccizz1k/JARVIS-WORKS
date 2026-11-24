"""Pinned historical normalized catalog checkpoints. No live source access.

Catalog fingerprint covers the specified object classes only. Ownership, ACL,
role memberships and effective RLS enforcement are NOT established by the
normalized restore, which deliberately strips ownership/ACL. No raw metadata
is printed by the probe or included in receipts.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import re
from scripts import jw_independent_equivalence_v223 as eq

FORMAT = 'JW-PG17-NORMALIZED-CATALOG-REFERENCE-V2'
ALGORITHM = 'JW-PG17-CATALOG-JSONB-C-SHA256-V1'
SECTIONS = ('relations','columns','constraints','indexes','triggers','policies','rls_flags','views','sequences','routines')
MAX_COUNT = 100_000
# Fixed SQL, no interpolation. All content hashes computed inside PG17. The
# JSONB arrays avoid delimiter ambiguity; C order avoids locale-dependent sorting.
SQL = r'''
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL search_path = pg_catalog;
SET LOCAL statement_timeout = '40s';
SET LOCAL lock_timeout = '2s';
SET LOCAL TimeZone = 'UTC';
SET LOCAL DateStyle = 'ISO, YMD';
SET LOCAL IntervalStyle = 'postgres';
SET LOCAL extra_float_digits = 3;
WITH rel AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p','v','m','S','f','c')
), entries(section, item) AS (
 SELECT 'relations', jsonb_build_array(c.relname,c.relkind,c.relpersistence,c.relispartition,
   CASE WHEN c.relkind='p' THEN pg_get_partkeydef(c.oid) END,
   CASE WHEN c.relispartition THEN pg_get_expr(c.relpartbound,c.oid,false) END,
   c.reloptions) FROM rel c
 UNION ALL SELECT 'columns',jsonb_build_array(c.relname,a.attnum,a.attname,
   format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,
   CASE WHEN co.oid IS NOT NULL THEN jsonb_build_array(cn.nspname,co.collname) END,
   pg_get_expr(d.adbin,d.adrelid,false))
 FROM rel c JOIN pg_attribute a ON a.attrelid=c.oid
 LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
 LEFT JOIN pg_collation co ON co.oid=a.attcollation
 LEFT JOIN pg_namespace cn ON cn.oid=co.collnamespace
 WHERE a.attnum>0 AND NOT a.attisdropped AND c.relkind<>'S'
 UNION ALL SELECT 'constraints',jsonb_build_array(c.relname,k.conname,k.contype,
   k.condeferrable,k.condeferred,k.convalidated,pg_get_constraintdef(k.oid,false))
 FROM rel c JOIN pg_constraint k ON k.conrelid=c.oid
 UNION ALL SELECT 'indexes',jsonb_build_array(c.relname,ic.relname,
   i.indisunique,i.indisprimary,i.indisexclusion,i.indisvalid,i.indisready,
   i.indisreplident,pg_get_indexdef(i.indexrelid,0,false))
 FROM rel c JOIN pg_index i ON i.indrelid=c.oid JOIN pg_class ic ON ic.oid=i.indexrelid
 UNION ALL SELECT 'triggers',jsonb_build_array(c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid,false))
 FROM rel c JOIN pg_trigger t ON t.tgrelid=c.oid WHERE NOT t.tgisinternal
 UNION ALL SELECT 'policies',jsonb_build_array(c.relname,p.polname,p.polcmd,p.polpermissive,
   (SELECT coalesce(jsonb_agg(CASE WHEN u.roleid=0 THEN 'PUBLIC' ELSE r.rolname::text END
     ORDER BY (CASE WHEN u.roleid=0 THEN 'PUBLIC' ELSE r.rolname::text END) COLLATE "C"),'[]'::jsonb)
    FROM unnest(p.polroles) u(roleid) LEFT JOIN pg_roles r ON r.oid=u.roleid),
   pg_get_expr(p.polqual,p.polrelid,false),pg_get_expr(p.polwithcheck,p.polrelid,false))
 FROM rel c JOIN pg_policy p ON p.polrelid=c.oid
 UNION ALL SELECT 'rls_flags',jsonb_build_array(c.relname,c.relrowsecurity,c.relforcerowsecurity)
 FROM rel c WHERE c.relkind IN ('r','p')
 UNION ALL SELECT 'views',jsonb_build_array(c.relname,c.relkind,pg_get_viewdef(c.oid,false))
 FROM rel c WHERE c.relkind IN ('v','m')
 UNION ALL SELECT 'sequences',jsonb_build_array(c.relname,format_type(s.seqtypid,NULL),
   s.seqstart,s.seqincrement,s.seqmax,s.seqmin,s.seqcache,s.seqcycle)
 FROM rel c JOIN pg_sequence s ON s.seqrelid=c.oid
 UNION ALL SELECT 'routines',jsonb_build_array(p.proname,pg_get_function_identity_arguments(p.oid),
   p.prokind,p.prosecdef,p.proleakproof,p.provolatile,p.proparallel,pg_get_functiondef(p.oid))
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='jw_dev' AND p.prokind IN ('f','p','w')
), sections(section) AS (VALUES ('relations'),('columns'),('constraints'),('indexes'),('triggers'),
 ('policies'),('rls_flags'),('views'),('sequences'),('routines')),
 summaries AS (
 SELECT s.section,count(e.item) AS n,
   CASE WHEN count(e.item)<=100000 THEN encode(sha256(convert_to(
      coalesce(jsonb_agg(e.item ORDER BY (e.item::text) COLLATE "C") FILTER (WHERE e.item IS NOT NULL),'[]'::jsonb)::text,
      'UTF8')),'hex') END AS digest
 FROM sections s LEFT JOIN entries e USING(section) GROUP BY s.section
)
SELECT jsonb_object_agg(section,jsonb_build_array(n,digest)) FROM summaries;
ROLLBACK;
'''

def parse_catalog(doc):
    eq.require(type(doc) is dict and set(doc)==set(SECTIONS),'CATALOG_SECTION_SET')
    out={}
    for name in SECTIONS:
        v=doc[name]
        eq.require(type(v) is list and len(v)==2 and type(v[0]) is int and 0<=v[0]<=MAX_COUNT and eq.valid_hex(v[1]),'CATALOG_ENTRY_INVALID')
        out[name]=(v[0],v[1])
    eq.require(out['rls_flags'][0]==eq.TABLES and out['relations'][0]>=eq.TABLES,'CATALOG_TABLE_SCOPE')
    eq.require(out['columns'][0]>=eq.TABLES,'CATALOG_COLUMN_SCOPE')
    return out

def probe(exec_fn, container, db):
    eq.require(eq.valid_hex(container) and type(db) is str and re.fullmatch(r'jw_p1_offline_(?:[0-9]|10)',db) is not None,'CATALOG_TARGET_INVALID')
    try:
        r=exec_fn(container,['psql','-X','-qAt','-U','postgres','-d',db,'-v','ON_ERROR_STOP=1','-c',SQL],timeout=50)
        eq.require(r.returncode==0 and type(r.stdout) is bytes and 0<len(r.stdout)<=16384,'CATALOG_PROBE_FAILED')
        return parse_catalog(json.loads(r.stdout.decode('ascii'),object_pairs_hook=eq.no_duplicates,parse_constant=eq.reject_constant))
    except eq.Blocked: raise
    except Exception: raise eq.Blocked('CATALOG_PROBE_FAILED') from None

def load_reference(raw, *, expected_reference_sha256, expected_vault, expected_scope, provider_pairs):
    eq.require(type(raw) is bytes and 0<len(raw)<=eq.MAX_JSON,'CATALOG_REFERENCE_SIZE')
    eq.require(eq.valid_hex(expected_reference_sha256) and hmac.compare_digest(hashlib.sha256(raw).hexdigest(),expected_reference_sha256),'CATALOG_REFERENCE_PIN_MISMATCH')
    try: doc=json.loads(raw.decode('ascii'),object_pairs_hook=eq.no_duplicates,parse_constant=eq.reject_constant)
    except eq.Blocked: raise
    except Exception: raise eq.Blocked('CATALOG_REFERENCE_JSON') from None
    eq.require(type(doc) is dict and set(doc)=={'format','algorithm','data_reference','catalog_archives'},'CATALOG_REFERENCE_FIELDS')
    eq.require(doc['format']==FORMAT and doc['algorithm']==ALGORITHM,'CATALOG_REFERENCE_ALGORITHM')
    data=eq.canonical(doc['data_reference'])
    rows=eq.load_reference(data,expected_reference_sha256=hashlib.sha256(data).hexdigest(),expected_vault=expected_vault,expected_scope=expected_scope,provider_pairs=provider_pairs)
    a=doc['catalog_archives']; eq.require(type(a) is list and len(a)==eq.COUNT,'CATALOG_REFERENCE_COUNT')
    expected={r.git_blob_sha1:r.cipher_sha256 for r in rows}; catalogs={}
    for item in a:
        eq.require(type(item) is dict and set(item)=={'git_blob_sha1','cipher_sha256','sections'},'CATALOG_ARCHIVE_FIELDS')
        b=item['git_blob_sha1']; c=item['cipher_sha256']
        eq.require(eq.valid_hex(b,eq.GIT) and b in expected and b not in catalogs and eq.valid_hex(c) and hmac.compare_digest(c,expected[b]),'CATALOG_ARCHIVE_IDENTITY')
        catalogs[b]=parse_catalog(item['sections'])
    return rows,catalogs

class CatalogComparison:
    def __init__(self, rows, catalogs):
        self.data=eq.Equivalence(rows)
        eq.require(set(catalogs)=={r.git_blob_sha1 for r in rows},'CATALOG_ARCHIVE_SET')
        self.catalogs={b:parse_catalog({k:list(v) for k,v in sections.items()}) for b,sections in catalogs.items()}
        self.done=set(); self.failed=False
    def compare(self,blob,cipher,restored,observed):
        try:
            eq.require(not self.failed,'CATALOG_RUN_FAILED')
            self.data.compare(blob,cipher,restored)
            eq.require(type(observed) is dict and set(observed)==set(SECTIONS),'CATALOG_OBSERVATION_MISSING')
            for k in SECTIONS:
                v=observed[k]; target=self.catalogs[blob][k]
                eq.require(type(v) is tuple and len(v)==2 and type(v[0]) is int and eq.valid_hex(v[1]) and v[0]==target[0] and hmac.compare_digest(v[1],target[1]),'CATALOG_'+k.upper()+'_MISMATCH')
            self.done.add(blob)
        except BaseException:
            self.failed=True; raise
    def receipt(self,*,cleanup):
        r=self.data.receipt(cleanup=cleanup)
        complete=not self.failed and len(self.done)==eq.COUNT and r['normalized_archive_comparison']=='PASS_11_ARCHIVE_CHECKPOINTS'
        if not complete: r['normalized_archive_comparison']='BLOCKED'
        r.update(normalized_catalog_comparison='PASS_11_SCOPED_CATALOG_CHECKPOINTS' if complete else 'BLOCKED',catalog_matched_archives=len(self.done),
                 rls_policy_definition_comparison='PASS_11_ARCHIVE_POLICY_AND_FLAGS' if complete else 'BLOCKED',
                 rls_effective_enforcement='NOT_RUN',full_schema_equivalence='NOT_ATTESTED_SCOPED_CATALOG_ONLY',
                 original_owner_acl_equivalence='NOT_RUN_RESTORE_STRIPS_OWNER_ACL',role_membership_equivalence='NOT_ATTESTED_CLUSTER_GLOBALS_NOT_BACKED_UP',overall='BLOCKED')
        return r
