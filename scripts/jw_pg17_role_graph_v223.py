"""Read-only PG17 global role graph checkpoints. No password material or raw role names.

The SQL must run in an explicitly authorized environment. The module never opens
connections or executes SQL itself. A matching checkpoint does not prove that
old schema-only backups contained global roles, or that credentials were restored.
"""
import hashlib
import hmac
import json
import re

FORMAT = 'JW-PG17-GLOBAL-ROLE-GRAPH-V1'
SECTIONS = ('roles', 'memberships', 'all_database_role_settings')
MAX_COUNT = 100_000
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
SQL = r'''
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL search_path=pg_catalog;
SET LOCAL statement_timeout='40s';
SET LOCAL lock_timeout='2s';
SET LOCAL TimeZone='UTC';
SET LOCAL DateStyle='ISO, YMD';
WITH entries(section,item) AS (
 SELECT 'roles',jsonb_build_array(r.rolname,r.rolsuper,r.rolinherit,
   r.rolcreaterole,r.rolcreatedb,r.rolcanlogin,r.rolreplication,
   r.rolbypassrls,r.rolconnlimit,r.rolvaliduntil) FROM pg_roles r
 UNION ALL SELECT 'memberships',jsonb_build_array(p.rolname,c.rolname,g.rolname,
   m.admin_option,m.inherit_option,m.set_option)
 FROM pg_auth_members m LEFT JOIN pg_roles p ON p.oid=m.roleid
 LEFT JOIN pg_roles c ON c.oid=m.member LEFT JOIN pg_roles g ON g.oid=m.grantor
 UNION ALL SELECT 'all_database_role_settings',jsonb_build_array(d.datname,r.rolname,
   s.setdatabase=0,s.setrole=0,
   (SELECT coalesce(jsonb_agg(v ORDER BY v COLLATE "C"),'[]'::jsonb) FROM unnest(s.setconfig) v))
 FROM pg_db_role_setting s LEFT JOIN pg_database d ON d.oid=s.setdatabase
 LEFT JOIN pg_roles r ON r.oid=s.setrole
), sections(section) AS (VALUES ('roles'),('memberships'),('all_database_role_settings')),
 summary AS (SELECT s.section,count(e.item) n,CASE WHEN count(e.item)<=100000 THEN
 encode(sha256(convert_to(coalesce(jsonb_agg(e.item ORDER BY e.item::text COLLATE "C")
 FILTER (WHERE e.item IS NOT NULL),'[]'::jsonb)::text,'UTF8')),'hex') END digest
 FROM sections s LEFT JOIN entries e USING(section) GROUP BY s.section),
 invalid AS (
 SELECT count(*) n FROM pg_auth_members m LEFT JOIN pg_roles p ON p.oid=m.roleid
 LEFT JOIN pg_roles c ON c.oid=m.member LEFT JOIN pg_roles g ON g.oid=m.grantor
 WHERE p.oid IS NULL OR c.oid IS NULL OR g.oid IS NULL
 UNION ALL SELECT count(*) FROM pg_db_role_setting s LEFT JOIN pg_database d ON d.oid=s.setdatabase
 LEFT JOIN pg_roles r ON r.oid=s.setrole
 WHERE (s.setdatabase<>0 AND d.oid IS NULL) OR (s.setrole<>0 AND r.oid IS NULL)
)
SELECT jsonb_build_object('format','JW-PG17-GLOBAL-ROLE-GRAPH-V1',
 'server_major',current_setting('server_version_num')::integer/10000,
 'unresolved_refs',(SELECT sum(n) FROM invalid),
 'sections',(SELECT jsonb_object_agg(section,jsonb_build_array(n,digest)) FROM summary));
ROLLBACK;
'''

class Blocked(ValueError):
    pass

def require(ok, code):
    if not ok:
        raise Blocked(code)

def unique(pairs):
    out = {}
    for k, v in pairs:
        require(k not in out, 'DUPLICATE_FIELD')
        out[k] = v
    return out

def canonical(doc):
    return json.dumps(doc, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')

def parse(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 8192, 'CHECKPOINT_SIZE')
    try:
        doc = json.loads(raw.decode('ascii'), object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise Blocked('CHECKPOINT_JSON') from None
    require(type(doc) is dict and set(doc) == {'format','server_major','unresolved_refs','sections'}, 'CHECKPOINT_FIELDS')
    require(doc['format'] == FORMAT and type(doc['server_major']) is int and doc['server_major'] == 17, 'PG17_REQUIRED')
    require(type(doc['unresolved_refs']) is int and doc['unresolved_refs'] == 0, 'UNRESOLVED_CATALOG_REFERENCE')
    sections = doc['sections']
    require(type(sections) is dict and set(sections) == set(SECTIONS), 'SECTION_SET')
    for value in sections.values():
        require(type(value) is list and len(value) == 2 and type(value[0]) is int and 0 <= value[0] <= MAX_COUNT and type(value[1]) is str and HEX.fullmatch(value[1]), 'SECTION_INVALID')
    require(sections['roles'][0] > 0, 'NO_ROLES')
    return doc

def pin(raw):
    return hashlib.sha256(canonical(parse(raw))).hexdigest()

def compare(reference, observed, *, expected_reference_pin):
    """Compare against an independently obtained pin. Never authorizes release."""
    result = {'role_graph_checkpoint':'BLOCKED', 'historical_role_equivalence':'NOT_ATTESTED',
              'credential_equivalence':'NOT_MEASURED', 'overall':'BLOCKED'}
    try:
        require(type(expected_reference_pin) is str and HEX.fullmatch(expected_reference_pin), 'REFERENCE_PIN_FORMAT')
        require(hmac.compare_digest(pin(reference), expected_reference_pin), 'REFERENCE_PIN_MISMATCH')
        ref, actual = parse(reference), parse(observed)
        for name in SECTIONS:
            a,b = ref['sections'][name],actual['sections'][name]
            require(a[0] == b[0] and hmac.compare_digest(a[1],b[1]), 'MISMATCH_'+name.upper())
        result['role_graph_checkpoint'] = 'PASS_GLOBAL_ROLE_GRAPH_CHECKPOINT_MATCH'
    except Blocked as exc:
        result['blocker'] = str(exc)
    return result
