"""Review-only PG17 role graph evidence. No DDL, grants, passwords or activation.
Caller must supply an authorized, idle DB connection with verified source identity.
Evidence is CURRENT metadata, not historical backup-era attestation.
"""
import hashlib
import json
import re
from datetime import datetime, timezone
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN = b'JW-PG17-ROLE-EVIDENCE-V1\x00'
ROLE_FIELDS = ('superuser','inherit','createrole','createdb','login','replication','bypassrls')
MAX_ROLES = 4096
MAX_EDGES = 32768
SHA = re.compile(r'^[0-9a-f]{64}$')
COMMIT = re.compile(r'^[0-9a-f]{40}$')
ROLE_SQL = '''SELECT rolname::text, rolsuper, rolinherit, rolcreaterole,
 rolcreatedb, rolcanlogin, rolreplication, rolbypassrls, rolconnlimit
 FROM pg_catalog.pg_roles LIMIT 4097'''
EDGE_SQL = '''SELECT p.rolname::text, m.rolname::text, g.rolname::text,
 a.admin_option, a.inherit_option, a.set_option
 FROM pg_catalog.pg_auth_members a
 LEFT JOIN pg_catalog.pg_roles p ON p.oid=a.roleid
 LEFT JOIN pg_catalog.pg_roles m ON m.oid=a.member
 LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantor LIMIT 32769'''

class Blocked(ValueError):
    pass

def need(ok, code):
    if not ok:
        raise Blocked(code)

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')

def role_name(x):
    return type(x) is str and 0 < len(x.encode('utf-8')) <= 63 and '\x00' not in x

def graph(roles, edges, scope):
    """All membership-connected roles (both directions), plus grantor attributes.
    No roles are created, and no unscoped records are returned.
    """
    need(type(scope) in (list,tuple) and 0<len(scope)<=64 and all(role_name(x) for x in scope) and len(set(scope))==len(scope),'SCOPE_INVALID')
    need(len(roles)<=MAX_ROLES and len(edges)<=MAX_EDGES,'GRAPH_BUDGET')
    by={}
    for r in roles:
        need(len(r)==9 and role_name(r[0]) and all(type(x) is bool for x in r[1:8]) and type(r[8]) is int and -1<=r[8]<=2147483647,'ROLE_ROW_INVALID')
        need(r[0] not in by,'DUPLICATE_ROLE')
        by[r[0]]=list(r)
    need(set(scope)<=by.keys(),'REQUIRED_ROLE_MISSING')
    es=set(); adj={name:set() for name in by}
    for e in edges:
        need(len(e)==6 and all(role_name(x) and x in by for x in e[:3]) and all(type(x) is bool for x in e[3:]),'MEMBERSHIP_INVALID')
        e=tuple(e)
        es.add(e)
        adj[e[0]].add(e[1]);adj[e[1]].add(e[0])
    need(len(es)==len(edges) and len({e[:3] for e in es})==len(es),'DUPLICATE_MEMBERSHIP')
    connected=set(scope); stack=list(scope)
    while stack:
        for name in adj[stack.pop()]-connected:
            connected.add(name);stack.append(name)
    selected=[e for e in es if e[0] in connected or e[1] in connected]
    relevant=connected|{e[2] for e in selected}
    return {'schema':'jw-pg17-role-graph-v1','scope':sorted(scope),'roles':[by[n] for n in sorted(relevant)],'memberships':[list(e) for e in sorted(selected)]}

def capture(conn, scope):
    """Requires idle connection. Transaction rolls back on all exits.
    Caller must independently verify TLS, database identity and authorization.
    Never prints query results. No pg_authid, role settings or passwords.
    """
    need(getattr(conn,'autocommit',None) is True,'IDLE_AUTOCOMMIT_REQUIRED')
    need(getattr(getattr(conn,'info',None),'transaction_status',None)==0,'IDLE_CONNECTION_REQUIRED')
    with conn.cursor() as cur:
        cur.execute('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
        try:
            cur.execute("SET LOCAL statement_timeout = '15s'")
            cur.execute("SELECT current_setting('server_version_num')::int, current_setting('transaction_read_only')")
            v,ro=cur.fetchone();need(type(v) is int and 170000<=v<180000 and ro=='on','PG17_READONLY_REQUIRED')
            cur.execute(ROLE_SQL); roles=cur.fetchall()
            cur.execute(EDGE_SQL); edges=cur.fetchall()
            result=graph(roles,edges,scope)
        finally:
            cur.execute('ROLLBACK')
        need(conn.info.transaction_status==0,'ROLLBACK_NOT_IDLE')
    return result

def verify_snapshot(doc):
    need(type(doc) is dict and set(doc)=={'schema','scope','roles','memberships'} and doc['schema']=='jw-pg17-role-graph-v1','SNAPSHOT_FORMAT')
    need(type(doc['roles']) is list and type(doc['memberships']) is list and all(type(r) is list for r in doc['roles']+doc['memberships']),'SNAPSHOT_FORMAT')
    need(graph(doc['roles'],doc['memberships'],doc['scope'])==doc,'SNAPSHOT_NOT_CANONICAL')

def compare(source,target,source_pin):
    verify_snapshot(source);verify_snapshot(target)
    need(type(source_pin) is str and SHA.fullmatch(source_pin) and digest(source)==source_pin,'SOURCE_PIN_MISMATCH')
    need(source['scope']==target['scope'],'SCOPE_MISMATCH')
    roles_same=source['roles']==target['roles'];edges_same=source['memberships']==target['memberships']
    return {'role_attributes_equal':roles_same,'membership_edges_equal':edges_same,'scoped_role_graph':'PASS' if roles_same and edges_same else 'FAIL','role_settings':'NOT_ATTESTED','password_expiry':'NOT_ATTESTED','passwords':'NOT_CAPTURED','object_acl':'NOT_ATTESTED','object_ownership':'NOT_ATTESTED','effective_rls':'NOT_RUN','historic_source_signature':'NOT_ATTESTED','independent_key_custody':'NOT_ATTESTED','overall':'BLOCKED','activation_allowed':False}

def evidence_message(payload):
    need(type(payload) is dict and set(payload)=={'schema','commit','snapshot_sha256','archive_scope_sha256','challenge','observed_at','purpose'},'EVIDENCE_FORMAT')
    need(payload['schema']=='jw-role-evidence-v1' and payload['purpose']=='current-scoped-role-graph','EVIDENCE_PURPOSE')
    need(type(payload['commit']) is str and COMMIT.fullmatch(payload['commit']),'EVIDENCE_COMMIT')
    for k in ('snapshot_sha256','archive_scope_sha256','challenge'):
        need(type(payload[k]) is str and SHA.fullmatch(payload[k]),'EVIDENCE_PIN_FORMAT')
    need(type(payload['observed_at']) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',payload['observed_at']),'EVIDENCE_TIME')
    try: datetime.strptime(payload['observed_at'],'%Y-%m-%dT%H:%M:%SZ')
    except ValueError: raise Blocked('EVIDENCE_TIME') from None
    return DOMAIN+canonical(payload)

def verify_attestation(payload,signature,public_key,*,public_key_pin,expected_commit,expected_snapshot,expected_scope,expected_challenge,not_before,now):
    """Only verifies a pinned key's signature. Identity/custody and trustworthy
    timestamp require separate external evidence. Caller manages challenge reuse.
    """
    msg=evidence_message(payload)
    need(type(public_key) is bytes and len(public_key)==32 and type(signature) is bytes and len(signature)==64,'SIGNATURE_FORMAT')
    need(type(public_key_pin) is str and SHA.fullmatch(public_key_pin) and hashlib.sha256(public_key).hexdigest()==public_key_pin,'SIGNER_PIN_MISMATCH')
    need((payload['commit'],payload['snapshot_sha256'],payload['archive_scope_sha256'],payload['challenge'])==(expected_commit,expected_snapshot,expected_scope,expected_challenge),'EVIDENCE_BINDING_MISMATCH')
    t=datetime.strptime(payload['observed_at'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    need(isinstance(not_before,datetime) and isinstance(now,datetime) and not_before.tzinfo is not None and now.tzinfo is not None and not_before<=t<=now,'EVIDENCE_TIME_WINDOW')
    try: Ed25519PublicKey.from_public_bytes(public_key).verify(signature,msg)
    except (InvalidSignature,ValueError): raise Blocked('SIGNATURE_INVALID') from None
    return {'pinned_signature':'PASS','independent_custody':'NOT_ATTESTED','trusted_timestamp':'NOT_ATTESTED','historic_source_signature':'NOT_ATTESTED','overall':'BLOCKED','activation_allowed':False}
