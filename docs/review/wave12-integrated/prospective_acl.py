"""New prospective policy acceptance gate, separate from historical restore comparator.
Inputs are redacted count/hash checkpoints from existing read-only probes.
Never infer approval, historical equivalence or actual enforcement from hashes.
"""
import json,hashlib,secrets,re
from review_gates import Blocked,need,digest
AUTHZ=('owners','object_acl','column_acl','default_acl','role_attributes','role_memberships','role_settings','database_acl')
ROLES=('roles','memberships','all_database_role_settings')
BEHAVIOR=('same_tenant_read','same_tenant_write','cross_tenant_read_denied','cross_tenant_write_denied','owner_force_rls','role_escalation_denied','direct_grant_denied','mutation_negative_control','rollback_cleanup')
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def sections(x,keys):
    need(type(x) is dict and set(x)==set(keys),'ACL_SECTION_SET')
    for k in keys:
        a=x[k];need(type(a) is list and len(a)==2 and type(a[0]) is int and 0<=a[0]<=100000 and digest(a[1]),'ACL_SECTION_INVALID')
    return x

def compare(*,reference,reference_pin,observed,observed_scope,behavior,expected_migration_sha):
    need(type(reference) is dict and set(reference)=={'schema','scope','migration_sha','authz','roles','behavior_required'} and reference['schema']=='NARUV_PROSPECTIVE_ACL_V1','ACL_REFERENCE')
    need(digest(reference_pin) and secrets.compare_digest(hashlib.sha256(canonical(reference)).hexdigest(),reference_pin),'ACL_REFERENCE_PIN')
    need(digest(expected_migration_sha,40) and reference['migration_sha']==expected_migration_sha and type(observed_scope) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',observed_scope) and reference['scope']==observed_scope,'ACL_SCOPE')
    need(reference['behavior_required']==list(BEHAVIOR),'ACL_BEHAVIOR_POLICY')
    need(type(observed) is dict and set(observed)=={'server_major','authz','roles'} and type(observed['server_major']) is int and observed['server_major']==17,'ACL_PG17_REQUIRED')
    reasons=[]
    for field,keys in [('authz',AUTHZ),('roles',ROLES)]:
        a,b=sections(reference[field],keys),sections(observed[field],keys)
        for k in keys:
            if a[k]!=b[k]:reasons.append('ACL_MISMATCH_'+k.upper())
    need(reference['authz']['owners'][0]>0 and reference['authz']['object_acl'][0]>0 and reference['roles']['roles'][0]>0,'ACL_EMPTY_SCOPE')
    need(type(behavior) is dict and set(behavior)==set(BEHAVIOR) and all(type(v) is bool for v in behavior.values()),'ACL_BEHAVIOR_SHAPE')
    reasons.extend('ACL_NOT_PASSED_'+k.upper() for k in BEHAVIOR if not behavior[k])
    return dict(status='BLOCKED' if reasons else 'PROSPECTIVE_CHECKPOINT_AND_BEHAVIOR_CLAIMS_MATCH_ONLY',reasons=reasons,independent_approval_verified=False,actual_effective_enforcement_attested=False,historical_acl_equivalence=False,production_authorized=False)
