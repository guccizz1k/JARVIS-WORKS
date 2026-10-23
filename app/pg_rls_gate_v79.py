"""V7.9 non-mutating PostgreSQL SELECT-policy audit for an isolated synthetic lab.

Catalog PASS is not a tenant isolation certification and never authorizes deploy.
All 35 tables, roles, grants, policies and guard functions must be accounted for.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .pg_full_shadow_v76 import EXPECTED_TABLES
from .pg_rls_full_review_v78 import PRIVATE, DIRECT, DERIVED, SPECIAL

DANGEROUS_GRANTS = ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER')
PUBLIC_POLICY = 'jw_v78_review_select'


@dataclass(frozen=True)
class CatalogResult:
    decision: str
    tables: int
    policies: int
    findings: tuple[str, ...]
    postgres_executed: bool = False
    tenant_attack_executed: bool = False
    cutover_approved: bool = False


class CatalogBlocked(RuntimeError):
    pass


def audit_catalog(snapshot: dict[str, Any]) -> CatalogResult:
    """Evaluate only an explicitly collected PostgreSQL catalog snapshot.

    Each snapshot key has a fixed documented shape. Missing catalog evidence
    is a BLOCK, not an assumed secure default. Avoids parsing arbitrary SQL.
    """
    findings: list[str] = []
    role = snapshot.get('app_role') or {}
    if role.get('name') != 'jw_app':
        findings.append('Unexpected or missing application role')
    for flag in ('superuser','bypassrls','createrole','createdb','replication'):
        if role.get(flag) is not False:
            findings.append(f'Application role must have {flag}=false')
    if role.get('member_of') != []:
        findings.append('Application role must have no inherited role memberships')

    tables = snapshot.get('tables')
    if not isinstance(tables,dict) or set(tables)!=EXPECTED_TABLES:
        findings.append('35-table set mismatch')
        tables = tables if isinstance(tables,dict) else {}
    policies = snapshot.get('policies')
    if not isinstance(policies,dict) or set(policies)!=EXPECTED_TABLES:
        findings.append('Policy catalog must cover exactly all 35 tables')
        policies = policies if isinstance(policies,dict) else {}

    count=0
    for name in sorted(EXPECTED_TABLES):
        meta=tables.get(name) or {}
        if meta.get('rls_enabled') is not True or meta.get('force_rls') is not True:
            findings.append(f'{name}: RLS not enabled and forced')
        if meta.get('owner') in (None,'jw_app'):
            findings.append(f'{name}: unsafe owner')
        grants = meta.get('grants')
        if not isinstance(grants,dict):
            findings.append(f'{name}: missing privilege evidence')
            grants={}
        if grants.get('SELECT') is not (name not in PRIVATE):
            findings.append(f'{name}: incorrect SELECT privilege')
        for grant in DANGEROUS_GRANTS:
            if grants.get(grant) is not False:
                findings.append(f'{name}: {grant} must be denied')
        entries=policies.get(name)
        if not isinstance(entries,list):
            findings.append(f'{name}: missing policy evidence')
            entries=[]
        expected=0 if name in PRIVATE else 1
        if len(entries)!=expected:
            findings.append(f'{name}: expected {expected} policy, found {len(entries)}')
        count+=len(entries)
        for p in entries:
            if not isinstance(p,dict):
                findings.append(f'{name}: unrecognized policy format')
                continue
            if p.get('name')!=PUBLIC_POLICY or p.get('command')!='SELECT' or p.get('roles')!=['jw_app'] or p.get('permissive') is not True:
                findings.append(f'{name}: unexpected policy identity/scope')
            clause=p.get('using')
            if not isinstance(clause,str) or 'jw_guard.current_tenant()' not in clause:
                findings.append(f'{name}: signed tenant function absent')
            # A signed guard on its own is insufficient: confirm ownership
            # predicates for the exact table class without treating substring
            # matching as a formal SQL-equivalence proof.
            if name in DIRECT and ('org_id' not in (clause or '')):
                findings.append(f'{name}: direct organization key absent')
            if name in DERIVED and ('EXISTS' not in (clause or '').upper()):
                findings.append(f'{name}: parent relationship missing')
            if name in SPECIAL and (('id' not in (clause or '')) if name=='organizations' else ('org_a' not in (clause or '') or 'org_b' not in (clause or ''))):
                findings.append(f'{name}: special relationship missing')
    guard=snapshot.get('tenant_guard') or {}
    if guard.get('schema')!='jw_guard' or guard.get('name')!='current_tenant' or guard.get('definer') is not True or guard.get('owner')!='postgres' or guard.get('app_can_execute') is not True:
        findings.append('Signed tenant context function identity/privileges unverified')
    if guard.get('signature')!='current_tenant()':
        findings.append('Signed tenant function signature mismatch')
    if 'search_path=pg_catalog, jw_guard, pg_temp' not in guard.get('settings',[]):
        findings.append('Tenant guard SECURITY DEFINER search_path not pinned')
    if guard.get('public_can_execute') is not False:
        findings.append('Tenant guard publicly executable')

    return CatalogResult('BLOCKED' if findings else 'CATALOG_ONLY_PASS',len(tables),count,tuple(findings))


def require_catalog_pass(result:CatalogResult) -> None:
    if result.decision!='CATALOG_ONLY_PASS':
        raise CatalogBlocked('; '.join(result.findings))
