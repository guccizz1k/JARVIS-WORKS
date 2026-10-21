"""V5.0 synthetic-only identity linkage rehearsal; NEVER a production mapper.

Reuse V4.4's verified PostgreSQL session/RLS adapter. Never accept mappings
from a web request, query parameter, cookie value, or employee-entered input.
No persistent PG writes, schema changes, account changes or live user migration.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import re

LAB_DATABASE = re.compile(r'jw_v20_test_[0-9a-f]{12}\Z')
MAX_LINKS = 32


class IdentityAuditBlocked(RuntimeError):
    """Fail-closed mapping or eligibility check. No credentials in text."""


@dataclass(frozen=True)
class ActorLink:
    source_org: str
    source_user: str
    pg_org: str
    pg_user: str


def _validate_links(links):
    if not isinstance(links, tuple) or not 2 <= len(links) <= MAX_LINKS:
        raise IdentityAuditBlocked('Invalid synthetic actor roster')
    for link in links:
        if not isinstance(link, ActorLink):
            raise IdentityAuditBlocked('Untrusted mapping format')
        if any(not isinstance(v, str) or not (1 <= len(v) <= 80)
               or re.fullmatch(r'[a-zA-Z0-9_-]+', v) is None
               for v in (link.source_org, link.source_user, link.pg_org, link.pg_user)):
            raise IdentityAuditBlocked('Invalid mapping identifier')
    # The same actor cannot be mapped twice, even if one side repeats exactly.
    if (len({x.source_user for x in links}) != len(links)
        or len({x.pg_user for x in links}) != len(links)):
        raise IdentityAuditBlocked('Actor collision')
    source_to_pg = {}; pg_to_source = {}
    for x in links:
        if (x.source_org in source_to_pg and source_to_pg[x.source_org] != x.pg_org
            or x.pg_org in pg_to_source and pg_to_source[x.pg_org] != x.source_org):
            raise IdentityAuditBlocked('Tenant collision')
        source_to_pg[x.source_org] = x.pg_org
        pg_to_source[x.pg_org] = x.source_org
    if len(source_to_pg) < 2 or len(pg_to_source) < 2:
        raise IdentityAuditBlocked('Cross-tenant fixture coverage missing')
    return source_to_pg


def _check_lab():
    if (os.getenv('JW_ENV', '').casefold() == 'production'
        or os.getenv('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE'
        or os.getenv('JW_PG_LAB_V50') != 'ONLY_DISPOSABLE_LAB'):
        raise IdentityAuditBlocked('Disposable V5.0 gate not authorized')


def audit_roster(source, pg_admin, adapter, links: tuple[ActorLink, ...],
                 tokens: tuple[str, ...]):
    """Read-only eligible-users parity + signed PG actor checks for a lab roster.

    source: snapshot SQLite connection (never a live website connection).
    pg_admin: connection to disposable PostgreSQL 17 admin for catalog reads.
    adapter: V3.0 review adapter; signed session validated under jw_app RLS.
    tokens: server-side, synthetic-only, in matching link order; never returned.
    """
    _check_lab()
    _validate_links(links)
    if (not isinstance(tokens, tuple) or len(tokens) != len(links)
        or any(not isinstance(t, str) or not 40 <= len(t) <= 512 for t in tokens)
        or len(set(tokens)) != len(tokens)):
        raise IdentityAuditBlocked('Invalid test session registry')
    # Refuse BEFORE any tenant reads if PG admin is not an ephemeral cluster.
    with pg_admin.cursor() as cur:
        cur.execute("SELECT current_database(),current_user,current_setting('server_version_num')")
        db, role, version = cur.fetchone()
        if (not isinstance(db, str) or LAB_DATABASE.fullmatch(db) is None
            or role != 'postgres' or int(version)//10000 != 17):
            raise IdentityAuditBlocked('Refuse non-disposable PostgreSQL 17')
        ids = tuple(x.pg_user for x in links)
        cur.execute('SELECT id,org_id FROM public.users WHERE id=ANY(%s)', (list(ids),))
        rows = cur.fetchall()
    pg_found = {str(r[0]): str(r[1]) for r in rows}
    if len(rows) != len(links) or len(pg_found) != len(links):
        raise IdentityAuditBlocked('PostgreSQL actor absent or duplicated')
    # Account existence, organization and disablement must agree *before*
    # using the signed PG token; source connection is never modified.
    for link, token in zip(links, tokens):
        record = source.execute('''SELECT u.org_id,d.user_id
            FROM users AS u LEFT JOIN staff_disabled AS d ON d.user_id=u.id
            WHERE u.id=?''', (link.source_user,)).fetchall()
        if (len(record) != 1 or record[0][0] != link.source_org
            or record[0][1] is not None
            or pg_found.get(link.pg_user) != link.pg_org):
            raise IdentityAuditBlocked('Unverified or disabled synthetic actor')
        # The PG adapter binds the token via jw_guard and enforces role jw_app,
        # RLS, PG version and its own loopback disposable DSN validation.
        try:
            with adapter.verified_transaction(token, readonly=True) as (_, org, user):
                if (org, user) != (link.pg_org, link.pg_user):
                    raise IdentityAuditBlocked('Signed identity does not match roster')
        except IdentityAuditBlocked:
            raise
        except Exception as exc:
            raise IdentityAuditBlocked('Synthetic actor session rejected') from None
    return {
        'decision': 'BLOCKED',
        'cutover_approved': False,
        'synthetic_only': True,
        'verified_fixture_links': len(links),
        'verified_fixture_tenants': len({x.source_org for x in links}),
        'remaining_blockers': [
            'REAL_EMPLOYEE_IDENTITY_MAPPING_NOT_VERIFIED',
            'PRODUCTION_CUTOVER_NOT_AUTHORIZED',
            'DUAL_WRITE_AND_ROLLBACK_NOT_VERIFIED',
        ],
    }
