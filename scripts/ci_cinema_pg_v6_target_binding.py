"""V6 target binding: never alter the pinned backup engine or legacy 55432 target.

This module is intentionally not a live role-activation launcher.
"""
from __future__ import annotations
from scripts import ci_cinema_pg_v6_target_adapter as gate
from scripts.ci_cinema_pg_m import read_private_target
from scripts.pg_backup_v223 import parse_dsn

class BindingBlocked(Exception):
    pass

def checked_target_config(psycopg, backup_module):
    """Bind the existing owner-only token to the independently verified 55433 cluster."""
    old = read_private_target()
    parsed = parse_dsn(old['JW_PG_TARGET_ADMIN_DSN'])
    if (parsed['host'], parsed['port'], parsed['dbname'], parsed['user']) != (
        '127.0.0.1', '55432', 'postgres', 'postgres'
    ):
        raise BindingBlocked('legacy_secret_contract_changed')
    if old['JW_PG_CI_ALLOW'] != 'ONLY_EPHEMERAL_LOCAL_DATABASE':
        raise BindingBlocked('ephemeral_guard_disabled')
    gate.prove_target(psycopg, parsed['password'], old['JW_PG_TARGET_EPHEMERAL_TOKEN'], backup_module)
    from psycopg.conninfo import make_conninfo
    dsn = make_conninfo(host='127.0.0.1', port=gate.PORT,
                        dbname='postgres', user='postgres',
                        password=parsed['password'], sslmode='disable',
                        connect_timeout=5)
    return {
        'JW_PG_TARGET_ADMIN_DSN': dsn,
        'JW_PG_TARGET_EPHEMERAL_TOKEN': old['JW_PG_TARGET_EPHEMERAL_TOKEN'],
        'JW_PG_CI_ALLOW': old['JW_PG_CI_ALLOW'],
    }

def bind_backup_environment(base_env, psycopg, backup_module):
    """Create child-only environment; fail closed on a different or missing target."""
    import os
    if not isinstance(base_env, dict):
        raise BindingBlocked('invalid_base_environment')
    target = checked_target_config(psycopg, backup_module)
    result = dict(base_env)
    result.update(target)
    return result
