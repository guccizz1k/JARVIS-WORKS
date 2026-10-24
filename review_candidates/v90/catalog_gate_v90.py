"""Fail-closed V9.0 dev DB catalog/release evidence gate.

This is a metadata checker, NOT a substitute for independent PostgreSQL
connections, real RLS tenant probes, SQL migration rehearsal, or production E2E.
No connection strings, SQL execution, customer data or secrets are handled.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

REQUIRED_FUNCTIONS = ('v90_send_text', 'v90_edit_text')


def assess(catalog: dict, *, independent_pg_e2e: bool = False) -> dict:
    funcs = catalog.get('functions', {})
    checks = {
        'postgresql_17_verified': catalog.get('postgresql_17') is True,
        '35_force_rls_tables': catalog.get('force_rls_tables') == 35,
        'no_direct_app_login': catalog.get('app_role_nologin') is True,
        'safe_nonprivileged_gateway_login_exists': catalog.get('safe_gateway_logins', 0) >= 1,
        'send_function_has_tx_lock': funcs.get('v90_send_text', {}).get('tx_lock') is True,
        'edit_function_has_tx_lock': funcs.get('v90_edit_text', {}).get('tx_lock') is True,
        'function_execution_least_privilege': all(
            funcs.get(name, {}).get('anon_execute') is False
            and funcs.get(name, {}).get('authenticated_execute') is False
            and funcs.get(name, {}).get('app_execute') is True
            for name in REQUIRED_FUNCTIONS
        ),
        'two_independent_pg_sessions_e2e': independent_pg_e2e is True,
    }
    failed = [name for name, passed in checks.items() if not passed]
    return {
        'verdict': 'PASS' if not failed else 'BLOCKED',
        'scope': 'PRE_RELEASE_CATALOG_PLUS_REQUIRED_E2E',
        'checks': checks,
        'blocking_checks': failed,
        'mutated_database': False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('catalog', type=Path, help='Review-only catalog metadata JSON')
    # Deliberately do not provide a CLI flag to impersonate independent test evidence.
    args = parser.parse_args()
    result = assess(json.loads(args.catalog.read_text(encoding='utf-8')))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['verdict'] == 'PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
