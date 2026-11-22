#!/usr/bin/env python3
"""V6 preflight: read-only gates only. Does NOT authorize or run live B2/B3.

The old approval is deliberately not extended or inherited.
"""
from __future__ import annotations
from scripts import ci_cinema_pg_v6_owner_readonly as v6
from scripts import ci_cinema_pg_v223_owner_live_20261117 as owner
from scripts import ci_cinema_pg_v223_codespace_run as runner
from scripts.ci_cinema_pg_s import load_dashboard_ca
from scripts.ci_cinema_pg_u import read_password_file
from scripts.pg_backup_v223 import load_key
from scripts.ci_cinema_pg_v6_credential_probe import check as check_scram

def check():
    # Immutable source and target proof BEFORE any access to the live admin DB.
    v6.check()
    for label, func in (
        ('TOOLS', runner.check_tools),
        ('PRIVATE_INPUTS', runner.check_private_inputs),
        ('AES_KEY', load_key),
        ('CA_TLS', load_dashboard_ca),
        ('BACKUP_AUTH', read_password_file),
        ('SERVER_SCRAM', check_scram),
        ('ADMIN_READONLY', owner.check_live_admin_state),
    ):
        try:
            func()
        except BaseException:
            raise v6.Blocked('PREFLIGHT_'+label) from None
    return True

def main():
    try:
        check()
        print('V6_PREFLIGHT_READONLY_PASS')
        print('NO_ROLE_CHANGE_NO_BACKUP')
        return 0
    except BaseException as e:
        label = str(e) if isinstance(e, v6.Blocked) else 'UNEXPECTED_'+type(e).__name__
        if label not in {'PREFLIGHT_TOOLS','PREFLIGHT_PRIVATE_INPUTS','PREFLIGHT_AES_KEY','PREFLIGHT_CA_TLS','PREFLIGHT_BACKUP_AUTH','PREFLIGHT_SERVER_SCRAM','PREFLIGHT_ADMIN_READONLY'}:
            label = 'SOURCE_OR_TARGET_GATE'
        print('BLOCKED_V6_'+label)
        print('NO_ROLE_CHANGE_NO_BACKUP')
        return 2

if __name__=='__main__':
    raise SystemExit(main())
