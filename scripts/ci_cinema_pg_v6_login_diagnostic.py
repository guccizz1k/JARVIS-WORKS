"""V6 restricted login diagnostic: allowlisted categories only, no secret output."""
from __future__ import annotations
import contextlib
import io

ALLOWED=('identity_or_readonly','business_table_count_changed',
 'unexpected_write_privilege','role_bypassrls_missing','source_role_not_least_privilege')

class LoginBlocked(Exception):pass

def classify(output):
    # Original checker prints either a fixed failure category or a Python
    # exception class in brackets. Never echo arbitrary remote/server text.
    if 'SOURCE_AUTH_ONLY_PASS' in output:
        return 'PASS'
    if 'source role does not meet the expected identity/privileges' in output:
        return 'SOURCE_IDENTITY_OR_PRIVILEGES'
    if 'live read-only login or guard failed' in output:
        for name in ('OperationalError','InterfaceError','ProgrammingError',
                     'DataError','ValueError','OSError'):
            if '['+name+']' in output:
                return 'SOURCE_LOGIN_'+name.upper()
        return 'SOURCE_LOGIN_OTHER_ERROR'
    if 'use the approved Codespace only' in output:
        return 'CODESPACE_GUARD'
    return 'SOURCE_LOGIN_UNCLASSIFIED'

def stage_login():
    from scripts import ci_cinema_pg_u as live
    out=io.StringIO()
    with contextlib.redirect_stdout(out):
        code=live.main()
    result=classify(out.getvalue())
    if code!=0 or result!='PASS':
        # Fixed category only; the original output may contain confidential data.
        print('V6_RESTRICTED_LOGIN_'+result)
        raise LoginBlocked(result)
    return {'login':'PASS','tables_expected':live.EXPECTED_TABLES}
