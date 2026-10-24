"""Fail-closed static guard for V8.9↔V9.0 PG login boundary.

These assertions supplement (not replace) the 18 executable FastAPI
mock-DB integration tests in the restored V8.9 tree.
"""
from pathlib import Path

SOURCE = (Path(__file__).parent / 'v89_integration/app/pg_v90_integrated_entry.py').read_text()


def test_server_refuses_business_login_with_auth_stage_membership():
    assert "pg_has_role(session_user,'jw_auth_stage_v85','SET')" in SOURCE
    assert "if cur.fetchone() != (False,)" in SOURCE
    assert "Business login can adopt authentication role" in SOURCE


def test_preflight_runs_before_data_role_switch():
    body = SOURCE.split("def _pg_validated_cursor", 1)[1].split("def _session_hash", 1)[0]
    assert body.index("pg_has_role(session_user") < body.index("cur.execute('SET LOCAL ROLE jw_app_dev')")


def test_business_data_session_is_server_derived_not_browser_derived():
    assert "hashlib.sha256(token.encode('utf-8')).hexdigest()" in SOURCE
    assert "SET LOCAL ROLE jw_app_dev" in SOURCE
    assert "stage_identity_v84()" in SOURCE


def test_dev_only_and_https_tenant_origins_remain_enforced():
    assert "JW_PG_MESSENGER_V90" in SOURCE
    assert "not x.startswith('https://')" in SOURCE
    assert "JW_INSECURE_LOCAL_DEV" in SOURCE
