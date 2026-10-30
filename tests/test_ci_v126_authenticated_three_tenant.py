"""V12.6 actual 3-company PG17 HTTPS browser regression contracts.

Static checks supplement (do not replace) the real Chrome/PG CI flow.
"""
from pathlib import Path
import ast
ROOT=Path(__file__).resolve().parents[1]

def test_disposable_auth_fixture_includes_three_companies():
    source=(ROOT/"scripts/ci_v106_real_pg_auth.py").read_text(encoding="utf-8")
    ast.parse(source)
    assert '("ci-ua", "ci-ub", "ci-uc")' in source
    assert "ONLY_EPHEMERAL_LOCAL_DATABASE" in source
    assert 'parts.get("host") != "127.0.0.1"' in source
    assert 'parts.get("user") != "postgres"' in source

def test_browser_real_company_c_denials_and_recovery():
    source=(ROOT/"scripts/ci_v93_https_pg_browser.py").read_text(encoding="utf-8")
    ast.parse(source)
    for evidence in (
        "email:'c@invalid.test'", "cMe.data.org_id!=='ci-c'",
        "cForeign.code!==404", "cCreate.code!==404",
        "cChat.code!==403", "cRevoked.code!==401",
        'login_success":4,"logout":3',
        "JW_V127_PG17_QUOTE_ORDER_DRAFT_A_B_C_PASS",
    ):
        assert evidence in source
    assert "ONLY_EPHEMERAL_LOCAL_DATABASE" in source
    assert "JW_INSECURE_LOCAL_DEV" in source
