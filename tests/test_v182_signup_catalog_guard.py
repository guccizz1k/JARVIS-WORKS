"""V18.2: independent static contract and 26 mutation-based regression cases.

Actual catalog gate is separately executed against genuine Supabase PG17.
These structural checks are *not* a substitute for DB evidence.
"""
from __future__ import annotations

from pathlib import Path
import re

import pytest

CATALOG=Path(__file__).resolve().parents[1]/"scripts/review/v145_signup_readiness_readonly.sql"


def guarded(src: str) -> bool:
    """Fail closed on dangerous / falsely optimistic readiness SQL changes."""
    statement=re.sub(r"(?m)^\s*--.*$","",src)
    compact=re.sub(r"\s+"," ",statement).strip()
    required=(
        "WITH controls AS ( SELECT",
        "schemaname='jw_dev' AND tablename='users'",
        "indexname='jw_v87_users_email_normalized_unique'",
        "indexname='messenger_companies_business_number_key'",
        "rolname IN ('jw_stage1_trade_20261030','jw_stage1_auth_20261030')",
        "AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolinherit",
        ") = 2 AS split_restricted_logins",
        "WHERE n.nspname='jw_dev' AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity ) = 43 AS forced_rls_baseline",
        "WHERE n.nspname='jw_dev' AND c.relkind='r' ) = 43 AS exact_43_table_scope",
        "SELECT count(*) FROM pg_policies WHERE schemaname='jw_dev' ) = 62 AS reviewed_62_policy_scope",
        "p.proname='v85_auth_issue_session'",
        "AND split_restricted_logins AND forced_rls_baseline",
        "AND exact_43_table_scope AND reviewed_62_policy_scope",
        "AND existing_session_issuer",
        "THEN 'PASS_EXISTING_PREREQUISITES_ONLY'",
        "ELSE 'FAIL_EXISTING_PREREQUISITES'",
        "'NOT_VERIFIED'::text AS official_business_owner_proof",
        "'NOT_VERIFIED'::text AS email_delivery_and_password_reset",
        "'NOT_VERIFIED'::text AS public_signup_https_e2e",
        "'BLOCKED'::text AS stage2_release_acceptance",
        "FROM controls;",
    )
    if any(piece not in compact for piece in required):
        return False
    if compact.count("= 43 AS")!=2 or compact.count("= 62 AS")!=1:
        return False
    if re.search(r"\b(INSERT|UPDATE|DELETE|ALTER|DROP|CREATE|GRANT|REVOKE|TRUNCATE|COPY|CALL|DO|EXECUTE)\b",compact,re.I):
        return False
    if compact.count(";")!=1:
        return False
    return True


def test_v182_unchanged_contract_is_readonly_and_non_release():
    sql=CATALOG.read_text(encoding="utf-8")
    assert guarded(sql)
    assert "official_business_owner_proof" in sql
    assert "stage2_release_acceptance" in sql
    assert "NOT_VERIFIED" in sql and "'BLOCKED'" in sql


@pytest.mark.parametrize(("original","malicious"),[
    ("= 43 AS forced_rls_baseline","= 35 AS forced_rls_baseline"),
    ("= 43 AS forced_rls_baseline","= 44 AS forced_rls_baseline"),
    ("= 43 AS exact_43_table_scope","= 35 AS exact_43_table_scope"),
    ("= 43 AS exact_43_table_scope","= 44 AS exact_43_table_scope"),
    ("= 62 AS reviewed_62_policy_scope","= 61 AS reviewed_62_policy_scope"),
    ("= 62 AS reviewed_62_policy_scope","= 63 AS reviewed_62_policy_scope"),
    ("c.relforcerowsecurity","TRUE"),
    ("c.relrowsecurity","TRUE"),
    ("WHERE n.nspname='jw_dev'","WHERE n.nspname='public'"),
    ("AND NOT rolsuper","AND rolsuper"),
    ("AND NOT rolbypassrls","AND rolbypassrls"),
    ("AND NOT rolinherit","AND rolinherit"),
    ("AND rolcanlogin","AND NOT rolcanlogin"),
    ("= 2 AS split_restricted_logins","= 1 AS split_restricted_logins"),
    ("'jw_stage1_trade_20261030'","'postgres'"),
    ("'jw_stage1_auth_20261030'","'postgres'"),
    ("'jw_v87_users_email_normalized_unique'","'nonunique_index'"),
    ("'messenger_companies_business_number_key'","'nonunique_index'"),
    ("p.proname='v85_auth_issue_session'","p.proname='fake_session'"),
    ("AND split_restricted_logins AND forced_rls_baseline","AND TRUE"),
    ("AND exact_43_table_scope AND reviewed_62_policy_scope","AND TRUE"),
    ("AND existing_session_issuer","AND TRUE"),
    ("THEN 'PASS_EXISTING_PREREQUISITES_ONLY'","THEN 'PASS_PUBLIC_SIGNUP_AND_BANK'"),
    ("ELSE 'FAIL_EXISTING_PREREQUISITES'","ELSE 'PASS_EXISTING_PREREQUISITES'"),
    ("'NOT_VERIFIED'::text AS official_business_owner_proof","'VERIFIED'::text AS official_business_owner_proof"),
    ("'NOT_VERIFIED'::text AS email_delivery_and_password_reset","'VERIFIED'::text AS email_delivery_and_password_reset"),
    ("'NOT_VERIFIED'::text AS public_signup_https_e2e","'VERIFIED'::text AS public_signup_https_e2e"),
    ("'BLOCKED'::text AS stage2_release_acceptance","'PASS'::text AS stage2_release_acceptance"),
    ("FROM controls;","FROM controls; DELETE FROM jw_dev.users;"),
    ("WITH controls AS (","WITH controls AS ( UPDATE jw_dev.users SET name='x';"),
])
def test_v182_thirty_catalog_counterexamples_fail_closed(original,malicious):
    source=CATALOG.read_text(encoding="utf-8")
    assert original in source
    forged=source.replace(original,malicious,1)
    assert forged!=source
    assert guarded(forged) is False


def test_v182_comments_cannot_disable_guard():
    src=CATALOG.read_text(encoding="utf-8")
    altered=src.replace("AND existing_session_issuer","-- AND existing_session_issuer")
    assert not guarded(altered)


def test_v182_no_write_statement_even_if_guards_remain():
    src=CATALOG.read_text(encoding="utf-8")
    assert not guarded(src+"\\nDROP TABLE jw_dev.users;")


def test_v182_policy_and_rls_are_separate_requirements():
    src=CATALOG.read_text(encoding="utf-8")
    assert not guarded(src.replace("AND exact_43_table_scope AND reviewed_62_policy_scope","AND exact_43_table_scope"))
