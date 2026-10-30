"""Offline migration/permission safety constraints for Stage 2-3 preflights."""
from pathlib import Path
import re

BASE = Path(__file__).resolve().parents[1] / "scripts/review"


def _sql(filename):
    return (BASE / filename).read_text()


def test_stage3_catalog_query_is_read_only_and_never_grants():
    sql = _sql("v146_delivery_posting_readiness_readonly.sql")
    normalized = re.sub(r"--[^\n]*", "", sql).upper()
    for forbidden in ("INSERT INTO ", "UPDATE JW_DEV.", "DELETE FROM ", "DROP TABLE",
                      "ALTER TABLE", "GRANT ", "REVOKE ", "TRUNCATE ", "COMMIT;",
                      "DO $$", "CREATE "):
        assert forbidden not in normalized
    assert "PHYSICAL_DELIVERY_LEDGER" in normalized
    assert "NOT_VERIFIED'::TEXT AS PHYSICAL_DELIVERY_HUMAN_ACCEPTANCE" in normalized
    assert "'BLOCKED'::TEXT AS STAGE3_RELEASE_ACCEPTANCE" in normalized


def test_stage2_verdict_does_not_claim_signup_approval():
    sql = _sql("v145_signup_readiness_readonly.sql")
    assert "PASS_EXISTING_PREREQUISITES_ONLY" in sql
    assert "'BLOCKED'::text AS stage2_release_acceptance" in sql
    assert "'NOT_VERIFIED'::text AS public_signup_https_e2e" in sql
