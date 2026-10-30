"""V15.3 fail-closed SQL contract. Run only on exact repository checkout."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICIES = ROOT / "scripts/review/v153_restricted_review_writer_candidate.sql"
AB = ROOT / "scripts/review/v153_actual_pg_trade_rls_abc_rollback.sql"


def test_restricted_review_only_grants():
    sql = re.sub(r"--[^\n]*", "", POLICIES.read_text())
    assert len(re.findall(r"CREATE POLICY v153_", sql)) == 6
    assert len(re.findall(r"FOR INSERT TO jw_app_dev", sql)) == 3
    assert len(re.findall(r"FOR SELECT TO jw_app_dev", sql)) == 3
    assert "GRANT SELECT, INSERT ON TABLE" in sql
    for t in ("review_delivery_receipts_v151", "review_delivery_nonces_v151",
              "review_delivery_items_v151"):
        assert t in sql
    assert "review_signup_requests_v151" not in sql
    assert "review_signup_nonces_v151" not in sql
    for term in ("GRANT ALL", "UPDATE ON TABLE", "DELETE ON TABLE",
                 "SECURITY DEFINER", "TO anon", "TO authenticated", "TO PUBLIC"):
        assert term not in sql


def test_tenant_and_admin_policy_present_on_both_read_and_write():
    sql = re.sub(r"--[^\n]*", "", POLICIES.read_text())
    assert "current_org_from_session()" in sql
    assert sql.count("stage_identity_v84()") >= 4
    assert sql.count("actor_role='admin'") >= 2
    assert "a.actor_role = 'admin'" in sql
    assert "o.status='fulfilled'" in sql
    assert "o.review_state='acknowledged'" in sql


def test_actual_pg_abc_and_non_admin_denial_fixture_present():
    sql = re.sub(r"--[^\n]*", "", AB.read_text())
    for guard in (
        "FAIL_V153_A_SESSION", "FAIL_V153_A_CANNOT_READ_WRITES",
        "FAIL_V153_B_CROSS_TENANT_READ", "FAIL_V153_B_CROSS_TENANT_INSERT",
        "FAIL_V153_UNKNOWN_SESSION_READ", "FAIL_V153_UNKNOWN_SESSION_INSERT",
        "FAIL_V153_NON_ADMIN_CAN_READ_REVIEW_EVIDENCE",
        "FAIL_V153_NON_ADMIN_CAN_INSERT_REVIEW_EVIDENCE",
        "FAIL_V153_POLICY_COUNT", "FAIL_V153_SIGNUP_POLICY_EXPOSED",
    ):
        assert guard in sql
    assert "v153-member@invalid.test" in sql
    assert "actor_role='member'" in sql
    for forbidden in ("COMMIT;", "INSERT INTO jw_dev.payments",
                      "INSERT INTO jw_dev.invoices", "DROP TABLE"):
        assert forbidden not in sql
