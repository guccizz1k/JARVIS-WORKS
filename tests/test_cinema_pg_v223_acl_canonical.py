"""Regression for canonical effective ACL comparison across disposable restore owners."""
from scripts.pg_backup_v223 import SIGNATURE_QUERIES

def test_acl_signature_uses_effective_grants_not_raw_oids():
    q = SIGNATURE_QUERIES["acl"]
    assert "aclexplode(coalesce(c.relacl" in q
    assert "acldefault(" in q
    assert "a.grantor=c.relowner" in q
    assert "a.grantee=c.relowner" in q
    assert "a.grantee=0" in q
    assert "a.privilege_type" in q
    assert "a.is_grantable" in q
    assert "jsonb_agg" in q
    assert "c.relacl)::text" not in q

def test_constraint_gate_remains_strict():
    query = SIGNATURE_QUERIES["constraints"]
    # PostgreSQL owns precedence-aware rendering; client-side stripping of
    # parentheses or filtering to CHECK-only would weaken the gate.
    assert "md5(pg_get_constraintdef(k.oid, true))" in query
    assert "FROM pg_constraint k JOIN pg_class c" in query
    assert "k.contype" not in query
    assert "regexp_replace" not in query
    assert "replace(" not in query
