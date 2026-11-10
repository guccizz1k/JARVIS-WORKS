"""Regressions found by the first real CI run of the V22.3 double-PG17 job (run 42213814751).

1. ``pg_dump --version`` on the official postgres:17 image prints a distribution suffix in
   parentheses; the old parser read only the text after the LAST ``)`` and refused the tool.
2. ``aclexplode('{}'::aclitem[])`` raises "ACL arrays must be one-dimensional".
3. An explicit owner-only ACL (left by GRANT then DROP OWNED) is not dumped, so the restored
   table has NULL relacl: the signature must compare the EFFECTIVE ACL, not its spelling.
The behavioural proof is the CI job itself on two PG17 containers; these pin the code.
"""
from pathlib import Path

import pytest

from scripts import pg_backup_v223 as pb

SRC = (Path(__file__).resolve().parents[1] / "scripts/pg_backup_v223.py").read_text()


@pytest.mark.parametrize("out,major", [
    ("pg_dump (PostgreSQL) 17.11 (Debian 17.11-1.pgdg13+2)\n", 17),
    ("pg_restore (PostgreSQL) 17.11 (Debian 17.11-1.pgdg13+2)\n", 17),
    ("pg_dump (PostgreSQL) 17.2\n", 17),
    ("pg_dump (PostgreSQL) 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)\n", 16),
    ("pg_dump (PostgreSQL) 18beta1\n", None),
    ("pg_dump (PostgreSQL) 9.6.24\n", 9),
])
def test_tool_version_ignores_distribution_suffix(out, major):
    assert pb.parse_tool_major(out) == major


@pytest.mark.parametrize("out", ["", "garbage", "pg_dump 17.2", "(PostgreSQL) 17", None,
                                 "pg_dump (EnterpriseDB) 17.2"])
def test_unknown_tool_version_is_refused(out):
    assert pb.parse_tool_major(out) is None


def test_tool_major_refuses_unknown_and_too_old(monkeypatch):
    class R:
        def __init__(self, stdout):
            self.stdout = stdout
    monkeypatch.setattr(pb.subprocess, "run", lambda *a, **k: R("pg_dump (PostgreSQL) 17.11 (Debian 17.11-1)\n"))
    assert pb.tool_major("pg_dump") == 17
    pb.require_pg17_tools()
    monkeypatch.setattr(pb.subprocess, "run", lambda *a, **k: R("pg_dump (PostgreSQL) 16.4 (Debian)\n"))
    with pytest.raises(pb.BackupError, match="BLOCKED_V223_PG_DUMP_OLDER_THAN_17"):
        pb.require_pg17_tools()
    monkeypatch.setattr(pb.subprocess, "run", lambda *a, **k: R("nonsense"))
    with pytest.raises(pb.BackupError, match="BLOCKED_V223_TOOL_VERSION_UNKNOWN"):
        pb.tool_major("pg_dump")


def test_roles_in_acl_never_explodes_an_empty_literal_array():
    assert "'{}'::aclitem[]" not in SRC
    assert "LATERAL aclexplode(c.relacl) a" in SRC and "c.relacl IS NOT NULL" in SRC


def test_signature_compares_effective_acl():
    acl = pb.SIGNATURE_QUERIES["acl"]
    assert "aclexplode(coalesce(c.relacl," in acl
    assert "acldefault(" in acl
    assert "a.privilege_type" in acl and "a.is_grantable" in acl
    assert "a.grantor=c.relowner" in acl and "a.grantee=c.relowner" in acl
    assert "jsonb_agg" in acl and "ORDER BY" in acl
    assert "c.relacl)::text" not in acl
