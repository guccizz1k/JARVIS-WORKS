"""CI-only real PostgreSQL 17 round-trip using generated synthetic data.

Two disposable loopback Docker databases are required. Never use any real DSN.
"""
from __future__ import annotations

import base64
from pathlib import Path

import psycopg

from scripts import pg_backup_v223 as backup
from scripts import p1_owner_archive_inventory_v223 as inventory

SOURCE = "postgresql://postgres:synthetic_only_change_not_needed@127.0.0.1:55432/postgres"
TARGET = "postgresql://postgres:synthetic_only_change_not_needed@127.0.0.1:55433/postgres"
TOKEN = "ci-local-target-fixture-not-for-production"


def test_full_pg17_synthetic_backup_encrypt_restore(tmp_path: Path, monkeypatch):
    assert backup.parse_dsn(SOURCE)["host"] == "127.0.0.1"
    assert backup.parse_dsn(TARGET)["host"] == "127.0.0.1"
    assert backup.parse_dsn(SOURCE)["port"] == "55432"
    assert backup.parse_dsn(TARGET)["port"] == "55433"
    monkeypatch.setenv("JW_PG_CI_ALLOW", "ONLY_EPHEMERAL_LOCAL_DATABASE")
    monkeypatch.setenv("JW_PG_TARGET_EPHEMERAL_TOKEN", TOKEN)
    monkeypatch.setenv("JW_PG_BACKUP_KEY", base64.urlsafe_b64encode(bytes(range(32))).decode())
    monkeypatch.delenv("JW_PG_EXPECT_SOURCE_HOST", raising=False)
    with psycopg.connect(SOURCE, autocommit=True) as source:
        assert source.execute("SHOW server_version_num").fetchone()[0].startswith("17")
        source.execute("CREATE SCHEMA jw_dev")
        source.execute("CREATE TABLE jw_dev.records (id bigint PRIMARY KEY, value text NOT NULL)")
        source.execute("INSERT INTO jw_dev.records SELECT x, md5(x::text) FROM generate_series(1, 120) AS x")
        source.execute("CREATE INDEX records_value_idx ON jw_dev.records(value)")
        source.execute("ALTER TABLE jw_dev.records ENABLE ROW LEVEL SECURITY")
        source.execute("ALTER TABLE jw_dev.records FORCE ROW LEVEL SECURITY")
        source.execute("CREATE POLICY read_all ON jw_dev.records FOR SELECT TO PUBLIC USING (true)")
        # This role is intentionally referenced by grants in the source.
        # The restore engine must create it NOLOGIN on the disposable target,
        # then remove that new cluster-global role after the restore DB is dropped.
        source.execute("CREATE ROLE jw_p1_synthetic_reader NOLOGIN")
        source.execute("GRANT USAGE ON SCHEMA jw_dev TO jw_p1_synthetic_reader")
        source.execute("GRANT SELECT ON jw_dev.records TO jw_p1_synthetic_reader")
        source.execute("CREATE ROLE jw_p1_existing_reader NOLOGIN")
        source.execute("GRANT SELECT ON jw_dev.records TO jw_p1_existing_reader")
        # Roles referenced exclusively by function/type ACLs must be discovered
        # before pg_restore or the restore will fail with a missing grantee.
        source.execute("CREATE FUNCTION jw_dev.synthetic_ping() RETURNS integer LANGUAGE sql AS 'SELECT 1'")
        source.execute("CREATE DOMAIN jw_dev.synthetic_label AS text")
        source.execute("CREATE ROLE jw_p1_function_only NOLOGIN")
        source.execute("CREATE ROLE jw_p1_type_only NOLOGIN")
        source.execute("GRANT EXECUTE ON FUNCTION jw_dev.synthetic_ping() TO jw_p1_function_only")
        source.execute("GRANT USAGE ON TYPE jw_dev.synthetic_label TO jw_p1_type_only")
        discovered = set(backup.roles_in_acl(source, "jw_dev"))
        assert {"jw_p1_function_only", "jw_p1_type_only"} <= discovered, discovered
        assert source.execute("SELECT count(*) FROM jw_dev.records").fetchone()[0] == 120
    with psycopg.connect(TARGET, autocommit=True) as target:
        target.execute("CREATE ROLE jw_p1_existing_reader NOLOGIN")
    backup.provision_ephemeral_marker(TARGET, TOKEN)
    results = backup.run(SOURCE, TARGET, schema="jw_dev", workdir=tmp_path, real_source=False)
    # Independently verify new archive inventory classification on an ACTUAL
    # PostgreSQL 17 pg_dump custom archive, not merely a fabricated PGDMP
    # string. No source/external data; plaintext is not written by inventory.
    real_fixture_ciphers = list(tmp_path.glob("*.jwpgbk"))
    assert len(real_fixture_ciphers) == 1
    assert inventory._single_chunk_postgres_magic(
        real_fixture_ciphers[0], bytes(range(32))
    ) == "AUTHENTICATED_PGDMP_HEADER_ONLY"
    assert backup.audit_encrypted_archive(
        real_fixture_ciphers[0], results["archive_sha256"], bytes(range(32))
    )["authenticated_decryption"] is True
    assert results["tables"] == 1
    assert results["signature_mismatches"] == [], results["signature_mismatch_diagnostics"]
    assert results["signature_digest_matches"] is True
    assert results["archive_sha256_matches"] is True
    assert results["restore_verified"] is True
    assert results["decrypt_sha256_matches"] is True
    assert results["tamper_rejected"] is True
    assert results["wrong_key_rejected"] is True
    assert results["truncation_rejected"] is True
    assert results["partial_dump_restore_rejected"] is True
    assert results["verdict"] != "PASS"
    assert results["source_is_real_dev_db"] is False
    assert results["restore_db"].startswith("jw_v223_")
    assert set(results["signature_component_sha256"]) == {"source", "restored"}
    assert not list(tmp_path.glob("*.dump"))
    assert not list(tmp_path.glob("*.back"))
    assert not list(tmp_path.glob("*.half"))
    with psycopg.connect(TARGET, autocommit=True) as target:
        assert not target.execute(
            "SELECT datname FROM pg_database WHERE datname LIKE 'jw_v223_%'"
        ).fetchall()
        assert target.execute(
            "SELECT count(*) FROM pg_roles WHERE rolname='jw_p1_synthetic_reader'"
        ).fetchone()[0] == 0, "restore-created cluster role leaked after cleanup"
        for new_role in ("jw_p1_function_only", "jw_p1_type_only"):
            assert target.execute(
                "SELECT count(*) FROM pg_roles WHERE rolname=%s", (new_role,)
            ).fetchone()[0] == 0, "function/type ACL restore-created role leaked"
        assert target.execute(
            "SELECT count(*) FROM pg_roles WHERE rolname='postgres'"
        ).fetchone()[0] == 1, "pre-existing restore admin role must remain"
        assert target.execute(
            "SELECT count(*) FROM pg_roles WHERE rolname='jw_p1_existing_reader'"
        ).fetchone()[0] == 1, "pre-existing auxiliary role must never be deleted"

    # Inject a failure after a new disposable restore DB and role are created.
    # The finally path must clean up the failed restore without touching
    # previously existing cluster roles, the marker or source records.
    original_run_tool = backup.run_tool

    def fail_during_real_restore(args, opts, timeout):
        if args[0] == "pg_restore" and "--dbname" in args and "--list" not in args:
            raise backup.BackupError("TEST_INJECTED_RESTORE_FAILURE")
        return original_run_tool(args, opts, timeout)

    monkeypatch.setattr(backup, "run_tool", fail_during_real_restore)
    with __import__("pytest").raises(backup.BackupError, match="TEST_INJECTED_RESTORE_FAILURE"):
        backup.run(SOURCE, TARGET, schema="jw_dev", workdir=tmp_path / "injected", real_source=False)
    with psycopg.connect(TARGET, autocommit=True) as target:
        assert not target.execute(
            "SELECT datname FROM pg_database WHERE datname LIKE 'jw_v223_%'"
        ).fetchall(), "failed restore leaked an ephemeral database"
        assert target.execute(
            "SELECT count(*) FROM pg_roles WHERE rolname='jw_p1_synthetic_reader'"
        ).fetchone()[0] == 0, "failed restore leaked a temporary role"
        assert target.execute(
            "SELECT count(*) FROM pg_roles WHERE rolname='jw_p1_existing_reader'"
        ).fetchone()[0] == 1, "failed restore deleted a preexisting role"
        assert target.execute(
            "SELECT count(*) FROM pg_database WHERE datname='jw_ephemeral_marker'"
        ).fetchone()[0] == 1, "failed restore damaged the ephemeral target marker"
    with psycopg.connect(SOURCE, autocommit=True) as source:
        assert source.execute("SELECT count(*) FROM jw_dev.records").fetchone()[0] == 120
    assert not list((tmp_path / "injected").glob("*.dump"))
    assert not list((tmp_path / "injected").glob("*.back"))


def test_pg17_real_catalog_role_probe_rejects_view_insert_and_sequence_nextval():
    """Independent disposable PG17 proof: SELECT-only source probes see both capabilities."""
    with psycopg.connect(SOURCE, autocommit=True) as admin:
        admin.execute("CREATE SCHEMA jw_p1_privilege_probe")
        admin.execute("CREATE TABLE jw_p1_privilege_probe.base (id bigint PRIMARY KEY)")
        admin.execute("CREATE VIEW jw_p1_privilege_probe.writable_view AS SELECT id FROM jw_p1_privilege_probe.base")
        admin.execute("CREATE SEQUENCE jw_p1_privilege_probe.mutable_sequence")
        admin.execute("CREATE ROLE jw_p1_privilege_probe_reader NOLOGIN")
        try:
            admin.execute("GRANT USAGE ON SCHEMA jw_p1_privilege_probe TO jw_p1_privilege_probe_reader")
            admin.execute("GRANT INSERT ON jw_p1_privilege_probe.writable_view TO jw_p1_privilege_probe_reader")
            admin.execute("GRANT USAGE ON SEQUENCE jw_p1_privilege_probe.mutable_sequence TO jw_p1_privilege_probe_reader")
            admin.execute("SET ROLE jw_p1_privilege_probe_reader")
            try:
                facts = backup.fetch_role_facts(admin, "jw_p1_privilege_probe")
                violations = backup.evaluate_source_privileges(facts)
                assert facts["tables_writable"] >= 1, facts
                assert facts["sequences_writable"] == 1, facts
                assert "tables_writable" in violations
                assert "sequences_writable" in violations
            finally:
                admin.execute("RESET ROLE")
        finally:
            admin.execute("DROP SCHEMA jw_p1_privilege_probe CASCADE")
            admin.execute("DROP ROLE jw_p1_privilege_probe_reader")
