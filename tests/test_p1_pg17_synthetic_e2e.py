"""CI-only real PostgreSQL 17 round-trip using generated synthetic data.

Two disposable loopback Docker databases are required. Never use any real DSN.
"""
from __future__ import annotations

import base64
from pathlib import Path

import psycopg

from scripts import pg_backup_v223 as backup

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
        assert source.execute("SELECT count(*) FROM jw_dev.records").fetchone()[0] == 120
    backup.provision_ephemeral_marker(TARGET, TOKEN)
    results = backup.run(SOURCE, TARGET, schema="jw_dev", workdir=tmp_path, real_source=False)
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
