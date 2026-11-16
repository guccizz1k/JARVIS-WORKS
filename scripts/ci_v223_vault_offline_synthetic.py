"""Actual PG17 execution of vault-offline restore tooling on SYNTHETIC data only.

A single disposable PostgreSQL17 cluster is used sequentially to create a
synthetic archive, remove the source fixture, and test restoration. This is
NOT an independent real development backup, source snapshot verification, or B2/B3.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import tempfile
from pathlib import Path

import psycopg
from psycopg import sql

from scripts import ci_v223_vault_offline_restore as offline
from scripts import pg_backup_v223 as pb


def main() -> None:
    dsn = os.environ.get("JW_PG_TARGET_ADMIN_DSN", "")
    token = secrets.token_hex(16)
    os.environ[pb.EPHEMERAL_TOKEN_ENV] = token
    opts = offline.ephemeral_target_options(dsn)
    pb.require_pg17_tools()
    seed = "jw_v223_synth_" + secrets.token_hex(5)
    with tempfile.TemporaryDirectory(prefix="jw-v223-vault-ci-", dir="/tmp") as temp:
        root = Path(temp)
        plain = root / "generated.dump"
        cipher = root / "synthetic-existing.jwpgbk"
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(seed)))
        try:
            with psycopg.connect(pb.dsn_with_dbname(dsn, seed), autocommit=True) as source:
                source.execute("CREATE SCHEMA jw_dev")
                source.execute("CREATE TABLE jw_dev.fixture (id bigint PRIMARY KEY, amount integer NOT NULL)")
                source.execute("INSERT INTO jw_dev.fixture VALUES (1,100),(2,250)")
                source.execute("ALTER TABLE jw_dev.fixture ENABLE ROW LEVEL SECURITY")
                source.execute("ALTER TABLE jw_dev.fixture FORCE ROW LEVEL SECURITY")
                source.execute("CREATE POLICY fixture_read ON jw_dev.fixture FOR SELECT USING (true)")
            pb.run_tool(["pg_dump","--format=custom","--no-owner","--schema=jw_dev",
                         "--file",str(plain)],{**opts,"dbname":seed},60)
        finally:
            with psycopg.connect(dsn, autocommit=True) as admin:
                admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(seed)))
        key = os.urandom(32)
        pb.encrypt_file(plain,cipher,key)
        plain.unlink()
        contents = cipher.read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(contents)).encode() + b"\0" + contents).hexdigest()
        pb.provision_ephemeral_marker(dsn,token)
        summary = offline.run(cipher,dsn,key,blob)
        assert summary["authenticated_ciphertext"]
        assert summary["restore_verified"]
        assert summary["target_proven_ephemeral"]
        assert summary["tables"]==1 and summary["rls"]==1 and summary["force_rls"]==1
        assert summary["policies"]==1
        assert summary["b3_existing_archive_restore"]=="PASS"
        assert summary["release_gate"]=="BLOCKED"
        assert summary["real_source_snapshot_parity"]=="NOT_VERIFIED"
        assert summary["source_database_contacted"] is False
        with psycopg.connect(dsn,autocommit=True) as admin:
            other={row[0] for row in admin.execute(
                "SELECT datname FROM pg_database WHERE NOT datistemplate")}
        assert other=={"postgres",pb.EPHEMERAL_MARKER_DB}, "Target cleanup failed"
        print("PASS_V223_EXISTING_ARCHIVE_OFFLINE_RESTORE_SYNTHETIC_PG17_ONLY")
        print("BLOCKED_REAL_B2_B3_OWNER_VAULT_KEY_AND_SNAPSHOT_PROVENANCE_REQUIRED")


if __name__ == "__main__":
    main()
