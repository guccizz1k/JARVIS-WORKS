"""CI-only real PostgreSQL 17 round-trip using generated synthetic data.

Two disposable loopback Docker databases are required. Never use any real DSN.
"""
from __future__ import annotations

import base64
from pathlib import Path

import psycopg

from scripts import pg_backup_v223 as backup
from scripts import p1_owner_archive_inventory_v223 as inventory
from scripts import p1_owner_archive_deep_v223 as deep

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
    # Actual synthetic PostgreSQL 17 custom-format archive TOC via stdin
    # (no plaintext temp file or connection; parsing is NOT a restore).
    mem = deep.authenticated_plain_in_memory(real_fixture_ciphers[0])
    try:
        toc_status, toc_tables = deep.pg17_toc_counts(mem)
        assert toc_status == "PG17_TOC_PARSED_NOT_RESTORED"
        assert toc_tables == 1
    finally:
        mem.clear()
    # Perform a REAL local full-data pg_restore of the synthetic encrypted
    # PG17 backup into a networkless, volume-free, temporary PG17 Docker server.
    # The owner-only tool never contacts the source DB or transfers customer
    # data; its "offline" PASS cannot prove the origin of historical archives.
    import shutil
    from scripts import p1_owner_one_shot_v223 as owner
    from scripts import p1_owner_offline_restore_v223 as offline
    owner_root = tmp_path / "owner-restore" / "backups"
    owner_root.mkdir(mode=0o700, parents=True)
    archive_group = owner_root / "jw_v223_ci"
    archive_group.mkdir(mode=0o700)
    candidate = archive_group / "ci.jwpgbk"
    shutil.copyfile(real_fixture_ciphers[0], candidate)
    candidate.chmod(0o600)
    monkeypatch.setattr(owner, "_owner_backup_dir", lambda: owner_root)
    monkeypatch.setenv("CODESPACES", "true")
    monkeypatch.setenv("JW_PG_OFFLINE_RESTORE_ACK", offline.ACK)
    offline_report = offline.run_offline()
    # Emit only fixed safe diagnostic labels/counts on CI failure.
    offline_diagnosis = {k: offline_report.get(k) for k in (
        "blocker", "offline_restore_execution", "offline_restored_archive_count",
        "offline_restore_failure_count", "offline_restore_skipped_budget_count",
        "failure_categories", "container_removed")}
    assert offline_report["offline_restored_archive_count"] == 1, offline_diagnosis
    assert offline_report["offline_other_table_archive_count"] == 1, offline_report
    assert offline_report["offline_65_table_archive_count"] == 0, offline_report
    assert offline_report["offline_restore_execution"] == "PASS_LOCAL_ONLY", offline_report
    assert offline_report["container_removed"] == "PASS", offline_report
    assert offline_report["remote_storage_proven"] is False
    assert offline_report["overall"] == "BLOCKED"
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


def test_actual_pg17_constraint_reparse_restore_and_semantic_mutation(tmp_path: Path):
    """Actual PG17 --schema dump/restore with a nested AND CHECK, then mutation.

    The original historical bug was default deparser parenthesization drifting
    across a PG17 upgrade. The engine's precedence-aware pretty deparser must
    preserve identical semantics after dump while still detecting real changes.
    Only disposable synthetic PG17 source/target containers are touched.
    """
    import hashlib
    import psycopg
    from psycopg import errors

    schema = "jw_p1_canonical_probe"
    src_opts, dst_opts = backup.parse_dsn(SOURCE), backup.parse_dsn(TARGET)
    dump = tmp_path / "constraint_synthetic.dump"
    # Both clusters are the disposable PG17 CI fixtures, not customer databases.
    assert src_opts["host"] == "127.0.0.1" and src_opts["port"] == "55432"
    assert dst_opts["host"] == "127.0.0.1" and dst_opts["port"] == "55433"
    with psycopg.connect(SOURCE, autocommit=True) as src, psycopg.connect(TARGET, autocommit=True) as dst:
        src.execute("CREATE SCHEMA jw_p1_canonical_probe")
        try:
            src.execute("""
                CREATE TABLE jw_p1_canonical_probe.sample (
                    id integer PRIMARY KEY,
                    display_name text,
                    CONSTRAINT name_check CHECK(
                        (length(display_name) >= 2 AND length(display_name) <= 120)
                        AND display_name = btrim(display_name)
                    )
                )
            """)
            before = backup.fetch_signature(src, schema)
            # This captures the actual DB server's normalized pretty deparser,
            # not a guessed textual SQL normalizer.
            original = dict(before["constraints"])["sample.name_check"]
            row = src.execute("""
                SELECT pg_get_constraintdef(k.oid, true)
                FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
                JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname=%s AND c.relname='sample' AND k.conname='name_check'
            """, (schema,)).fetchone()
            assert original == hashlib.md5(row[0].encode()).hexdigest()
            backup.run_tool(["pg_dump", "--format=custom", f"--schema={schema}",
                             "--no-owner", "--file", str(dump)], src_opts, timeout=60)
            backup.run_tool(["pg_restore", "--no-owner", "--no-acl", "--exit-on-error",
                             "--dbname", "postgres", str(dump)], dst_opts, timeout=60)
            after = backup.fetch_signature(dst, schema)
            assert backup.diff_signatures(before, after) == []
            assert dict(after["constraints"])["sample.name_check"] == original
            dst.execute("INSERT INTO jw_p1_canonical_probe.sample VALUES (1,'ab')")
            dst.execute("DELETE FROM jw_p1_canonical_probe.sample WHERE id=1")
            dst.execute("ALTER TABLE jw_p1_canonical_probe.sample DROP CONSTRAINT name_check")
            dst.execute("""
                ALTER TABLE jw_p1_canonical_probe.sample ADD CONSTRAINT name_check
                CHECK (length(display_name) >= 3 AND length(display_name) <= 120
                       AND display_name = btrim(display_name))
            """)
            changed = backup.fetch_signature(dst, schema)
            labels = backup.diff_signatures(before, changed)
            assert "constraints:sample?name_check" in labels
            assert "sample.name_check" not in repr(labels)
            with __import__("pytest").raises(errors.CheckViolation):
                dst.execute("INSERT INTO jw_p1_canonical_probe.sample VALUES (2,'ab')")
            dst.execute("ALTER TABLE jw_p1_canonical_probe.sample DROP CONSTRAINT name_check")
            missing = backup.fetch_signature(dst, schema)
            assert backup.diagnose_signature_mismatches(before, missing)["constraints"]["missing_in_restore"] == 1
        finally:
            dst.execute("DROP SCHEMA IF EXISTS jw_p1_canonical_probe CASCADE")
            src.execute("DROP SCHEMA IF EXISTS jw_p1_canonical_probe CASCADE")
    assert dump.exists()



def test_actual_65_table_legacy_compatible_archive_restores_in_networkless_tmpfs(tmp_path: Path, monkeypatch):
    """One-step REAL synthetic PG17 test matching the owner's 65-table shape.

    Includes nested CHECK, FK, FORCE RLS and a policy to a source-only role.
    The local offline restorer must create this role as NOLOGIN INSIDE the
    disposable Docker container, then full-data restore and remove it.
    Nothing touches the user's private backup or any remote database.
    """
    import shutil
    import os
    from psycopg import sql
    from scripts import p1_owner_one_shot_v223 as owner
    from scripts import p1_owner_offline_restore_v223 as offline

    db = "jw_p1_ci65_" + os.urandom(5).hex()
    role = "jw_p1_ci65_policy_" + os.urandom(3).hex()
    source_admin = psycopg.connect(SOURCE, autocommit=True)
    created_db = False
    created_role = False
    try:
        source_admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
        created_role = True
        source_admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db)))
        created_db = True
        source_db = backup.dsn_with_dbname(SOURCE, db)
        with psycopg.connect(source_db, autocommit=True) as conn:
            conn.execute("CREATE SCHEMA jw_dev")
            conn.execute("""
                CREATE TABLE jw_dev.parent (
                    id integer PRIMARY KEY,
                    name text NOT NULL,
                    CONSTRAINT parent_check CHECK (
                        (length(name) >= 2 AND length(name) <= 120)
                        AND name=btrim(name))
                )
            """)
            conn.execute("""
                CREATE TABLE jw_dev.child (
                    id integer PRIMARY KEY,
                    parent_id integer REFERENCES jw_dev.parent(id) DEFERRABLE INITIALLY DEFERRED,
                    label text CHECK (length(label) <= 120)
                )
            """)
            for i in range(63):
                conn.execute(sql.SQL(
                    "CREATE TABLE jw_dev.{} (id integer PRIMARY KEY, payload text NOT NULL)"
                ).format(sql.Identifier(f"item_{i}")))
            conn.execute("ALTER TABLE jw_dev.parent ENABLE ROW LEVEL SECURITY")
            conn.execute("ALTER TABLE jw_dev.parent FORCE ROW LEVEL SECURITY")
            conn.execute(sql.SQL(
                "CREATE POLICY allow_owner ON jw_dev.parent FOR SELECT TO {} USING (true)"
            ).format(sql.Identifier(role)))
            conn.execute("INSERT INTO jw_dev.parent VALUES (1,'synthetic')")
            conn.execute("INSERT INTO jw_dev.child VALUES (1,1,'synthetic')")
            for i in range(63):
                conn.execute(sql.SQL(
                    "INSERT INTO jw_dev.{} VALUES (1,'synthetic')"
                ).format(sql.Identifier(f"item_{i}")))
            tables = backup.fetch_signature(conn, "jw_dev")["tables"]
            assert len(tables) == 65
            # Build a trusted READ-ONLY synthetic source reference separately
            # from the tested offline restore implementation.
            import hashlib
            constraint_sql = """
                SELECT encode(sha256(convert_to(coalesce(string_agg(
                  c.relname||'.'||k.conname||'='||pg_get_constraintdef(k.oid,true),
                  E'\n' ORDER BY c.relname,k.conname),''),'UTF8')),'hex')
                FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
                JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='jw_dev';
            """
            expected_constraints = conn.execute(constraint_sql).fetchone()[0]
            row_manifest_parts = []
            expected_rows = 0
            for (table,) in conn.execute("""
                SELECT c.relname FROM pg_class c
                JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p')
                ORDER BY c.relname
            """).fetchall():
                digest_sql = sql.SQL("""
                    SELECT count(*)::bigint,
                    coalesce(sum(('x'||substr(h,1,16))::bit(64)::bigint::numeric),0)::text,
                    coalesce(sum(('x'||substr(h,17,16))::bit(64)::bigint::numeric),0)::text
                    FROM (SELECT md5(x::text) h FROM {}.{} x) z
                """).format(sql.Identifier("jw_dev"), sql.Identifier(table))
                count, lo, hi = conn.execute(digest_sql).fetchone()
                expected_rows += count
                row_manifest_parts.append(f"{table}:{count}:{lo}:{hi}")
            expected_data = hashlib.sha256(
                "\n".join(row_manifest_parts).encode("utf-8")).hexdigest()
            assert expected_rows == 65

        dump_path = tmp_path / "ci65.custom"
        key = bytes(range(32))
        opts = backup.parse_dsn(source_db)
        backup.run_tool(["pg_dump", "--format=custom", "--schema=jw_dev",
                         "--no-owner", "--file", str(dump_path)],
                        opts, timeout=90)
        root = tmp_path / "owner-only" / "backups"
        root.mkdir(mode=0o700, parents=True)
        nested = root / "jw_v223_ci"
        nested.mkdir(mode=0o700)
        encrypted = nested / "synthetic.jwpgbk"
        backup.encrypt_file(dump_path, encrypted, key)
        encrypted.chmod(0o600)
        # The owner's 2026-11-17 files predate V2. Reproduce the ORIGINAL
        # V1 32-bit-prefix + 64-bit-counter authenticated format with an
        # independent encryptor, then restore both V1 and V2 via the exact
        # owner-only networkless Docker path. Only synthetic CI data here.
        import struct
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        legacy_file = nested / "synthetic-legacy-v1.jwpgbk"
        payload = dump_path.read_bytes()
        prefix = bytes((10, 20, 30, 40))
        chunks = [payload[i:i+backup.CHUNK]
                  for i in range(0, len(payload), backup.CHUNK)] or [b""]
        with legacy_file.open("wb") as stream:
            stream.write(backup.MAGIC_LEGACY + prefix)
            for index, chunk in enumerate(chunks):
                final = index == len(chunks) - 1
                blob = AESGCM(key).encrypt(
                    prefix + struct.pack(">Q", index), chunk,
                    backup.MAGIC_LEGACY + struct.pack(">QB", index, int(final)))
                stream.write(struct.pack(">I", len(blob)))
                stream.write(blob)
        legacy_file.chmod(0o600)
        dump_path.unlink()
        monkeypatch.setattr(owner, "_owner_backup_dir", lambda: root)
        monkeypatch.setenv("CODESPACES", "true")
        monkeypatch.setenv("JW_PG_BACKUP_KEY", base64.urlsafe_b64encode(key).decode())
        monkeypatch.setenv("JW_PG_OFFLINE_RESTORE_ACK", offline.ACK)
        monkeypatch.setenv(offline.REFERENCE_CONSTRAINT_ENV, expected_constraints)
        monkeypatch.setenv(offline.REFERENCE_ROW_ENV, expected_data)
        monkeypatch.setenv(offline.REFERENCE_TOTAL_ENV, str(expected_rows))
        result = offline.run_offline()
        safe = {k: result.get(k) for k in (
            "blocker", "offline_restore_execution", "offline_restored_archive_count",
            "offline_65_table_archive_count", "failure_categories",
            "container_removed", "disposable_constraint_signature_groups")}
        assert result["offline_restore_execution"] == "PASS_LOCAL_ONLY", safe
        assert result["offline_restored_archive_count"] == 2, safe
        assert result["offline_65_table_archive_count"] == 2, safe
        assert result["offline_restore_failure_count"] == 0, safe
        assert result["container_removed"] == "PASS", safe
        assert result["disposable_constraint_signature_groups"] == 1
        assert result["disposable_row_manifest_groups"] == 1
        assert result["current_source_reference_provided"] is True
        assert result["current_source_constraints_match_count"] == 2, safe
        assert result["current_source_row_manifest_match_count"] == 2, safe
        assert result["current_source_combined_match_count"] == 2, safe
        assert result["current_source_comparison"] == "PASS_CURRENT_REFERENCE", safe
        assert result["current_source_row_total_match_count"] == 2, safe
        assert result["current_source_snapshot_is_historic_attestation"] is False
        assert result["historic_real_source_identity_verified"] is False
        assert result["remote_storage_proven"] is False
        assert result["overall"] == "BLOCKED"
        assert role not in str(result), "never expose source-only role names"
        # Negative control: a wrong current-source digest MUST NOT be reported
        # as source-matched, even though the historical V1/V2 files still
        # decrypt and restore cleanly. Never rewrite either archive to force a match.
        monkeypatch.setenv(offline.REFERENCE_ROW_ENV, "f" * 64)
        wrong = offline.run_offline()
        assert wrong["offline_restore_execution"] == "PASS_LOCAL_ONLY"
        assert wrong["container_removed"] == "PASS"
        assert wrong["current_source_row_manifest_match_count"] == 0
        assert wrong["current_source_combined_match_count"] == 0
        assert wrong["current_source_comparison"] == "SOURCE_DRIFT_OR_RESTORED_DATA_DIFFERENCE"
        assert wrong["overall"] == "BLOCKED"
    finally:
        if created_db:
            source_admin.execute(
                sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(db)))
        if created_role:
            source_admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
        source_admin.close()
