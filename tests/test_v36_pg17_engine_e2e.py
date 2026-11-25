
import hashlib
import os
import subprocess
import time
import uuid

import psycopg
import pytest

from app.pg_migration_shadow_v36 import (
    Record, stage_shadow, verify_shadow, drop_shadow
)

SCHEMA = "jw_migration_v36"


def test_real_pg17_engine():
    if os.environ.get("JW_V36_DISPOSABLE_PG17") != "1":
        pytest.skip("disposable PG17 not authorized")

    name = "jw-v36-e2e-" + uuid.uuid4().hex[:12]
    cid = subprocess.check_output([
        "docker", "run", "-d", "--rm",
        "--name", name,
        "-e", "POSTGRES_PASSWORD=isolated_test_only",
        "postgres:17"
    ], text=True).strip()

    try:
        for _ in range(40):
            ready = subprocess.run([
                "docker", "exec", cid,
                "pg_isready", "-U", "postgres"
            ], stdout=subprocess.DEVNULL,
               stderr=subprocess.DEVNULL)
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            pytest.fail("PG17 not ready")

        port = subprocess.check_output([
            "docker", "inspect", "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            cid
        ], text=True).strip()

        if not port:
            pytest.fail("isolated address unavailable")

        dbname = "jw_v20_test_" + uuid.uuid4().hex[:12]
        subprocess.run(
            ["docker", "exec", cid, "createdb",
             "-U", "postgres", dbname],
            check=True,
            stdout=subprocess.DEVNULL
        )
        subprocess.run(
            ["docker", "exec", cid, "psql",
             "-X", "-U", "postgres", "-d", dbname,
             "-v", "ON_ERROR_STOP=1",
             "-c", "CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public"],
            check=True,
            stdout=subprocess.DEVNULL
        )
        dsn = (
            f"host={port} port=5432 dbname={dbname} "
            "user=postgres password=isolated_test_only"
        )

        payload = b'{"order":"immutable snapshot","amount":100}'
        record = Record(
            "messenger_messages", "order-001", payload,
            hashlib.sha256(payload).hexdigest()
        )
        records = [record]

        with psycopg.connect(dsn) as pg:
            assert pg.info.server_version // 10000 == 17

            with pytest.raises(Exception):
                stage_shadow(
                    pg, records, inject_failure_after=1
                )

            with pg.cursor() as cur:
                cur.execute(
                    "SELECT to_regclass(%s)",
                    (SCHEMA + ".records",)
                )
                assert cur.fetchone()[0] is None

            stage_shadow(pg, records)
            verify_shadow(pg, records)

            with pg.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM "
                    "jw_migration_v36.records"
                )
                assert cur.fetchone()[0] == 1

            drop_shadow(pg)

            with pg.cursor() as cur:
                cur.execute(
                    "SELECT to_regclass(%s)",
                    (SCHEMA + ".records",)
                )
                assert cur.fetchone()[0] is None

    finally:
        subprocess.run(
            ["docker", "rm", "-f", cid],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
