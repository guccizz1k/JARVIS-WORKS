#!/usr/bin/env python3
"""Make an isolated local PG17 restore target in a Codespace. Never contacts Supabase."""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time

CONTAINER = "jw-v223-restore"
LOCAL_PORT = 55432
SECRET_DIR = Path.home() / ".local" / "share" / "jw-v223-restore"
SECRET_FILE = SECRET_DIR / "restore.sh"


def docker(*args: str, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], env=environment, capture_output=True, text=True,
                          timeout=180, check=False)


def live_local(password: str) -> bool:
    try:
        import psycopg
        with psycopg.connect(host="127.0.0.1", port=LOCAL_PORT, user="postgres",
                             password=password, dbname="postgres",
                             connect_timeout=2, sslmode="disable") as conn:
            row = conn.execute("SELECT current_setting('server_version_num')::int, "
                               "current_database(), current_user").fetchone()
            return row is not None and 170000 <= row[0] < 180000 and row[1:] == ("postgres", "postgres")
    except Exception:
        return False


def main() -> int:
    if os.environ.get("CODESPACES") != "true":
        print("BLOCKED: run only inside the approved Codespace")
        return 2
    if not shutil.which("docker"):
        print("BLOCKED: Docker missing")
        return 2
    if SECRET_FILE.exists() or SECRET_FILE.is_symlink():
        print("BLOCKED: local credential file already exists; no changes made")
        return 2
    try:
        existing = docker("container", "inspect", CONTAINER)
    except (OSError, subprocess.TimeoutExpired):
        print("BLOCKED: Docker not reachable")
        return 2
    if existing.returncode == 0:
        print("BLOCKED: restore container already exists; no changes made")
        return 2
    os.umask(0o077)
    SECRET_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    password = secrets.token_urlsafe(36)
    token = secrets.token_hex(24)
    content = (
        "# Local disposable PG17 restore target. NEVER commit, paste, or print this file.\n"
        "export JW_PG_TARGET_ADMIN_DSN='postgresql://postgres:"
        + password + "@127.0.0.1:55432/postgres'\n"
        "export JW_PG_TARGET_EPHEMERAL_TOKEN='" + token + "'\n"
        "export JW_PG_CI_ALLOW='ONLY_EPHEMERAL_LOCAL_DATABASE'\n"
    )
    try:
        fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(content)
    except OSError:
        print("BLOCKED: cannot create protected local credential file")
        return 2
    created = False
    ready = False
    try:
        env = dict(os.environ)
        env["POSTGRES_PASSWORD"] = password
        result = docker("run", "-d", "--name", CONTAINER, "--restart", "no",
                        "-e", "POSTGRES_PASSWORD", "-p",
                        "127.0.0.1:55432:5432", "postgres:17", environment=env)
        if result.returncode != 0:
            print("BLOCKED: isolated Docker container failed to start")
            return 2
        created = True
        for _ in range(40):
            if live_local(password):
                ready = True
                print("PASS: isolated local PostgreSQL 17 TCP connection verified")
                print("PASS: strong secret saved outside git with file mode 0600")
                print("LOCAL_RESTORE_TARGET_READY_ONLY: no Supabase connection or backup executed")
                return 0
            time.sleep(1)
        print("BLOCKED: isolated PostgreSQL 17 not reachable")
        return 2
    except (OSError, subprocess.TimeoutExpired):
        print("BLOCKED: local Docker operation failed")
        return 2
    finally:
        # On unsuccessful setup, clean up only the disposable container created by this invocation.
        # The credential file is likewise created only by this invocation.
        if not ready:
            if created:
                try:
                    docker("rm", "-f", CONTAINER)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            SECRET_FILE.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
