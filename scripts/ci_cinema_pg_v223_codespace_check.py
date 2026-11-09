"""Non-invasive Codespaces prerequisite checks; never read or print secrets.

Does not connect to Supabase, change its database, initialize a backup, or
claim that the approved temporary role was created. Status is tools-only.
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess


def _major(command: str) -> int:
    executable = shutil.which(command)
    if not executable:
        return 0
    try:
        result = subprocess.run([executable, "--version"], capture_output=True,
                                text=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return 0
    match = re.search(r"\b(\d+)\.\d+(?:\D|$)", result.stdout)
    return int(match.group(1)) if result.returncode == 0 and match else 0


def check() -> dict[str, bool]:
    codespaces = os.environ.get("CODESPACES") == "true"
    binary = {item: _major(item) >= 17 for item in ("pg_dump", "pg_restore", "psql")}
    try:
        docker_ok = (shutil.which("docker") is not None and
                     subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=15, check=False).returncode == 0)
    except (OSError, subprocess.TimeoutExpired):
        docker_ok = False
    return {
        "codespaces": codespaces,
        "docker_disposable_target_capable": docker_ok,
        "pg_dump_17_plus": binary["pg_dump"],
        "pg_restore_17_plus": binary["pg_restore"],
        "psql_17_plus": binary["psql"],
        "psycopg_present": importlib.util.find_spec("psycopg") is not None,
        "cryptography_present": importlib.util.find_spec("cryptography") is not None,
    }


def main() -> int:
    statuses = check()
    for key, ok in statuses.items():
        print(("PASS" if ok else "BLOCKED") + " " + key)
    if all(statuses.values()):
        print("TOOLS_READY_ONLY: no source credentials, TLS identity, or real restore tested")
        return 0
    print("BLOCKED: Codespaces tooling preflight incomplete; no DB actions permitted")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
