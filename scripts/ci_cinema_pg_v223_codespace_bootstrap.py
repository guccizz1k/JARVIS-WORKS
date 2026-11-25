"""Codespaces-only PG17 tooling bootstrap; never touches a live database."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from scripts import ci_cinema_pg_v223_codespace_check as preflight


def _run(*args: str) -> None:
    subprocess.run(list(args), check=True)


def main(args: list[str]) -> int:
    if args != ["--prepare"]:
        print("usage: python3 -m scripts.ci_cinema_pg_v223_codespace_bootstrap --prepare", file=sys.stderr)
        return 2
    if os.environ.get("CODESPACES") != "true":
        print("BLOCKED: only an approved GitHub Codespace may prepare the tools", file=sys.stderr)
        return 2
    if not shutil.which("docker"):
        print("BLOCKED: Docker-in-Docker is unavailable", file=sys.stderr)
        return 2
    try:
        info = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        print("BLOCKED: Docker daemon is unavailable", file=sys.stderr)
        return 2
    if info.returncode:
        print("BLOCKED: Docker daemon is unavailable", file=sys.stderr)
        return 2
    if any(preflight._major(name) < 17 for name in ("pg_dump", "pg_restore", "psql")):
        # Official signed PGDG repository helper installed from Debian package.
        _run("sudo", "apt-get", "update", "-qq")
        _run("sudo", "apt-get", "install", "-y", "-qq", "--no-install-recommends",
             "postgresql-common", "ca-certificates")
        helper = Path("/usr/share/postgresql-common/pgdg/apt.postgresql.org.sh")
        if not helper.is_file():
            print("BLOCKED: official PGDG signed repository helper unavailable", file=sys.stderr)
            return 2
        _run("sudo", str(helper), "-y")
        _run("sudo", "apt-get", "update", "-qq")
        _run("sudo", "apt-get", "install", "-y", "-qq", "--no-install-recommends", "postgresql-client-17")
    _run(sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "-r",
         "requirements-postgres-check.txt")
    return preflight.main()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
