#!/usr/bin/env python3
"""Create a high-entropy SCRAM verifier for the already approved temporary C role.

The verifier is the only material printed for dashboard SQL; a plaintext
password is stored ONLY in a file outside the Git repository (mode 0600).
No network calls, database logins or database changes.
"""
from __future__ import annotations

import base64
from datetime import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from zoneinfo import ZoneInfo

ROLE = "jw_backup_ro"
EXPIRY = datetime(2026, 11, 9, 0, 0, tzinfo=ZoneInfo("Asia/Seoul"))
CREDS = Path.home() / ".local" / "share" / "jw-v223-restore" / "backup_role_auth.json"


def make_verifier(password: str, salt: bytes | None = None, iterations: int = 4096) -> str:
    if len(password) < 48 or not password.isascii() or iterations < 4096:
        raise ValueError("password entropy or iteration minimum not satisfied")
    salt = secrets.token_bytes(16) if salt is None else salt
    if len(salt) < 16:
        raise ValueError("salt is too short")
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    encode = lambda b: base64.b64encode(b).decode("ascii")
    return ("SCRAM-SHA-256$" + str(iterations) + ":" + encode(salt) + "$"
            + encode(stored_key) + ":" + encode(server_key))


def load_or_create(path: Path = CREDS) -> dict[str, str]:
    if path.is_symlink():
        raise ValueError("backup credential symlink forbidden")
    if path.exists():
        st = path.stat()
        if st.st_uid != os.getuid() or st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ValueError("backup credential permission violation")
        obj = json.loads(path.read_text(encoding="utf-8"))
        if set(obj) != {"role", "password", "verifier"} or obj["role"] != ROLE:
            raise ValueError("invalid existing backup secret")
        if not secrets.compare_digest(obj["verifier"], make_verifier(
                obj["password"], decode_salt(obj["verifier"]))):
            raise ValueError("stored verifier and password mismatch")
        return obj
    password = secrets.token_hex(32)
    verifier = make_verifier(password)
    obj = {"role": ROLE, "password": password, "verifier": verifier}
    os.umask(0o077)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(obj, f)
    return obj


def decode_salt(verifier: str) -> bytes:
    try:
        return base64.b64decode(verifier.split("$", 2)[1].split(":", 1)[1], validate=True)
    except (ValueError, IndexError) as e:
        raise ValueError("invalid SCRAM verifier salt") from e


def main() -> int:
    if os.environ.get("CODESPACES") != "true":
        print("BLOCKED: run only in approved Codespaces")
        return 2
    if datetime.now(ZoneInfo("Asia/Seoul")) >= EXPIRY:
        print("BLOCKED: approved C role has expired; no credential generated")
        return 2
    try:
        v = load_or_create()["verifier"]
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        print("BLOCKED: protected credential creation failed; do not proceed")
        return 2
    print("PASS: password generated/stored outside Git, mode 0600; plaintext never printed")
    print("COPY THIS SINGLE SQL LINE INTO SUPABASE SQL EDITOR (never paste into chat):")
    print("ALTER ROLE jw_backup_ro PASSWORD '" + v + "';")
    print("WARNING: The SCRAM verifier is authentication material; do not share screenshots of this output.")
    print("PASSWORD_SQL_PREPARED_ONLY: C role credentials not yet enabled, no DB connection")
    return 0


if __name__ == "__main__":
    sys.exit(main())
