"""No-credential SSLRequest/hostname/CA verification against authorized dev DB.

This checks the *remote PostgreSQL TLS certificate only*: it NEVER logs in,
requests a password, sends SQL, fetches a secret or changes server settings.
Fail-closed on unavailable/untrusted endpoints, with one bounded attempt.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import sys

DEV_HOST = "db.rvymwwzclagvljnofyss.supabase.co"
TIMEOUT = 5


def probe(host: str, ca_file: str = "") -> dict[str, object]:
    if host != DEV_HOST:
        raise ValueError("Destination not allowlisted")
    if ca_file:
        p = Path(ca_file)
        if not p.is_file() or not p.stat().st_size or p.stat().st_size > 1000000:
            raise ValueError("Missing or oversized trusted certificate bundle")
    context = ssl.create_default_context(cafile=ca_file or None)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    result = {"host": DEV_HOST, "tls": "BLOCKED", "authenticated": False,
              "deployed_https": False, "production_cutover": False}
    try:
        with socket.create_connection((host, 5432), timeout=TIMEOUT) as connection:
            connection.settimeout(TIMEOUT)
            # Standard PostgreSQL SSLRequest packet, not a SQL command.
            connection.sendall(struct.pack("!II", 8, 80877103))
            if connection.recv(1) != b"S":
                result["reason"] = "server_declined_tls"
                return result
            with context.wrap_socket(connection, server_hostname=host) as tls:
                cert = tls.getpeercert(binary_form=True)
                if not cert or tls.version() not in ("TLSv1.2", "TLSv1.3"):
                    result["reason"] = "missing_trusted_tls"
                    return result
                result["tls"] = "VERIFIED_CA_AND_HOSTNAME"
                result["reason"] = "certificate_chain_verified"
                result["peer_sha256"] = hashlib.sha256(cert).hexdigest()
                result["protocol"] = tls.version()
    except (socket.gaierror, socket.timeout, TimeoutError, OSError,
            ssl.SSLError) as exc:
        # Do not leak network config or certificate contents.
        result["reason"] = type(exc).__name__
    return result


def main() -> int:
    ca = os.environ.get("JW_SUPABASE_ROOT_CA_FILE", "")
    try:
        outcome = probe(DEV_HOST, ca)
    except (ValueError, ssl.SSLError) as exc:
        outcome = {"host": DEV_HOST, "tls": "BLOCKED",
                   "reason": type(exc).__name__, "authenticated": False,
                   "deployed_https": False,"production_cutover": False}
    print(json.dumps(outcome, sort_keys=True))
    # A read-only discovery run records BLOCKED honestly, never authorizes
    # live DB login or a release. Strict enforcement uses explicit flag.
    if "--require-verified" in sys.argv and outcome["tls"] != "VERIFIED_CA_AND_HOSTNAME":
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
