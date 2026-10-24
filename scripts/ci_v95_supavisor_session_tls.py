"""V9.5 exact user-confirmed Supavisor session pooler TLS readiness proof.

No credentials, no PostgreSQL authentication, no SQL, no Supabase mutations.
DNS/TCP/SSLRequest + CA and hostname validation run only against the exact
approved IPv4-compatible session host:5432. Network reachability cannot
authorize service deployment or a direct privileged PostgreSQL login.
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

from scripts.ci_v93_supabase_tls_probe import dns_transport as direct_dns, error_category

POOLER_HOST = "aws-0-ap-northeast-2.pooler.supabase.com"
POOLER_PORT = 5432
DATABASE = "postgres"
PROJECT_REF = "rvymwwzclagvljnofyss"
TIMEOUT_SECONDS = 7


def _allowed(host: str, port: int) -> None:
    if host != POOLER_HOST or type(port) is not int or port != POOLER_PORT:
        raise ValueError("Only exact user-confirmed session pooler endpoint is permitted")


def address_families(host: str, port: int) -> dict:
    _allowed(host, port)
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return {"dns": "FAILED", "address_family": "NONE"}
    found = {record[0] for record in records}
    return {
        "dns": "RESOLVED" if found else "FAILED",
        "address_family": (
            "DUAL_STACK" if socket.AF_INET in found and socket.AF_INET6 in found else
            "IPV4_ONLY" if socket.AF_INET in found else
            "IPV6_ONLY" if socket.AF_INET6 in found else "UNKNOWN"
        ),
    }


def probe(host: str = POOLER_HOST, port: int = POOLER_PORT,
          ca_file: str = "") -> dict:
    _allowed(host, port)
    if ca_file:
        path = Path(ca_file)
        if not path.is_file() or not 0 < path.stat().st_size <= 1000000:
            raise ValueError("Untrusted or missing CA file")
    # No skip/opt-out: system roots (or supplied CA) AND DNS hostname matching.
    ctx = ssl.create_default_context(cafile=ca_file or None)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    result = {
        "endpoint": "session_pooler",
        "host": POOLER_HOST,
        "port": POOLER_PORT,
        "database": DATABASE,
        "tcp": "BLOCKED",
        "tls": "BLOCKED",
        "authenticated": False,
        "sql_executed": False,
        "service_deployed": False,
        "production_cutover": False,
    }
    result.update(address_families(host, port))
    if result["dns"] != "RESOLVED":
        result["reason"] = "DNS_RESOLUTION_FAILED"
        return result
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS) as sock:
            result["tcp"] = "CONNECTED"
            sock.settimeout(TIMEOUT_SECONDS)
            # PostgreSQL SSLRequest, not an authentication/startup message.
            sock.sendall(struct.pack("!II", 8, 80877103))
            response = sock.recv(1)
            if response != b"S":
                result["reason"] = "PG_SSL_NOT_ACCEPTED"
                return result
            # Never set CERT_NONE, disable hostname verification or use
            # plaintext fallback. Supavisor's certificate must chain to CA.
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert(binary_form=True)
                if not cert or tls.version() not in ("TLSv1.2", "TLSv1.3"):
                    result["reason"] = "TLS_PROTOCOL_INVALID"
                    return result
                result["tls"] = "VERIFIED_CA_AND_HOSTNAME"
                result["protocol"] = tls.version()
                result["peer_sha256"] = hashlib.sha256(cert).hexdigest()
                result["reason"] = "TLS_PEER_VERIFIED_NO_DATABASE_LOGIN"
    except (OSError, ssl.SSLError) as exc:
        result["reason"] = error_category(exc)
    return result


def main() -> int:
    try:
        answer = probe(ca_file=os.environ.get("JW_SUPABASE_POOLER_CA_FILE", ""))
    except (ValueError, OSError) as exc:
        answer = {
            "endpoint": "session_pooler", "host": POOLER_HOST, "port": POOLER_PORT,
            "tcp": "BLOCKED", "tls": "BLOCKED",
            "reason": type(exc).__name__, "authenticated": False,
            "sql_executed": False, "service_deployed": False,
            "production_cutover": False,
        }
    print(json.dumps(answer, sort_keys=True))
    if "--require-verified" in sys.argv and answer["tls"] != "VERIFIED_CA_AND_HOSTNAME":
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
