#!/usr/bin/env python3
"""Zero-credential IPv4 shared Supavisor SESSION pooler reachability probe.

Use only the exact session-pooler hostname confirmed in the project dashboard.
Never substitute an unverified similarly-named pooler.
No authentication, SQL, C change, source backup or data read occurs.
"""
from __future__ import annotations

import os
import socket
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.ci_cinema_pg_n import probe_tls

# Exact host was confirmed in the owner's Supabase Connect > Session pooler screenshot.
CANDIDATES = ("aws-0-ap-northeast-2.pooler.supabase.com",)
PORT = 5432  # Shared Supavisor SESSION mode, not transaction mode (6543).

# Python/OpenSSL verification codes. No certificate verification is ever disabled.
CERT_FAILURES = {
    9: "CERT_NOT_YET_VALID",
    10: "CERT_EXPIRED",
    18: "SELF_SIGNED_CERT",
    19: "SELF_SIGNED_CHAIN",
    20: "ISSUER_NOT_TRUSTED_OR_CHAIN_INCOMPLETE",
    21: "UNABLE_TO_VERIFY_LEAF",
    62: "HOSTNAME_MISMATCH",
}


def describe_verification_failure(exc: ssl.SSLCertVerificationError) -> str:
    code = getattr(exc, "verify_code", None)
    return CERT_FAILURES.get(code, "CERT_VERIFICATION_ERROR_OTHER")



def check(host: str) -> str:
    try:
        infos = socket.getaddrinfo(host, PORT, family=socket.AF_INET,
                                   type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return "IPV4_DNS_UNAVAILABLE"
    if not infos:
        return "IPV4_DNS_UNAVAILABLE"
    for endpoint in infos[:2]:
        try:
            result = probe_tls(endpoint, host=host)
        except ssl.SSLCertVerificationError as exc:
            return "TLS_BLOCKED_" + describe_verification_failure(exc)
        except ssl.SSLError:
            return "TLS_HANDSHAKE_FAILED"
        except (OSError, TimeoutError):
            continue
        if result == "TLS_CA_HOSTNAME_VERIFIED":
            return "TCP_SSL_CA_VERIFIED"
        return result
    return "IPV4_TCP_UNREACHABLE"


def main() -> int:
    if os.environ.get("CODESPACES") != "true":
        print("BLOCKED: check only in approved Codespaces")
        return 2
    results = [check(host) for host in CANDIDATES]
    for i, result in enumerate(results):
        print("POOLER_CANDIDATE_" + str(i + 1) + "=" + result)
    print("POOLER_HOST_SOURCE=OWNER_CONFIRMED_SUPABASE_CONNECT_SESSION")
    print("NO_CREDENTIALS_NO_SQL_NO_DB_CHANGES")
    if "TCP_SSL_CA_VERIFIED" in results:
        print("POOLER_IPV4_NETWORK_ONLY=PASS")
        return 0
    print("POOLER_IPV4_NETWORK_ONLY=BLOCKED")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
