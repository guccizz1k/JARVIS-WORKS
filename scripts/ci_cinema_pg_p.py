#!/usr/bin/env python3
"""Zero-credential IPv4 shared Supavisor SESSION pooler reachability probe.

The tested addresses are publicly documented hostname *patterns* for the
project's region, NOT the authoritative host for this specific tenant. The
project's own dashboard Connect > Session pooler must still be checked.
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

# ap-northeast-2 from Supabase project metadata. The aws-0/aws-1 numbering
# is a candidate only, not a declaration of this project's pooler assignment.
CANDIDATES = (
    "aws-0-ap-northeast-2.pooler.supabase.com",
    "aws-1-ap-northeast-2.pooler.supabase.com",
)
PORT = 5432  # Shared Supavisor SESSION mode, not transaction mode (6543).


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
        except ssl.SSLCertVerificationError:
            return "TLS_CA_HOSTNAME_FAILED"
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
    print("TENANT_BINDING=NOT_VERIFIED (confirm exact host in Supabase dashboard Connect > Session pooler)")
    print("NO_CREDENTIALS_NO_SQL_NO_DB_CHANGES")
    if "TCP_SSL_CA_VERIFIED" in results:
        print("POOLER_IPV4_NETWORK_ONLY=PASS")
        return 0
    print("POOLER_IPV4_NETWORK_ONLY=BLOCKED")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
