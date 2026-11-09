#!/usr/bin/env python3
"""Credential-free, read-only Supabase direct endpoint reachability probe.

Only TCP + PostgreSQL SSLRequest + CA-verified TLS negotiation. No SQL, no
password, no database role changes, and no source data access.
"""
from __future__ import annotations

import os
import socket
import ssl
import struct

SOURCE_HOST = "db.rvymwwzclagvljnofyss.supabase.co"
SOURCE_PORT = 5432
PG_SSL_REQUEST = struct.pack("!II", 8, 80877103)


def addresses(host: str = SOURCE_HOST) -> tuple[bool, bool, list[tuple]]:
    info = socket.getaddrinfo(host, SOURCE_PORT, type=socket.SOCK_STREAM)
    supported = [item for item in info if item[0] in (socket.AF_INET6, socket.AF_INET)]
    # Test at most two addresses, prioritizing IPv6/direct service.
    unique: list[tuple] = []
    seen: set[tuple] = set()
    for item in sorted(supported, key=lambda x: 0 if x[0] == socket.AF_INET6 else 1):
        key = (item[0], item[4])
        if key not in seen:
            unique.append(item)
            seen.add(key)
    return (any(x[0] == socket.AF_INET6 for x in supported),
            any(x[0] == socket.AF_INET for x in supported),
            unique[:2])


def probe_tls(endpoint: tuple, host: str = SOURCE_HOST) -> str:
    family, kind, proto, _, addr = endpoint
    with socket.socket(family, kind, proto) as sock:
        sock.settimeout(3)
        sock.connect(addr)
        sock.sendall(PG_SSL_REQUEST)
        reply = sock.recv(1)
        if reply != b"S":
            return "PG_SSL_NOT_ACCEPTED"
        context = ssl.create_default_context()
        # context.verify_mode=CERT_REQUIRED, check_hostname=True by default.
        with context.wrap_socket(sock, server_hostname=host) as secure:
            if secure.version() is None:
                return "TLS_NOT_ESTABLISHED"
            return "TLS_CA_HOSTNAME_VERIFIED"


def main() -> int:
    if os.environ.get("CODESPACES") != "true":
        print("BLOCKED: diagnostic is restricted to the approved Codespace")
        return 2
    try:
        has_v6, has_v4, endpoints = addresses()
    except (socket.gaierror, OSError):
        print("BLOCKED: Supabase direct hostname did not resolve")
        print("NO_CREDENTIALS_USED_NO_DB_CHANGES")
        return 2
    print("DIRECT_DNS_IPV6=" + ("YES" if has_v6 else "NO"))
    print("DIRECT_DNS_IPV4=" + ("YES" if has_v4 else "NO"))
    if not endpoints:
        print("BLOCKED: no supported direct endpoint addresses")
        print("NO_CREDENTIALS_USED_NO_DB_CHANGES")
        return 2
    reason = "TCP_NOT_REACHABLE"
    for endpoint in endpoints:
        try:
            result = probe_tls(endpoint)
        except ssl.SSLCertVerificationError:
            reason = "TCP_PG_SSL_OK_CA_HOSTNAME_VERIFICATION_FAILED"
            break
        except ssl.SSLError:
            reason = "TCP_PG_SSL_OK_TLS_HANDSHAKE_FAILED"
        except (OSError, TimeoutError):
            reason = "TCP_NOT_REACHABLE"
        else:
            if result == "TLS_CA_HOSTNAME_VERIFIED":
                print("DIRECT_TLS_VERIFY_FULL=PASS")
                print("NETWORK_READY_ONLY: no authentication, SQL, C role or backup attempted")
                return 0
            reason = result
    print("DIRECT_TLS_VERIFY_FULL=BLOCKED (" + reason + ")")
    print("NETWORK_READY_ONLY: no authentication, SQL, C role or backup attempted")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
