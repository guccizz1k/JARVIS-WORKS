#!/usr/bin/env python3
"""Trust an official Supabase CA over authenticated HTTPS; test exact session-pooler TLS.

Read-only network diagnostic. Does not authenticate to PostgreSQL, issue SQL,
create roles, use project DB credentials, or mutate source. This does NOT make a
real backup or provide DR proof.
"""
from __future__ import annotations

import os
import re
import socket
import ssl
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from datetime import datetime, timezone

HOST = "aws-0-ap-northeast-2.pooler.supabase.com"  # verified from owner Supabase Connect view
PORT = 5432
CERT_DIR = Path.home() / ".local" / "share" / "jw-v223-restore"
CERT_FILE = CERT_DIR / "prod-ca-2021.crt"
OFFICIAL_URLS = (
    "https://supabase.com/downloads/prod-ca-2021.crt",
    "https://supabase.com/prod-ca-2021.crt",
)
SSL_REQUEST = bytes.fromhex("0000000804d2162f")
MAX_CERT_BYTES = 128_000


def validate_ca(pem: bytes) -> None:
    from cryptography import x509
    if not pem or len(pem) > MAX_CERT_BYTES or not pem.startswith(b"-----BEGIN CERTIFICATE-----"):
        raise ValueError("not a bounded PEM")
    chain = x509.load_pem_x509_certificates(pem)
    if not chain or len(chain) > 5:
        raise ValueError("CA list empty or too long")
    for certificate in chain:
        try:
            bc = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            raise ValueError("CA BasicConstraints missing") from None
        if not bc.ca:
            raise ValueError("not a CA certificate")
        if certificate.not_valid_after_utc <= datetime.now(timezone.utc):
            raise ValueError("CA expired")
        # Never import a completely unrelated cert even when served by a URL.
        if "supabase" not in certificate.subject.rfc4514_string().lower():
            raise ValueError("unexpected CA subject")


def fetch_ca() -> bytes:
    # TLS for this HTTPS fetch is verified against the system web PKI, not the DB CA.
    for url in OFFICIAL_URLS:
        try:
            req = Request(url, headers={"User-Agent": "jw-v223-dr-diagnostics/1"})
            with urlopen(req, timeout=8) as response:
                final = urlsplit(response.geturl())
                if final.scheme != "https" or final.hostname != "supabase.com" or response.status != 200:
                    continue
                data = response.read(MAX_CERT_BYTES + 1)
            validate_ca(data)
            return data
        except (OSError, ValueError, ssl.SSLError, TimeoutError):
            continue
    raise ValueError("official Supabase CA URL unavailable or invalid")


def existing_or_download() -> bytes:
    if CERT_FILE.is_symlink():
        raise ValueError("CA file is symlink")
    if CERT_FILE.exists():
        mode = CERT_FILE.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ValueError("CA permissions unsafe")
        data = CERT_FILE.read_bytes()
        validate_ca(data)
        return data
    data = fetch_ca()
    os.umask(0o077)
    CERT_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(CERT_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(data)
    return data


def verify_tls(cadata: bytes) -> str:
    ctx = ssl.create_default_context(cadata=cadata.decode("ascii"))
    if ctx.verify_mode != ssl.CERT_REQUIRED or not ctx.check_hostname:
        raise RuntimeError("TLS verification disabled")
    addresses = socket.getaddrinfo(HOST, PORT, family=socket.AF_INET, type=socket.SOCK_STREAM)
    if not addresses:
        return "IPV4_DNS_UNAVAILABLE"
    failure = "TCP_NOT_REACHABLE"
    for family, kind, proto, _, addr in addresses[:2]:
        try:
            with socket.socket(family, kind, proto) as sock:
                sock.settimeout(4)
                sock.connect(addr)
                sock.sendall(SSL_REQUEST)
                if sock.recv(1) != b"S":
                    return "PG_SERVER_DID_NOT_ACCEPT_TLS"
                with ctx.wrap_socket(sock, server_hostname=HOST) as secure:
                    if secure.version():
                        return "CA_CHAIN_AND_HOST_VERIFIED"
        except ssl.SSLCertVerificationError as ex:
            code = getattr(ex, "verify_code", None)
            return ("CERT_HOSTNAME_MISMATCH" if code == 62 else
                    "CERT_CHAIN_STILL_INVALID")
        except (OSError, ssl.SSLError, TimeoutError):
            failure = "TCP_OR_TLS_NEGOTIATION_FAILED"
    return failure


def main() -> int:
    if os.environ.get("CODESPACES") != "true":
        print("BLOCKED: execute inside approved Codespaces only")
        return 2
    try:
        cert = existing_or_download()
        verdict = verify_tls(cert)
    except Exception as ex:
        # Never print raw exception strings or file contents.
        print("BLOCKED: official CA download, parsing, or TLS check failed [" + type(ex).__name__ + "]")
        print("NO_SECRETS_NO_SQL_NO_DB_CHANGES")
        return 2
    print("POOLER_CA_TLS_RESULT=" + verdict)
    print("NO_SECRETS_NO_SQL_NO_DB_CHANGES")
    if verdict == "CA_CHAIN_AND_HOST_VERIFIED":
        print("NETWORK_TLS_READY_ONLY: C not applied; real database backup NOT RUN")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
