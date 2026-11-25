"""Isolated-stage-only Supabase CA trust injection with pinned DER fingerprint.

The shared Supavisor pooler serves a private Supabase CA chain that is absent
from common system stores. This augments certifi with the PUBLIC 2021 root CA.
Do not change sslmode=verify-full, hostname validation or DSN role constraints.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import ssl
import tempfile

import certifi

CA_SHA256 = "807025ad50d4ed219d2c9c7d299c004f824eb00cf7f65afef607d07b72e6cafa"


def install() -> str:
    """Install a pinned CA bundle for libpq's sslrootcert=system (OpenSSL).

    This contains public roots only; it never stores passwords or credentials.
    """
    source = Path(__file__).resolve().parent / "certs" / "supabase-root-2021.crt"
    pem = source.read_text(encoding="ascii")
    try:
        der = ssl.PEM_cert_to_DER_cert(pem)
    except ValueError as exc:
        raise RuntimeError("Pinned stage CA PEM invalid") from exc
    if hashlib.sha256(der).hexdigest() != CA_SHA256:
        raise RuntimeError("Supabase root CA fingerprint mismatch")
    base = Path(certifi.where()).read_bytes()
    if not base or b"-----BEGIN CERTIFICATE-----" not in base:
        raise RuntimeError("System CA bundle missing")
    with tempfile.NamedTemporaryFile(mode="wb", prefix="jw-stage1-verified-ca-",
                                     suffix=".pem", delete=False) as bundle:
        bundle.write(base.rstrip() + b"\n" + pem.encode("ascii"))
        target = bundle.name
    os.environ["SSL_CERT_FILE"] = target
    return target
