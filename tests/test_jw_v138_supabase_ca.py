"""Review-only CA pinning regression; never uses a DB credential."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import ssl

import pytest

from scripts import jw_v138_supabase_ca as ca


def test_supabase_root_is_pinned_and_complete():
    source = Path(ca.__file__).resolve().parent / "certs" / "supabase-root-2021.crt"
    pem = source.read_text("ascii")
    der = ssl.PEM_cert_to_DER_cert(pem)
    assert hashlib.sha256(der).hexdigest() == ca.CA_SHA256
    assert "-----BEGIN CERTIFICATE-----" in pem
    assert "-----END CERTIFICATE-----" in pem


def test_installed_trust_bundle_retains_existing_system_roots(monkeypatch):
    original = os.environ.get("SSL_CERT_FILE")
    try:
        dest = ca.install()
        bundle = Path(dest).read_bytes()
        assert b"-----BEGIN CERTIFICATE-----" in bundle
        assert Path(ca.__file__).resolve().parent.joinpath(
            "certs/supabase-root-2021.crt").read_bytes().strip() in bundle
        assert os.environ["SSL_CERT_FILE"] == dest
        assert os.stat(dest).st_size > 1367
        assert not any(key in bundle.lower() for key in (b"password=", b"postgresql://"))
    finally:
        if original is None:
            monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        else:
            monkeypatch.setenv("SSL_CERT_FILE", original)
        if "dest" in locals():
            Path(dest).unlink(missing_ok=True)


def test_bad_ca_fingerprint_fails_closed_without_touching_env(monkeypatch):
    marker = "/do-not-change"
    monkeypatch.setenv("SSL_CERT_FILE", marker)
    monkeypatch.setattr(ca.ssl, "PEM_cert_to_DER_cert", lambda _: b"tampered")
    with pytest.raises(RuntimeError, match="fingerprint mismatch"):
        ca.install()
    assert os.environ["SSL_CERT_FILE"] == marker
