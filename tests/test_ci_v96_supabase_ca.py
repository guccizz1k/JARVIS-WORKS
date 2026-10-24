"""Verify user-supplied public Supabase Root 2021 CA fixture before TLS use."""
from __future__ import annotations
import hashlib
from pathlib import Path
import ssl

CA = Path(__file__).resolve().parents[1] / "tests" / "certs" / "prod-ca-2021.crt"
EXPECTED_DER_SHA256 = "807025ad50d4ed219d2c9c7d299c004f824eb00cf7f65afef607d07b72e6cafa"


def test_exact_ca_certificate_sha256_and_public_only():
    content = CA.read_text()
    assert content.count("-----BEGIN CERTIFICATE-----") == 1
    assert "PRIVATE KEY" not in content
    cert = ssl.PEM_cert_to_DER_cert(content)
    assert hashlib.sha256(cert).hexdigest() == EXPECTED_DER_SHA256


def test_ca_loadable_by_python_ssl_with_hostname_validation_enabled():
    ctx = ssl.create_default_context(cafile=str(CA))
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert len(ctx.get_ca_certs()) >= 1


def test_ca_expiration_window_and_name():
    decoded = ssl._ssl._test_decode_cert(str(CA))
    assert "Apr 28" in decoded["notBefore"] and "2021" in decoded["notBefore"]
    assert "Apr 26" in decoded["notAfter"] and "2031" in decoded["notAfter"]
    assert ("commonName", "Supabase Root 2021 CA") in decoded["subject"][-1]
