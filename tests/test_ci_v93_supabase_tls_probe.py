"""TLS probe safety contracts: no credentials, no opportunistic trust downgrade."""
import pytest
from scripts import ci_v93_supabase_tls_probe as tls


def test_refuse_other_destinations():
    with pytest.raises(ValueError):
        tls.probe("db.evil.example")


@pytest.mark.parametrize("host",["localhost","127.0.0.1","db.other.supabase.co",""])
def test_only_known_dev_host(host):
    with pytest.raises(ValueError):
        tls.probe(host)


def test_ssl_context_fail_closed_by_source():
    import inspect
    source = inspect.getsource(tls.probe)
    assert "CERT_REQUIRED" in source and "check_hostname = True" in source
    assert "SSLRequest packet" in source
    assert "password" not in source.lower()
    assert "verify_mode = ssl.CERT_NONE" not in source


def test_cannot_use_missing_ca():
    with pytest.raises(ValueError):
        tls.probe(tls.DEV_HOST, "/nonexistent/ca-bundle.crt")
