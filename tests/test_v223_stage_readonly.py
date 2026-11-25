"""Read-only Render acceptance probes fail closed and never self-certify release."""
import pytest
from scripts import ci_v223_stage_readonly as module

A="a"*40
B="b"*40

@pytest.mark.parametrize(("candidate","deployed","health","me","status","code"), [
    (A,B,200,401,"BLOCKED","RENDER_DEPLOYED_SHA_DIFFERS"),
    (A,A,200,401,"PARTIAL","TRANSPORT_ONLY_NOT_AUTHENTICATED_E2E"),
    (A,A,200,200,"FAIL","ANONYMOUS_IDENTITY_EXPOSED"),
    (A,A,200,302,"BLOCKED","ANONYMOUS_AUTH_NOT_VERIFIED"),
    (A,A,404,401,"BLOCKED","LIVE_HEALTH_NOT_VERIFIED"),
    (A,A,0,0,"BLOCKED","LIVE_HEALTH_NOT_VERIFIED"),
    (A,"bad",200,401,"BLOCKED","UNVERIFIED_SHA_METADATA"),
    ("not-sha",A,200,401,"BLOCKED","UNVERIFIED_SHA_METADATA"),
])
def test_fail_closed(candidate,deployed,health,me,status,code):
    r=module.classify(candidate,deployed,health,me)
    assert r=={"status":status,"code":code}
    assert r["status"]!="PASS"

def test_only_fixed_readonly_paths():
    assert module.ORIGIN.startswith("https://jw-v223-qa-isolated-20261115.onrender.com")
    with pytest.raises(ValueError):
        module.status("/api/login")
    with pytest.raises(ValueError):
        module.status("/api/invoices")

def test_no_redirect_is_accepted():
    redirect=module.NoRedirect()
    assert redirect.redirect_request(None,None,302,"redirect",{},"http://attacker.invalid") is None

def test_diagnostic_reason_classes_are_bounded_and_no_raw_exception_logged():
    import socket
    import ssl
    import urllib.error
    assert module.safe_error_code(TimeoutError("ignored"))=="TIMEOUT"
    assert module.safe_error_code(socket.gaierror(-2,"dns detail"))=="DNS_ERROR"
    assert module.safe_error_code(ssl.SSLError("ssl detail"))=="TLS_ERROR"
    assert module.safe_error_code(urllib.error.URLError("Tunnel connection failed: 403 Forbidden"))=="PROXY_TUNNEL_FAILURE"
    assert module.safe_error_code(OSError("private DSN/password must never print"))=="TRANSPORT_UNKNOWN"
