"""V9.4 regression: identify real network blockers without downgrading SSL."""
import errno
import socket
import ssl
import pytest

from scripts import ci_v93_supabase_tls_probe as tls


def test_dns_ipv6_only_address_family_is_reported_without_ip(monkeypatch):
    monkeypatch.setattr(tls.socket,"getaddrinfo",
        lambda *a,**k:[(socket.AF_INET6,socket.SOCK_STREAM,6,"",("2001:db8::9",5432,0,0))])
    result=tls.dns_transport(tls.DEV_HOST)
    assert result=={"dns":"RESOLVED","address_family":"IPV6_ONLY"}
    assert "2001:db8" not in str(result)


def test_dual_stack_vs_ipv4_only(monkeypatch):
    one=(socket.AF_INET,socket.SOCK_STREAM,6,"",("198.51.100.8",5432))
    six=(socket.AF_INET6,socket.SOCK_STREAM,6,"",("2001:db8::8",5432,0,0))
    monkeypatch.setattr(tls.socket,"getaddrinfo",lambda *a,**k:[one])
    assert tls.dns_transport(tls.DEV_HOST)["address_family"]=="IPV4_ONLY"
    monkeypatch.setattr(tls.socket,"getaddrinfo",lambda *a,**k:[one,six])
    assert tls.dns_transport(tls.DEV_HOST)["address_family"]=="DUAL_STACK"


def test_dns_fails_closed_and_no_raw_dns_error(monkeypatch):
    def cannot_resolve(*args,**kwargs):
        raise socket.gaierror(-2,"no such host is deliberately hidden")
    monkeypatch.setattr(tls.socket,"getaddrinfo",cannot_resolve)
    assert tls.dns_transport(tls.DEV_HOST)=={"dns":"FAILED","address_family":"NONE"}
    result=tls.probe(tls.DEV_HOST)
    assert result["reason"]=="DNS_RESOLUTION_FAILED"
    assert result["tls"]=="BLOCKED"


@pytest.mark.parametrize("err,kind",[
    (OSError(errno.ENETUNREACH,"network info must not be shown"),"NETWORK_UNREACHABLE"),
    (OSError(errno.EHOSTUNREACH,"host info"),"HOST_UNREACHABLE"),
    (OSError(errno.ECONNREFUSED,"refused"),"CONNECT_REFUSED"),
    (OSError(errno.ETIMEDOUT,"timeout"),"CONNECT_TIMEOUT"),
    (ssl.SSLError("bad handshake"),"TLS_HANDSHAKE_FAILED"),
])
def test_redacted_error_category(err,kind):
    assert tls.error_category(err)==kind


def test_unreachable_ipv6_only_does_not_claim_tls_success(monkeypatch):
    monkeypatch.setattr(tls.socket,"getaddrinfo",
        lambda *a,**k:[(socket.AF_INET6,socket.SOCK_STREAM,6,"",("2001:db8::9",5432,0,0))])
    def dial(*args,**kwargs):
        raise OSError(errno.ENETUNREACH,"Forbidden: leaking original IP")
    monkeypatch.setattr(tls.socket,"create_connection",dial)
    got=tls.probe(tls.DEV_HOST)
    assert got["tls"]=="BLOCKED" and got["authenticated"] is False
    assert got["reason"]=="NETWORK_UNREACHABLE"
    assert got["network_hint"]=="IPV6_DIRECT_ENDPOINT_REQUIRES_IPV6_ROUTE"
    assert "2001:db8" not in str(got)


def test_allowed_endpoint_is_exact():
    with pytest.raises(ValueError):
        tls.dns_transport("aws-0-ap-northeast-2.pooler.supabase.com")
