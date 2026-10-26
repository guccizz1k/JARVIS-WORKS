"""V9.5 session pooler guardrails — no synthetic PASSES for production DB."""
import errno
import inspect
import socket
import ssl
import struct

import pytest

from scripts import ci_v95_supavisor_session_tls as subject


def test_confirmed_host_and_session_port_are_pinned():
    assert subject.POOLER_HOST == "aws-0-ap-northeast-2.pooler.supabase.com"
    assert subject.POOLER_PORT == 5432
    assert subject.PROJECT_REF == "rvymwwzclagvljnofyss"


@pytest.mark.parametrize("host,port", [
    ("aws-0-ap-northeast-2.pooler.supabase.com", 6543),
    ("aws-0-ap-northeast-2.pooler.supabase.com.evil.net", 5432),
    ("db.rvymwwzclagvljnofyss.supabase.co", 5432),
    ("localhost", 5432), ("aws-0-ap-northeast-2.pooler.supabase.com", True),
])
def test_endpoint_substitution_is_rejected(host,port):
    with pytest.raises(ValueError):
        subject.probe(host,port)


def test_no_password_or_authentication_api_in_source():
    body=inspect.getsource(subject.probe)
    assert "password=" not in body
    assert "postgresql://" not in body
    assert "psycopg" not in body
    assert "CERT_NONE" not in body
    assert "create_default_context" in body
    assert "check_hostname = True" in body
    assert 'struct.pack("!II", 8, 80877103)' in body


def test_both_ipv4_and_ipv6_are_identified_but_addresses_redacted(monkeypatch):
    four=(socket.AF_INET,socket.SOCK_STREAM,6,"",("198.51.100.8",5432))
    six=(socket.AF_INET6,socket.SOCK_STREAM,6,"",("2001:db8::1",5432,0,0))
    monkeypatch.setattr(socket,"getaddrinfo",lambda *a,**k:[four,six])
    output=subject.address_families(subject.POOLER_HOST,5432)
    assert output == {"dns":"RESOLVED","address_family":"DUAL_STACK"}
    assert "198.51.100.8" not in str(output)


def test_dns_failure_is_not_reachable(monkeypatch):
    def failed_dns(*_args,**_kwargs):
        raise socket.gaierror(-2,"confidential upstream DNS response")
    monkeypatch.setattr(socket,"getaddrinfo",failed_dns)
    output=subject.probe()
    assert output["dns"]=="FAILED" and output["tls"]=="BLOCKED"
    assert output["authenticated"] is False and output["tcp"]=="BLOCKED"
    assert "confidential" not in str(output)


class FakeSocket:
    def __init__(self,response):
        self.response=response
        self.sent=[]
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def settimeout(self,*args):pass
    def sendall(self,bytes_):self.sent.append(bytes_)
    def recv(self,_n):return self.response


def test_non_tls_pg_gateway_refused_without_fallback(monkeypatch):
    fake=FakeSocket(b"N")
    monkeypatch.setattr(subject,"address_families",lambda h,p:{"dns":"RESOLVED","address_family":"IPV4_ONLY"})
    monkeypatch.setattr(subject.socket,"create_connection",lambda *_a,**_k:fake)
    out=subject.probe()
    assert fake.sent==[struct.pack("!II",8,80877103)]
    assert out["tcp"]=="CONNECTED" and out["tls"]=="BLOCKED"
    assert out["reason"]=="PG_SSL_NOT_ACCEPTED"
    assert out["authenticated"] is False


def test_unreachable_pooler_never_claims_tls_verified(monkeypatch):
    monkeypatch.setattr(subject,"address_families",lambda h,p:{"dns":"RESOLVED","address_family":"IPV4_ONLY"})
    def unreachable(*args,**kwargs): raise OSError(errno.ENETUNREACH,"do not report IP")
    monkeypatch.setattr(subject.socket,"create_connection",unreachable)
    out=subject.probe()
    assert out["reason"]=="NETWORK_UNREACHABLE"
    assert out["tcp"]=="BLOCKED" and out["tls"]=="BLOCKED"
    assert out["sql_executed"] is False


def test_absent_ca_bundle_rejected():
    with pytest.raises(ValueError):
        subject.probe(ca_file="/nonexistent/jw-v95-ca.pem")
