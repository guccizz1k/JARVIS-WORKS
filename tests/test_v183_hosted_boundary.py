"""V18.3 independent fail-closed cases for hosted negative boundary runner."""
import pytest
import httpx
from scripts.ci_v183_hosted_boundary import HOST, PATHS, HEADERS, probe


def good(req):
    if req.url.path == "/healthz":
        return httpx.Response(200,json={"mode":"isolated_pg_api_only","release":"BLOCKED"})
    return httpx.Response(403,json={"detail":"Staging access denied"},headers={"Cache-Control":"no-store"})


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler),follow_redirects=False)


def test_full_thirty_case_matrix():
    seen=[]
    def mock(req):
        seen.append((req.url.path,req.headers.get("x-jw-stage-key","")))
        return good(req)
    with client(mock) as c:
        assert probe(c)==30
    assert len(seen)==31
    assert len(set(seen))==31
    assert len(PATHS)==10 and len(HEADERS)==3


@pytest.mark.parametrize("path",PATHS)
def test_each_exposed_route_must_fail_closed(path):
    def mock(req):
        if req.url.path==path:
            return httpx.Response(200,json={"oops":True})
        return good(req)
    with client(mock) as c:
        with pytest.raises(AssertionError,match="UNPROTECTED"):
            probe(c)


@pytest.mark.parametrize("case",[
    "health_approved", "health_sealed", "health_redirect", "health_nonjson",
    "denial_redirect", "denial_401", "denial_200", "denial_html",
    "denial_wrong_body", "denial_no_cache", "denial_cache_public",
    "denial_503", "denial_500", "denial_empty_json", "denial_bad_cache",
])
def test_fifteen_transport_or_gate_corruptions_rejected(case):
    def mock(req):
        if req.url.path=="/healthz":
            if case=="health_approved":return httpx.Response(200,json={"mode":"isolated_pg_api_only","release":"APPROVED"})
            if case=="health_sealed":return httpx.Response(200,json={"mode":"sealed-no-db","release":"BLOCKED"})
            if case=="health_redirect":return httpx.Response(302,headers={"Location":"/"})
            if case=="health_nonjson":return httpx.Response(200,text="not json")
            return good(req)
        r={
            "denial_redirect":httpx.Response(302,headers={"Location":"/"}),
            "denial_401":httpx.Response(401,json={"detail":"Staging access denied"}),
            "denial_200":httpx.Response(200,json={"detail":"Staging access denied"}),
            "denial_html":httpx.Response(403,text="<h1>denied</h1>",headers={"Cache-Control":"no-store"}),
            "denial_wrong_body":httpx.Response(403,json={"detail":"Other"},headers={"Cache-Control":"no-store"}),
            "denial_no_cache":httpx.Response(403,json={"detail":"Staging access denied"}),
            "denial_cache_public":httpx.Response(403,json={"detail":"Staging access denied"},headers={"Cache-Control":"public"}),
            "denial_503":httpx.Response(503,json={"detail":"Staging access denied"}),
            "denial_500":httpx.Response(500,json={"detail":"Staging access denied"}),
            "denial_empty_json":httpx.Response(403,json={},headers={"Cache-Control":"no-store"}),
            "denial_bad_cache":httpx.Response(403,json={"detail":"Staging access denied"},headers={"Cache-Control":"max-age=120"}),
        }
        return r[case]
    with client(mock) as c:
        with pytest.raises(AssertionError):
            probe(c)


def test_no_unapproved_host_or_write_paths():
    assert HOST == "https://jw-stage1-secure-20261030.onrender.com"
    assert all(x.startswith("/") and "?" not in x and x!="/healthz" for x in PATHS)
    assert all("Authorization" not in x and "service_role" not in x for x in HEADERS)
