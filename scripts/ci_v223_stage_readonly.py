"""Read-only LIVE Render transport/auth preflight. It is NOT release E2E.

Hard-coded trusted HTTPS host, no credentials, redirects, cookies, secrets,
database writes, server configuration updates, or response body logging.
The Render deploy SHA is supplied from an independently captured metadata
snapshot. A successful transport probe never certifies release readiness.
"""
from __future__ import annotations
import argparse
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request

ORIGIN = "https://jw-v223-qa-isolated-20261115.onrender.com"
SHA = re.compile(r"^[a-f0-9]{40}$")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def safe_error_code(error: Exception) -> str:
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in str(reason).lower():
        return "TIMEOUT"
    if isinstance(reason, ssl.SSLError):
        return "TLS_ERROR"
    if isinstance(reason, socket.gaierror):
        return "DNS_ERROR"
    if isinstance(reason, ConnectionRefusedError):
        return "REFUSED"
    if "tunnel connection failed" in str(reason).lower():
        return "PROXY_TUNNEL_FAILURE"
    return "TRANSPORT_UNKNOWN"

def probe(path: str, *, retry: bool = False) -> tuple[int,str]:
    if path not in ("/api/health", "/api/me"):
        raise ValueError("untrusted endpoint")
    request = urllib.request.Request(ORIGIN + path, method="GET", headers={
        "Accept": "application/json", "Cache-Control": "no-store",
        "User-Agent": "JW-V223-ReadOnly-NoSecret-Probe/1"})
    opener = urllib.request.build_opener(NoRedirect)
    for attempt in range(2 if retry else 1):
        try:
            with opener.open(request, timeout=20) as response:
                return response.status, "NONE"
        except urllib.error.HTTPError as error:
            return error.code, "HTTP_STATUS"
        except (OSError, TimeoutError, urllib.error.URLError) as error:
            code = safe_error_code(error)
            if attempt==0 and retry and code in ("TIMEOUT", "TRANSPORT_UNKNOWN"):
                time.sleep(2)
                continue
            return 0, code
    return 0, "TRANSPORT_UNKNOWN"

def status(path: str) -> int:
    return probe(path)[0]

def classify(candidate: str, deployed: str, health: int, me: int) -> dict:
    if not SHA.fullmatch(candidate) or not SHA.fullmatch(deployed):
        return {"status":"BLOCKED", "code":"UNVERIFIED_SHA_METADATA"}
    if health not in (200, 204):
        return {"status":"BLOCKED", "code":"LIVE_HEALTH_NOT_VERIFIED"}
    if me == 200:
        return {"status":"FAIL", "code":"ANONYMOUS_IDENTITY_EXPOSED"}
    if me != 401:
        return {"status":"BLOCKED", "code":"ANONYMOUS_AUTH_NOT_VERIFIED"}
    if candidate != deployed:
        return {"status":"BLOCKED", "code":"RENDER_DEPLOYED_SHA_DIFFERS"}
    # All recorded receipts so far are anonymous transport only:
    # authenticated transactions, physical Safari, real PG17, B2/B3 remain absent.
    return {"status":"PARTIAL", "code":"TRANSPORT_ONLY_NOT_AUTHENTICATED_E2E"}

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--candidate",required=True)
    ap.add_argument("--deployed-metadata-sha",required=True)
    ns=ap.parse_args()
    health, health_error=probe("/api/health",retry=True)
    me, me_error=probe("/api/me")
    result=classify(ns.candidate,ns.deployed_metadata_sha,health,me)
    print(json.dumps({"scope":"REAL_RENDER_READONLY_TRANSPORT_ONLY",
        "origin":ORIGIN,"health_http_status":health,
        "health_transport_code":health_error,
        "anonymous_me_http_status":me,
        "anonymous_me_transport_code":me_error,
        "candidate_sha":ns.candidate,
        "deployed_metadata_sha":ns.deployed_metadata_sha,
        "metadata_provenance":"external Render API snapshot, may change after observation",
        "release_ready":False, **result},sort_keys=True))
    return 2 if result["status"]=="FAIL" else 0

if __name__=="__main__":
    raise SystemExit(main())
