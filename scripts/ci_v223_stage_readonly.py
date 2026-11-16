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
import urllib.error
import urllib.request

ORIGIN = "https://jw-v223-qa-isolated-20261115.onrender.com"
SHA = re.compile(r"^[a-f0-9]{40}$")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def status(path: str) -> int:
    if path not in ("/api/health", "/api/me"):
        raise ValueError("untrusted endpoint")
    request = urllib.request.Request(ORIGIN + path, method="GET", headers={
        "Accept": "application/json", "Cache-Control": "no-store",
        "User-Agent": "JW-V223-ReadOnly-NoSecret-Probe/1"})
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=12) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except (OSError, TimeoutError, urllib.error.URLError):
        return 0

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
    health=status("/api/health")
    me=status("/api/me")
    result=classify(ns.candidate,ns.deployed_metadata_sha,health,me)
    print(json.dumps({"scope":"REAL_RENDER_READONLY_TRANSPORT_ONLY",
        "origin":ORIGIN,"health_http_status":health,
        "anonymous_me_http_status":me,
        "candidate_sha":ns.candidate,
        "deployed_metadata_sha":ns.deployed_metadata_sha,
        "metadata_provenance":"external Render API snapshot, may change after observation",
        "release_ready":False, **result},sort_keys=True))
    return 2 if result["status"]=="FAIL" else 0

if __name__=="__main__":
    raise SystemExit(main())
