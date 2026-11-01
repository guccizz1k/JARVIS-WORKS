"""V20.4 review-only offline container boundary for original import_worker.

Not a production scanner, human approval, OCR validation or hosted release.
Runtime container has no network, writable root, mounts, capabilities or root UID.
Only an isolated GitHub runner with a freshly built review image may invoke it.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess

from app.import_engine import MAX_FILE_SIZE

IMAGE = "jw-v204-offline-import:ci"
ACK = "ONLY_DISPOSABLE_DOCKER_NETWORK_NONE"
MAX_OUTPUT = 2_000_000
SAFE = re.compile(r"^[^/\\\\\x00-\x1f\x7f]{1,116}\\.(xlsx|pdf)$", re.IGNORECASE)


def _guard() -> None:
    if os.environ.get("JW_ENV") != "review" or os.environ.get("JW_V204_ISOLATED") != ACK:
        raise RuntimeError("BLOCKED_V204_NONDISPOSABLE_ENVIRONMENT")
    result = subprocess.run(
        ["docker", "image", "inspect", "--format",
         '{{index .Config.Labels "org.jarvisworks.scope"}}', IMAGE],
        capture_output=True, timeout=10, check=False)
    if result.returncode != 0 or result.stdout.strip() != b"review-only-offline-import-v204":
        raise RuntimeError("BLOCKED_V204_UNVERIFIED_CONTAINER_IMAGE")


def _flags() -> list[str]:
    return [
        "run", "--rm", "-i", "--pull=never", "--network=none",
        "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--pids-limit=32", "--memory=768m", "--cpus=1",
        "--user=65532:65532",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m",
        "--env=PYTHONDONTWRITEBYTECODE=1", "--env=PYTHONNOUSERSITE=1",
    ]


def _invoke(extra: list[str], payload: bytes, timeout: int = 25) -> dict:
    done = subprocess.run(
        ["docker", *_flags(), *extra], input=payload,
        capture_output=True, timeout=timeout, check=False)
    if done.returncode != 0 or len(done.stdout) > MAX_OUTPUT:
        raise ValueError("BLOCKED_V204_SANDBOX_WORKER_FAILURE")
    try:
        value = json.loads(done.stdout)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("BLOCKED_V204_INVALID_WORKER_OUTPUT") from exc
    if not isinstance(value, dict):
        raise ValueError("BLOCKED_V204_INVALID_WORKER_RESULT")
    return value


def extract(filename: str, raw: bytes) -> dict:
    _guard()
    if not isinstance(filename, str) or not SAFE.fullmatch(filename):
        raise ValueError("BLOCKED_V204_UNSAFE_FILENAME")
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_FILE_SIZE:
        raise ValueError("BLOCKED_V204_INVALID_UPLOAD_SIZE")
    payload = json.dumps(
        {"filename": filename, "base64": base64.b64encode(raw).decode("ascii")},
        ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    result = _invoke([IMAGE], payload)
    if result.get("error"):
        raise ValueError("BLOCKED_V204_DOCUMENT_PARSER_REJECTED")
    if not isinstance(result.get("result"), dict):
        raise ValueError("BLOCKED_V204_MISSING_DOCUMENT_RESULT")
    return result["result"]


PROBE = r"""
import json,os,socket
assert os.geteuid()==65532
status=open('/proc/self/status').read()
assert 'CapEff:\\t0000000000000000' in status
assert 'NoNewPrivs:\\t1' in status
blocked=0
for ip in ('1.1.1.1','8.8.8.8','9.9.9.9','208.67.222.222',
           '1.0.0.1','8.8.4.4','149.112.112.112','208.67.220.220',
           '4.2.2.1','4.2.2.2'):
    s=socket.socket()
    s.settimeout(0.2)
    try:
        if s.connect_ex((ip,443))==0: raise AssertionError('NETWORK_ESCAPE')
        blocked+=1
    finally:s.close()
for p in ('/srv/forbidden','/etc/forbidden','/usr/forbidden',
          '/var/forbidden','/bin/forbidden','/opt/forbidden',
          '/lib/forbidden','/root/forbidden','/home/forbidden',
          '/forbidden'):
    try:
        with open(p,'wb') as f:f.write(b'unsafe')
    except OSError:blocked+=1
    else:raise AssertionError('WRITABLE_ROOT_ESCAPE')
assert blocked==20
print(json.dumps({'blocked':blocked,'uid':os.geteuid(),
                  'network':'none','root':'read-only',
                  'capabilities':'zero','no_new_privileges':True}))
"""


def probe() -> dict:
    _guard()
    result = _invoke(
        ["--entrypoint=python", IMAGE, "-c", PROBE], b"", timeout=15)
    if result != {"blocked":20,"uid":65532,"network":"none",
                  "root":"read-only","capabilities":"zero",
                  "no_new_privileges":True}:
        raise AssertionError("V204_SANDBOX_ISOLATION_PROOF_FAILED")
    return result
