"""Bounded, read-only QA probe. Never release authorization or a keep-alive job."""
import json
import re
import subprocess
import tempfile
import time
from pathlib import Path

HOST = 'https://jw-v223-qa-pinned-20261122.onrender.com'
VERSION = '2.2.0-candidate'
TRANSIENT_CODES = {6, 7, 18, 28, 52, 55, 56}
TRANSIENT_HTTP = {502, 503, 504}


def request(path, timeout):
    if path not in ('/api/health', '/'):
        raise ValueError('QA_PATH_NOT_ALLOWED')
    with tempfile.TemporaryDirectory() as d:
        body, headers = Path(d)/'body', Path(d)/'headers'
        cmd = ['curl', '--disable', '--proto', '=https', '--tlsv1.2',
               '--connect-timeout', str(min(5, timeout)),
               '--max-time', str(timeout), '--max-filesize', '16384',
               '--silent', '--show-error', '--output', str(body),
               '--dump-header', str(headers), '--write-out', '%{http_code} %{ssl_verify_result}', HOST+path]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2, check=False)
        except subprocess.TimeoutExpired:
            return (28, 0, -1, b'', '')
        except OSError:
            return (127, 0, -1, b'', '')
        m = re.fullmatch(r'(\d{3}) (\d+)', p.stdout.strip())
        return (p.returncode, int(m[1]) if m else 0, int(m[2]) if m else -1,
                body.read_bytes()[:16385] if body.exists() else b'',
                headers.read_text(errors='replace')[:16384] if headers.exists() else '')


def assess(fetch=request, clock=time.monotonic, sleep=time.sleep, budget=120):
    if type(budget) is not int or not 10 <= budget <= 120:
        raise ValueError('QA_BUDGET_INVALID')
    deadline=clock()+budget
    observations=[]
    def result(status):
        return dict(status=status, observations=observations, release_authorized=False,
                    database_verified=False, deployed_sha_verified=False, production_sla_verified=False)
    for attempt in range(1, 5):
        remaining=deadline-clock()
        if remaining<4: break
        rc, http, tls, body, hdr=fetch('/api/health', min(35,int(remaining-2)))
        observations.append(dict(path='health', attempt=attempt, curl_exit=rc, http=http, tls=tls))
        if rc==0 and tls==0 and http==200:
            try: parsed=json.loads(body)
            except (ValueError, UnicodeError): return result('BLOCKED_HEALTH_PAYLOAD')
            if parsed != {'status':'ok','version':VERSION}: return result('BLOCKED_HEALTH_PAYLOAD')
            break
        if rc==0 and tls==0 and http not in TRANSIENT_HTTP: return result('BLOCKED_HEALTH_HTTP')
        if rc not in TRANSIENT_CODES and not (rc==0 and tls==0 and http in TRANSIENT_HTTP): return result('BLOCKED_TRANSPORT')
        if attempt==4 or deadline-clock()<6: return result('BLOCKED_STARTUP_OR_TRANSPORT')
        sleep(min(3,max(0,deadline-clock()-4)))
    else:
        return result('BLOCKED_STARTUP_OR_TRANSPORT')
    if not observations or rc!=0 or http!=200 or tls!=0: return result('BLOCKED_STARTUP_OR_TRANSPORT')
    remaining=deadline-clock()
    if remaining<4: return result('BLOCKED_AUTH_PROBE_BUDGET')
    rc,http,tls,body,hdr=fetch('/',min(15,int(remaining-2)))
    observations.append(dict(path='root',curl_exit=rc,http=http,tls=tls))
    if rc!=0 or tls!=0: return result('BLOCKED_AUTH_TRANSPORT')
    final_headers=hdr.strip().replace('\r\n','\n').split('\n\n')[-1]
    if http!=401 or not re.search(r'^WWW-Authenticate:\s*Basic realm="JARVIS-WORKS isolated review"(?:,|\s*$)',final_headers,re.I|re.M):
        return result('BLOCKED_AUTH_BARRIER')
    return result('QA_HEALTH_AND_UNAUTHENTICATED_BARRIER_PASS')

if __name__=='__main__':
    r=assess(); print(json.dumps(r,sort_keys=True)); raise SystemExit(0 if r['status'].endswith('_PASS') else 1)
