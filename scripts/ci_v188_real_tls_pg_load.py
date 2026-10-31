"""V18.8 real TLS + restricted PostgreSQL17 synthetic lifecycle/load acceptance.

Reuses V18.4 proven quote -> human review -> internal order HTTP flow.
This only runs in a fresh disposable localhost GitHub PostgreSQL 17 service.
A bounded concurrent test measures (not asserts an invented production SLA)
read availability, tenant isolation, session revocation boundaries and
quote idempotency under 96 real HTTPS reads + 16 concurrent writes.
No real Render POSTs, bank settlement, invoice issuance, customer data.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from statistics import median
from tempfile import TemporaryDirectory
from threading import Thread
import os
import subprocess
import time

import httpx
import psycopg
import uvicorn

from scripts import ci_v184_actual_https_pg_order as v184
from scripts import ci_v157_real_pg_delivery_http as fixture

ACK="ONLY_EPHEMERAL_LOCAL_DATABASE"
N_READS_PER_ACTOR=24
N_CONCURRENT_REPLAYS=16
HOST=v184.HOST


def _assert_ephemeral() -> None:
    if (os.getenv("JW_ENV")!="review"
        or os.getenv("JW_PG_CI_ALLOW")!=ACK
        or "@127.0.0.1:5432/postgres" not in os.getenv("JW_PG_CI_ROOT_DSN","")):
        raise RuntimeError("BLOCKED_V188_NONLOCAL_OR_UNAPPROVED_PG")
    fixture.disposable_root_check()


def _percentile95(ms: list[float]) -> float:
    sorted_ms=sorted(ms)
    return round(sorted_ms[max(0,(95*len(sorted_ms)+99)//100-1)],3)


def acceptance(client: httpx.Client) -> None:
    # V18.4 checks real cookie, CSRF, origin, B/M isolation, approval
    # provenance, immutable order/audit, and rejects 20 fabricated quote IDs.
    v184.run_live(client)
    with psycopg.connect(fixture.DSN) as root:
        all_quotes=root.execute("SELECT id FROM jw_dev.quotes").fetchall()
        assert len(all_quotes)==1,"V188_EXPECT_EXACTLY_ONE_QUOTE"
        quote_id=all_quotes[0][0]
    endpoint=HOST+"/api/pg-stage/v92/quote-review-previews/"+quote_id

    def one_read(i: int):
        actor=("A","B","M","none")[i%4]
        headers={} if actor=="none" else v184.request_headers(actor)
        t=time.monotonic()
        try:
            res=client.get(endpoint,headers=headers)
            elapsed=(time.monotonic()-t)*1000
            return actor,res.status_code,elapsed
        except httpx.HTTPError:
            return actor,0,(time.monotonic()-t)*1000

    with ThreadPoolExecutor(max_workers=8) as pool:
        result=list(pool.map(one_read,range(N_READS_PER_ACTOR*4)))
    expected={"A":200,"B":404,"M":403,"none":401}
    mismatches=[(actor,status) for actor,status,_ in result if status!=expected[actor]]
    if mismatches:
        raise AssertionError("V188_ISOLATED_REAL_TLS_96_REQUEST_STATUS_MISMATCH "+str(mismatches[:8]))
    timings=[latency for _,_,latency in result]
    print("PASS_V188_REAL_TLS_96_READS_TENANT_MEMBER_UNAUTH_0_UNEXPECTED_STATUSES",flush=True)
    print("MEASURED_V188_EPHEMERAL_HTTPS_READ_P95_MS="+str(_percentile95(timings)),flush=True)
    print("MEASURED_V188_EPHEMERAL_HTTPS_READ_MEDIAN_MS="+str(round(median(timings),3)),flush=True)

    # Concurrent idempotent POST of the *same* previously accepted quote,
    # using real TCP HTTPS + 16 restricted PG transaction paths.
    quote_body={"request_id":"v184-real-tls-quote-01",
        "customer_id":"0"*32,
        "title":"V184 Real TLS internal quote",
        "vat_mode":"taxable",
        "items":[{"name":"Synthetic pump","quantity":2,"unit_price":3500},
                 {"name":"Synthetic seal","quantity":1,"unit_price":1800}]}
    url=HOST+"/api/pg-stage/v92/quotes"
    def replay(_: int):
        try:
            response=client.post(url,json=quote_body,headers=v184.request_headers("A",True))
            if response.status_code!=200:
                return (response.status_code,None)
            body=response.json()
            return (response.status_code,body.get("quote_id"))
        except (httpx.HTTPError,ValueError):
            return (0,None)

    with ThreadPoolExecutor(max_workers=8) as pool:
        repeats=list(pool.map(replay,range(N_CONCURRENT_REPLAYS)))
    if any(code!=200 or identity!=quote_id for code,identity in repeats):
        raise AssertionError("V188_CONCURRENT_QUOTE_REPLAY_UNEXPECTED_RESPONSE "+str(repeats))
    with psycopg.connect(fixture.DSN) as root:
        assert root.execute("SELECT count(*) FROM jw_dev.quotes").fetchone()==(1,)
        assert root.execute("SELECT count(*) FROM jw_dev.quote_items").fetchone()==(2,)
        assert root.execute("SELECT count(*) FROM jw_dev.orders").fetchone()==(1,)
        assert root.execute("SELECT count(*) FROM jw_dev.order_items").fetchone()==(2,)
        assert root.execute("SELECT count(*) FROM jw_dev.invoices").fetchone()==(0,)
    print("PASS_V188_16_CONCURRENT_HTTPS_PG17_QUOTE_REPLAYS_EXACTLY_ONE_QUOTE_AND_ORDER",flush=True)
    print("LIMIT_V188_HOSTED_RENDER_WHOLE_WORKFLOW_NOT_TESTED",flush=True)
    print("LIMIT_V188_EPHEMERAL_LATENCY_NOT_OPERATIONAL_SLO",flush=True)
    print("LIMIT_V188_NO_BANK_SETTLEMENT_OR_LEGAL_INVOICE",flush=True)


def main() -> None:
    _assert_ephemeral()
    app=v184.prepare()
    with TemporaryDirectory(prefix="jw-v188-verified-tls-") as tmp:
        key=Path(tmp)/"key.pem"
        cert=Path(tmp)/"cert.pem"
        subprocess.run(["openssl","req","-x509","-nodes","-newkey","rsa:2048",
             "-keyout",str(key),"-out",str(cert),"-days","1",
             "-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost"],
             check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        server=uvicorn.Server(uvicorn.Config(app,host="127.0.0.1",port=8767,
            ssl_keyfile=str(key),ssl_certfile=str(cert),access_log=False,log_level="error"))
        worker=Thread(target=server.run,daemon=True)
        worker.start()
        try:
            for _ in range(100):
                if server.started:break
                time.sleep(.1)
            assert server.started,"V188_EPHEMERAL_HTTPS_STARTUP_BLOCKED"
            with httpx.Client(verify=str(cert),trust_env=False,
                              follow_redirects=False,timeout=20) as client:
                acceptance(client)
        finally:
            server.should_exit=True
            worker.join(timeout=12)
            assert not worker.is_alive(),"V188_HTTPS_WORKER_CLEANUP_FAILED"


if __name__=="__main__":
    main()
