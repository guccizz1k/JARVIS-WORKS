"""V19.0 real TLS -> restricted PostgreSQL17 messenger and attachment acceptance.

Uses original V9.0 RPC handlers; fresh localhost-only disposable PostgreSQL17
in GitHub Actions. No Supabase, Render DB, bank, customer accounts, or
production data. Actual TLS, no TestClient nor mock backend.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from threading import Thread
import time

import httpx
import psycopg
import uvicorn

from scripts import ci_v90_postgres_browser as fixture

ACK="ONLY_EPHEMERAL_LOCAL_DATABASE"
HOST="https://localhost:8768"
PAYLOAD=b"SYNTHETIC_V190_ATTACHMENT_INTEGRITY_ONLY\n"


def headers(actor: str, write: bool = False):
    result={"Cookie":"jw_ci_session="+fixture.TOKENS[actor],
            "Cache-Control":"no-store"}
    if write:result["X-CSRF-Token"]=fixture.CSRF[actor]
    return result


def assert_http(response: httpx.Response, code: int, label: str):
    if response.status_code != code:
        raise AssertionError((label,response.status_code,response.text[:180]))
    return response.json()


def run(client: httpx.Client):
    post=lambda path,body,who="A":client.post(HOST+path,json=body,headers=headers(who,True))
    get=lambda path,who="A":client.get(HOST+path,headers=headers(who))
    base="/api/pg-stage/v90"
    assert client.post(HOST+base+"/chats",json={"other_org_id":"ci-b"},
                       headers=headers("A")).status_code==403
    assert post(base+"/chats",{"other_org_id":"ci-a"}).status_code==403
    assert post(base+"/chats",{"other_org_id":"ci-unknown"}).status_code==403
    started=assert_http(post(base+"/chats",{"other_org_id":"ci-b"}),200,"start-chat")
    chat=started["connection_id"]
    assert chat and len(chat)<=128
    text_payload={"request_id":"v190-synthetic-attach-0001",
        "body":"V190 internal document discussion",
        "filename":"v190-safe.txt","mime":"text/plain",
        "data_base64":base64.b64encode(PAYLOAD).decode("ascii")}
    send_path=base+"/chats/"+chat+"/messages"
    assert client.post(HOST+send_path,json=text_payload,
                       headers=headers("A")).status_code==403
    assert client.post(HOST+send_path,json={**text_payload,"data_base64":"!bad!"},
                       headers=headers("A",True)).status_code==422
    sent=assert_http(post(send_path,text_payload),200,"send-attachment")
    mid=sent["message_id"]
    assert sent["replayed"] is False
    assert_http(post(send_path,text_payload),200,"idempotent-replay")
    assert post(send_path,{**text_payload,"body":"tampered-payload"}).status_code==409

    messages=assert_http(get(send_path,"B"),200,"recipient-sync")
    assert sum(m["message_id"]==mid and m["body"]==text_payload["body"]
           and m["filename"]=="v190-safe.txt" for m in messages)==1
    attachment=HOST+base+"/chats/"+chat+"/attachments/"+mid
    a=client.get(attachment,headers=headers("B"))
    assert a.status_code==200 and a.content==PAYLOAD
    assert a.headers["Content-Type"].startswith("application/octet-stream")
    assert "attachment;" in a.headers["content-disposition"]
    assert a.headers["x-content-type-options"]=="nosniff"
    assert a.headers["cache-control"]=="no-store"
    assert get(send_path,"C").status_code==403
    assert client.get(attachment,headers=headers("C")).status_code==403
    assert client.patch(HOST+base+"/messages/"+mid,
              json={"body":"forgery","expected_version":1},
              headers=headers("B",True)).status_code==403

    # Twenty different IDs prove missing/forged chat IDs stay inaccessible.
    for i in range(20):
        forged=f"v190-inaccessible-{i:04d}"
        assert get(base+"/chats/"+forged+"/messages","A").status_code==403
        assert client.get(HOST+base+"/chats/"+forged+"/attachments/"+mid,
                          headers=headers("A")).status_code==403
    # Replay under concurrent real TLS connections, only one durable row.
    def replay(_: int):
        res=client.post(HOST+send_path,json=text_payload,headers=headers("A",True))
        return res.status_code,res.json().get("message_id") if res.status_code==200 else None
    with ThreadPoolExecutor(max_workers=6) as pool:
        concurrent=list(pool.map(replay,range(12)))
    assert all(code==200 and m==mid for code,m in concurrent),concurrent
    with psycopg.connect(fixture.root_dsn) as db:
        assert db.execute("""SELECT count(*) FROM jw_dev.messenger_messages
                             WHERE id=%s""",(mid,)).fetchone()==(1,)
        assert db.execute("""SELECT count(*) FROM jw_dev.messenger_attachments
                             WHERE message_id=%s AND size_bytes=%s
                             AND content_hash=%s""",(mid,len(PAYLOAD),
                                hashlib.sha256(PAYLOAD).hexdigest())).fetchone()==(1,)
        # Isolated disposable session revocation; never touch user accounts.
        db.execute("DELETE FROM jw_dev.sessions WHERE id='B'")
    assert get(send_path,"B").status_code==401
    assert client.get(attachment,headers=headers("B")).status_code==401
    assert_http(get(send_path,"A"),200,"sender-survives-recipient-revocation")
    print("PASS_V190_ACTUAL_HTTPS_PG17_A_TO_B_DOCUMENT_TEXT_ATTACHMENT_AND_DOWNLOAD")
    print("PASS_V190_20_FORGED_CHAT_IDS_40_READ_DENIALS_AND_CSRF_TENANT_REVOCATION")
    print("PASS_V190_12_CONCURRENT_TLS_IDEMPOTENT_ATTACHMENT_REPLAYS_ONE_STORED_MESSAGE")
    print("LIMIT_V190_LOCAL_DISPOSABLE_NOT_HOSTED_RENDER_MESSENGER_LIVE")


def main() -> None:
    if (os.getenv("JW_ENV")!="review" or
        os.getenv("JW_PG_CI_ALLOW")!=ACK or
        "@127.0.0.1:5432/postgres" not in os.getenv("JW_PG_CI_ROOT_DSN","")):
        raise RuntimeError("BLOCKED_V190_REQUIRES_LOCAL_DISPOSABLE_PG17")
    fixture.require_disposable()
    fixture.bootstrap()
    with TemporaryDirectory(prefix="jw-v190-https-") as tmp:
        key,crt=Path(tmp)/"key.pem",Path(tmp)/"cert.pem"
        subprocess.run(["openssl","req","-x509","-nodes","-newkey","rsa:2048",
            "-keyout",str(key),"-out",str(crt),"-days","1","-subj","/CN=localhost",
            "-addext","subjectAltName=DNS:localhost"],check=True,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        server=uvicorn.Server(uvicorn.Config(fixture.app,host="127.0.0.1",port=8768,
            ssl_keyfile=str(key),ssl_certfile=str(crt),log_level="error",access_log=False))
        worker=Thread(target=server.run,daemon=True)
        worker.start()
        try:
            for _ in range(100):
                if server.started:break
                time.sleep(.1)
            assert server.started,"V190_HTTPS_STARTUP_FAILED"
            with httpx.Client(verify=str(crt),trust_env=False,
                  follow_redirects=False,timeout=20) as client:
                run(client)
        finally:
            server.should_exit=True
            worker.join(timeout=15)
            assert not worker.is_alive(),"V190_HTTPS_SERVER_CLEANUP_FAILED"


if __name__=="__main__":
    main()
