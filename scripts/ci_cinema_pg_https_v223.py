#!/usr/bin/env python3
"""Exercise V22.3 real V9 PostgreSQL TLS and legacy HTTP API through a real HTTPS socket.

Requires the existing disposable PostgreSQL 17 GitHub Actions service and CI-only
certificate. Never connects to real Supabase, Render or business data.
"""
from __future__ import annotations

import os
import socket
import threading
import time
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI

from scripts import ci_cinema_pg_validated_tls_e2e_v223 as validated


def run() -> int:
    if os.environ.get("JW_CINEMA_PG_DISPOSABLE") != "1":
        raise SystemExit("BLOCKED: disposable PG17 required")
    if os.environ.get("PGHOST") not in ("127.0.0.1", "localhost"):
        raise SystemExit("BLOCKED: loopback PostgreSQL required")

    cert = Path(os.environ.get("JW_PG_CI_TLS_SERVER_CERT", ""))
    key = Path(os.environ.get("JW_PG_CI_TLS_SERVER_KEY", ""))
    ca = Path(os.environ.get("JW_PG_CI_TLS_CA", ""))
    if not all(p.is_file() for p in (cert, key, ca)):
        raise SystemExit("BLOCKED: disposable TLS certificate/CA missing")

    servers: list[tuple[uvicorn.Server, threading.Thread]] = []
    clients: list[httpx.Client] = []

    def real_https_client(app: FastAPI, base_url: str = "https://testserver") -> httpx.Client:
        # Base URL from historical TestClient call is intentionally replaced by
        # an actual loopback TLS listener. The server is not externally exposed.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(128)
        sock.setblocking(False)
        port = sock.getsockname()[1]
        config = uvicorn.Config(
            app=app, host="127.0.0.1", port=port,
            ssl_certfile=str(cert), ssl_keyfile=str(key),
            log_level="warning", lifespan="off", proxy_headers=False,
        )
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        servers.append((server, thread))
        deadline = time.monotonic() + 12
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        if not server.started:
            raise RuntimeError("FAIL_V223_HTTPS_SERVER_NOT_STARTED")

        url = f"https://127.0.0.1:{port}"
        client = httpx.Client(base_url=url, verify=str(ca), trust_env=False, timeout=15)
        clients.append(client)
        response = client.get("/api/quotes")
        if response.status_code != 401 or response.url.scheme != "https":
            raise AssertionError(f"FAIL_V223_HTTPS_UNAUTHENTICATED_ROUTE: {response.status_code}")
        print("PASS_V223_HTTPS_VERIFIED_TLS_SOCKET_AND_401", flush=True)
        try:
            with httpx.Client(base_url=url, verify=True, trust_env=False, timeout=3) as untrusted:
                untrusted.get("/api/quotes")
        except httpx.ConnectError:
            print("PASS_V223_HTTPS_UNTRUSTED_CERT_REFUSED", flush=True)
        else:
            raise AssertionError("FAIL_V223_HTTPS_UNTRUSTED_CERT_ACCEPTED")
        return client

    original_test_client = validated.e2e.TestClient
    validated.e2e.TestClient = real_https_client
    try:
        code = validated.main()
        if code != 0:
            return code
        if len(clients) != 1:
            raise AssertionError("FAIL_V223_HTTPS_SINGLE_SERVER_NOT_USED")
        print("PASS_V223_REAL_HTTPS_74_HTTP_E2E_VERIFIED_TLS", flush=True)
        return 0
    finally:
        validated.e2e.TestClient = original_test_client
        for client in clients:
            client.close()
        for server, thread in servers:
            server.should_exit = True
            thread.join(timeout=8)


if __name__ == "__main__":
    raise SystemExit(run())
