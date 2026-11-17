"""Isolated ASGI and real CutoverFront composition tests. No live DB or secrets."""
import json

import httpx
import pytest
from fastapi import FastAPI, Request
from starlette.responses import JSONResponse, StreamingResponse

from app import pg_cinema_list_integrity_v223 as integrity
from app import pg_cinema_cutover_front_v223 as cut

LEGACY_TOKEN = "L" * 40
PG_TOKEN = "P" * 40
PG_ID = "pg_" + "a" * 32


def make_real_cutover_front(rows):
    legacy = FastAPI()
    postgres = FastAPI()

    @legacy.get("/api/quotes")
    def legacy_list():
        return [{"id": "legacy-1", "amount": 500}]

    @postgres.get("/api/quotes")
    def pg_list():
        return rows

    def legacy_identity(request: Request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == LEGACY_TOKEN
        return cut.Identity("org-A", "actor-A", "admin")

    def postgres_identity(request: Request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == PG_TOKEN
        return cut.Identity("org-A", "actor-A", "admin")

    return cut.CutoverFront(
        legacy, postgres, legacy_identity, postgres_identity,
        lambda: frozenset({"org-A"}),
    )


async def fetch_merged(app):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(cut.LEGACY_COOKIE, LEGACY_TOKEN)
        client.cookies.set(cut.PG_COOKIE, PG_TOKEN)
        return await client.get("/api/quotes")


@pytest.mark.asyncio
async def test_real_cutover_baseline_repeats_pg_id_but_guard_denies():
    rows = [{"id": PG_ID, "amount": 100}, {"id": PG_ID, "amount": 100}]
    original = make_real_cutover_front(rows)
    baseline = await fetch_merged(original)
    assert baseline.status_code == 200
    assert len(baseline.json()) == 3
    guarded = await fetch_merged(integrity.MergedListIntegrityGuard(original))
    assert guarded.status_code == 503
    assert guarded.json() == {"code": "duplicate_merged_list_id"}
    assert guarded.headers["cache-control"] == "no-store"
    assert "legacy-1" not in guarded.text
    assert PG_ID not in guarded.text


@pytest.mark.asyncio
async def test_real_cutover_distinct_ids_and_source_tags_preserved():
    original = make_real_cutover_front([{"id": PG_ID, "source": "forged", "amount": 100}])
    guarded = await fetch_merged(integrity.MergedListIntegrityGuard(original))
    assert guarded.status_code == 200
    assert guarded.json() == [
        {"id": "legacy-1", "amount": 500, "source": "legacy"},
        {"id": PG_ID, "source": "pg", "amount": 100},
    ]
    assert guarded.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("source,record_id", [
    ("legacy", "legacy-1"),
    ("pg", PG_ID),
])
def test_duplicate_rows_refused_from_either_store(source, record_id):
    payload = json.dumps([{"id": record_id}, {"id": record_id}]).encode()
    with pytest.raises(integrity.ListIntegrityRefused) as error:
        integrity.validate_merged_list(payload)
    assert error.value.code == "duplicate_merged_list_id"


@pytest.mark.parametrize("bad", [
    b"{oops", b"null", b'"str"', b"[1]", b'[{"amount":100}]',
    b'[{"id":""}]', b'{"id":"one"}',
])
def test_invalid_payload_fails_closed(bad):
    with pytest.raises(integrity.ListIntegrityRefused):
        integrity.validate_merged_list(bad)


def test_10001_entries_rejected_before_browser_response():
    payload = json.dumps([{"id": str(i)} for i in range(10001)]).encode()
    with pytest.raises(integrity.ListIntegrityRefused) as error:
        integrity.validate_merged_list(payload)
    assert error.value.code == "invalid_merged_list_shape"


@pytest.mark.asyncio
async def test_streamed_duplicate_rejected_before_partial_output():
    upstream = FastAPI()

    @upstream.get("/api/quotes")
    async def quotes():
        async def chunks():
            yield b'[{"id":"pg_duplicate"},'
            yield b'{"id":"pg_duplicate"}]'
        return StreamingResponse(chunks(), media_type="application/json")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=integrity.MergedListIntegrityGuard(upstream)),
        base_url="https://testserver",
    ) as client:
        response = await client.get("/api/quotes")
    assert response.status_code == 503
    assert response.json() == {"code": "duplicate_merged_list_id"}
    assert "pg_duplicate" not in response.text


@pytest.mark.asyncio
async def test_large_body_fails_closed():
    upstream = FastAPI()

    @upstream.get("/api/quotes")
    def quotes():
        return JSONResponse([{"id": "p", "value": "z" * integrity.MAX_LIST_BYTES}])

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=integrity.MergedListIntegrityGuard(upstream)),
        base_url="https://testserver",
    ) as client:
        response = await client.get("/api/quotes")
    assert response.status_code == 503
    assert response.json() == {"code": "merged_list_response_too_large"}


@pytest.mark.asyncio
async def test_non_list_and_unauthorized_responses():
    upstream = FastAPI()

    @upstream.get("/api/quotes")
    def quotes():
        return {"wrong": "schema"}

    @upstream.get("/api/customers")
    def auth():
        return JSONResponse({"error": "sign in"}, status_code=401)

    @upstream.get("/api/health")
    def health():
        return {"status": "ok"}

    @upstream.post("/api/quotes")
    def post():
        return {"status": "untouched"}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=integrity.MergedListIntegrityGuard(upstream)),
        base_url="https://testserver",
    ) as client:
        mismatch = await client.get("/api/quotes")
        denied = await client.get("/api/customers")
        health = await client.get("/api/health")
        post = await client.post("/api/quotes")
    assert mismatch.status_code == 503
    assert mismatch.json() == {"code": "invalid_merged_list_shape"}
    assert denied.status_code == 401
    assert denied.json() == {"error": "sign in"}
    assert health.json() == {"status": "ok"}
    assert post.json() == {"status": "untouched"}


@pytest.mark.asyncio
async def test_single_valid_response_keeps_original_bytes_and_headers():
    upstream = FastAPI()

    @upstream.get("/api/invoices")
    def invoices():
        return JSONResponse([{"id": "pg_" + "b" * 32, "amount": 140}],
                            headers={"X-Trace": "safe-marker"})

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=integrity.MergedListIntegrityGuard(upstream)),
        base_url="https://testserver",
    ) as client:
        response = await client.get("/api/invoices")
    assert response.status_code == 200
    assert response.headers["x-trace"] == "safe-marker"
    assert response.json() == [{"id": "pg_" + "b" * 32, "amount": 140}]


@pytest.mark.parametrize("env,flag", [("production", "ISOLATED_REVIEW_ONLY"),
                                     ("review", "not-approved"), ("", "")])
def test_factory_fails_closed_without_isolated_approval(monkeypatch, env, flag):
    monkeypatch.setenv("JW_ENV", env)
    monkeypatch.setenv("JW_MERGED_LIST_INTEGRITY_V223", flag)
    with pytest.raises(RuntimeError, match="isolated review"):
        integrity.create_guarded_app()


def test_factory_disallows_unsafe_local_dev(monkeypatch):
    monkeypatch.setenv("JW_ENV", "review")
    monkeypatch.setenv("JW_MERGED_LIST_INTEGRITY_V223", "ISOLATED_REVIEW_ONLY")
    monkeypatch.setenv("JW_INSECURE_LOCAL_DEV", "1")
    with pytest.raises(RuntimeError, match="isolated review"):
        integrity.create_guarded_app()
