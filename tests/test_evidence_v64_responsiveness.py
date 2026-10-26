"""Concurrency regression: OCR cannot block the single Uvicorn async event loop."""
import asyncio
import threading
import time
import pytest
import httpx
from app import evidence_v64,main
from tests.test_evidence_v64 import xlsx

@pytest.mark.asyncio
async def test_ocr_worker_does_not_block_async_server(api,monkeypatch):
    started=threading.Event()
    def long_ocr(filename,raw):
        started.set()
        time.sleep(.7)
        return {'document_kind':'receipt','kind_inference':'explicit','method':'xlsx',
                'filename':filename,'fields':{'counterparty':'한국상사','document_date':'2026-10-21',
                'reference_number':'FAST-TEST','gross_amount':11000},'warnings':[]}
    monkeypatch.setattr(evidence_v64,'protected_parse',long_ocr)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app),base_url='https://testserver') as client:
        upload=asyncio.create_task(client.post('/api/evidence/preview',
                files={'file':('fast.xlsx',xlsx())},headers=api.auth))
        for i in range(30):
            if started.is_set():break
            await asyncio.sleep(.015)
        assert started.is_set(), 'OCR thread was not scheduled'
        t=time.monotonic()
        try:
            r=await asyncio.wait_for(client.get('/api/config'),timeout=.4)
            latency=time.monotonic()-t
        finally:
            response=await upload
        assert r.status_code==200
        assert latency<.55, 'Health route was stalled by synchronous OCR'
        assert response.status_code==201,response.text
