"""V21.7: synthetic-only OCR high-resolution input and approval-safety tests.

No AI-Hub bytes, real customers, network posting, or production database.
Tests full worker source path and ephemeral FastAPI preview/confirm protections.
"""
from __future__ import annotations
import hashlib
import io
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from PIL import Image, ImageDraw, ImageFont
from app import evidence_v64_worker as w

FONT_FILE = Path("/usr/share/fonts/truetype/nanum/NanumGothic.ttf")


def photo(width=600, height=600, fmt="JPEG", orientation=None):
    image = Image.new("RGB", (width, height), "white")
    d = ImageDraw.Draw(image)
    font = ImageFont.truetype(str(FONT_FILE), 62) if FONT_FILE.exists() else ImageFont.load_default()
    for i, line in enumerate(("문서종류: 영수증", "거래처: 가상기업", "거래일: 2026-11-03", "총금액: 11000")):
        d.text((80, 70+i*110), line, font=font, fill="black")
    out = io.BytesIO()
    opts = {}
    if orientation is not None:
        exif = Image.Exif()
        exif[274] = orientation
        opts["exif"] = exif
    image.save(out, format=fmt, **opts)
    return out.getvalue()


def stub_ocr(monkeypatch):
    called = []
    def fake(command, **kwargs):
        target = Path(command[1])
        with Image.open(target) as img:
            called.append({"size": img.size, "format": img.format,
                           "exif": dict(img.getexif()), "name": target.name,
                           "command": command[:], "contents_sha": hashlib.sha256(target.read_bytes()).hexdigest()})
        return SimpleNamespace(returncode=0,stdout="문서종류: 영수증\n거래처: 가상기업\n거래일: 2026-11-03\n총금액: 11000".encode())
    monkeypatch.setattr(w.subprocess,"run",fake)
    return called


@pytest.mark.parametrize("wth,hgt", [(3700,3500),(4000,3400),(4800,4000),(3500,4000)])
def test_high_resolution_enters_worker_and_is_downscaled(monkeypatch,wth,hgt):
    calls=stub_ocr(monkeypatch)
    raw=photo(wth,hgt)
    digest=hashlib.sha256(raw).hexdigest()
    result=w.extract("synthetic.jpg",raw)
    assert result["method"]=="ocr"
    assert result["quality"]["needs_manual_review"] is True
    assert result["proposed_record_type"]=="expense"
    assert len(calls)==1 and calls[0]["name"]=="input.jpg"
    out_w,out_h=calls[0]["size"]
    assert out_w*out_h<=w.MAX_PIXELS
    assert out_w*out_h<=w.DOWNSAMPLE_TARGET_PIXELS
    assert calls[0]["format"]=="JPEG"
    assert calls[0]["exif"]=={}
    assert calls[0]["command"][-3:]==["--psm","6"][-3:] if False else calls[0]["command"][-2:]==["--psm","6"]
    assert digest==hashlib.sha256(raw).hexdigest(), "original must remain unchanged"


@pytest.mark.parametrize("wth,hgt", [(600,600),(1800,1800),(3000,3000)])
def test_existing_below_limit_path_unchanged(monkeypatch,wth,hgt):
    calls=stub_ocr(monkeypatch)
    assert w.extract("existing.png",photo(wth,hgt,fmt="PNG"))["method"]=="ocr"
    assert len(calls)==1 and calls[0]["name"]=="input.png"
    assert calls[0]["format"]=="PNG"
    assert calls[0]["size"]==(wth,hgt)


@pytest.mark.parametrize("wth,hgt", [(4900,4100),(6000,3800),(9100,100),(100,9100),(45,600),(600,45)])
def test_rejects_pixel_or_edge_limit(monkeypatch,wth,hgt):
    # Use valid but bounded images; OCR should never launch.
    called=stub_ocr(monkeypatch)
    raw=photo(wth,hgt)
    with pytest.raises(w.EvidenceError,match="해상도"):
        w.extract("disallowed.jpg",raw)
    assert called==[]


@pytest.mark.parametrize("name,content", [
    ("malware.exe",b"hello"),("fake.jpg",b"%PDF-1.4"),
    ("fake.png",b"\xff\xd8\xff invalid"),("blank.jpeg",b""),
    ("oversized.jpg",b"X"*(w.MAX_BYTES+1)),
])
def test_rejects_unsupported_or_invalid_inputs_without_ocr(monkeypatch,name,content):
    called=stub_ocr(monkeypatch)
    with pytest.raises(w.EvidenceError):
        w.extract(name,content)
    assert called==[]


def test_exif_rotation_metadata_stripped_on_large_image(monkeypatch):
    calls=stub_ocr(monkeypatch)
    result=w.extract("rotated.jpg",photo(4000,3500,orientation=6))
    assert result["method"]=="ocr"
    assert len(calls)==1
    assert calls[0]["size"][0]<calls[0]["size"][1]
    assert calls[0]["exif"]=={}


def test_large_image_still_cannot_auto_approve(monkeypatch):
    calls=stub_ocr(monkeypatch)
    doc=w.extract("financial.jpg",photo(4000,3500))
    assert doc["quality"]["calibrated_confidence"] is None
    assert doc["quality"]["needs_manual_review"] is True
    assert doc["source_sha_note"].startswith("원본은 저장되지 않으며")
    assert doc["document_kind"]=="receipt"
    assert calls


def test_original_5mb_ceiling_preserved():
    assert w.MAX_BYTES==5*1024*1024
    assert w.MAX_PIXELS==12_000_000
    assert w.MAX_SOURCE_IMAGE_PIXELS==20_000_000


def test_real_api_highres_preview_remains_pending(api):
    raw=photo(4000,3400)
    assert len(raw)<w.MAX_BYTES
    response=api.c.post("/api/evidence/preview", files={"file":("synthetic-highres.jpg",raw,"image/jpeg")},headers=api.auth)
    assert response.status_code==201,response.text
    payload=response.json()
    assert payload["status"]=="pending"
    assert payload["confirmation_required"] is True
    assert payload["original_file_stored"] is False
    assert payload["document"]["quality"]["needs_manual_review"] is True
    dashboard=api.get("/evidence/dashboard").json()
    assert dashboard["total_confirmed"]==0
    assert dashboard["pending_review"]==1


def test_real_api_hard_ceiling_unchanged(api):
    raw=b"x"*(w.MAX_BYTES+1)
    response=api.c.post("/api/evidence/preview",files={"file":("oversized.jpg",raw)},headers=api.auth)
    assert response.status_code==413
    assert api.get("/evidence/dashboard").json()["pending_review"]==0


def test_real_api_wrong_extension_or_corrupt_image_rejected(api):
    r=api.c.post("/api/evidence/preview",files={"file":("bad.jpg",b"garbage")},headers=api.auth)
    assert r.status_code==422
    r=api.c.post("/api/evidence/preview",files={"file":("bad.exe",b"garbage")},headers=api.auth)
    assert r.status_code==422
    assert api.get("/evidence/dashboard").json()["pending_review"]==0


def test_real_api_no_csrf_cannot_upload(api):
    raw=photo(700,600)
    result=api.c.post("/api/evidence/preview",files={"file":("bad.jpg",raw)})
    assert result.status_code==403
    assert api.get("/evidence/dashboard").json()["pending_review"]==0


def test_real_api_duplicate_highres_rejected_before_ocr(api,monkeypatch):
    from app import evidence_v64
    raw=photo(4000,3400)
    ok=api.c.post("/api/evidence/preview",files={"file":("first.jpg",raw)},headers=api.auth)
    assert ok.status_code==201,ok.text
    def forbidden(*args,**kwargs):
        raise AssertionError("duplicate must not enter expensive OCR")
    monkeypatch.setattr(evidence_v64,"protected_parse",forbidden)
    duplicate=api.c.post("/api/evidence/preview",files={"file":("second.jpg",raw)},headers=api.auth)
    assert duplicate.status_code==409
    assert api.get("/evidence/dashboard").json()["total_confirmed"]==0
