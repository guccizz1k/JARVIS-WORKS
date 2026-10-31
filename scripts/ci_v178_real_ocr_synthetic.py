"""V17.8 offline actual Tesseract OCR study on 24 synthetic Korean forms.

Never connects to a service, uses company data, or changes the production
import engine. Produces privacy-safe aggregate accuracy and *always* marks
production OCR as UNVERIFIED.  Synthetic performance cannot be used as an
approval gate for customer-document automation.
"""
from __future__ import annotations

from pathlib import Path
import json
import re
import subprocess
import tempfile
from PIL import Image, ImageDraw, ImageEnhance, ImageFilter, ImageFont

from scripts.ocr_quality_gate_v77 import evaluate

_COUNT = 24
_ALLOWED = {"counterparty", "business_number", "total_amount"}
_FONT_ROOT = Path("/usr/share/fonts")
_MAX_IMAGE = 10_000_000


def _font() -> Path:
    candidates=sorted(_FONT_ROOT.rglob("*NanumGothic*.ttf"))
    if not candidates:
        raise RuntimeError("BLOCKED_KOREAN_FONT_NOT_INSTALLED")
    return candidates[0]


def parse_fields(untrusted_text: str) -> dict[str,str]:
    """Conservative; never guess from neighboring amounts or unknown lines."""
    if type(untrusted_text) is not str or len(untrusted_text) > 20_000:
        raise ValueError("Oversized untrusted OCR")
    output={}
    poisoned=set()
    def offer(field: str, value: str) -> None:
        # Repeated contradictory OCR labels must abstain rather than guess.
        if field in poisoned:
            return
        if field in output and output[field] != value:
            poisoned.add(field)
            output.pop(field,None)
        else:
            output[field]=value
    for line in untrusted_text.splitlines():
        v=line.strip()
        if not v or len(v)>180:
            continue
        # Every value must have its recognized label on that SAME line.
        if re.match(r"^(거래처|고객사)\s*[:：]",v):
            after=re.split(r"[:：]",v,maxsplit=1)
            if len(after)==2:
                name=after[1].strip()
                if 1<=len(name)<=80 and not any(ord(c)<32 for c in name):
                    offer("counterparty",name)
        elif re.match(r"^사업자(등록)?번호\s*[:：]",v):
            after=re.split(r"[:：]",v,maxsplit=1)
            if len(after)==2:
                numbers=re.sub(r"[\s-]","",after[1])
                if re.fullmatch(r"\d{10}",numbers):
                    offer("business_number",numbers)
        elif re.match(r"^(총금액|총합계)\s*[:：]",v):
            after=re.split(r"[:：]",v,maxsplit=1)
            if len(after)==2:
                amount=after[1].strip().replace(",","")
                if re.fullmatch(r"\d{1,16}",amount):
                    offer("total_amount",str(int(amount)))
    return output


def _render(path: Path, font: ImageFont.FreeTypeFont, number: int) -> dict:
    biz="12345678"+f"{number:02d}"
    amount=7700+100*number
    company="한빛상사"+f"{number:02d}"
    expected={"counterparty":company,"business_number":biz,
              "total_amount":str(amount)}
    im=Image.new("RGB",(1120,520),"white")
    d=ImageDraw.Draw(im)
    values=[
       "견적서 — SYNTHETIC TEST ONLY",
       f"거래처: {company}",
       f"사업자등록번호: {biz}",
       "견적일: 2026-10-31",
       "공급가액: 7000",
       "부가세: 700",
       f"총금액: {amount:,}",
    ]
    for n,line in enumerate(values):
        d.text((40,25+n*65),line,fill="black",font=font)
    variant=number%6
    if variant==1: im=im.rotate(1.2,resample=Image.Resampling.BICUBIC,expand=True,fillcolor="white")
    elif variant==2: im=im.resize((750,360)).resize(im.size,Image.Resampling.BICUBIC)
    elif variant==3: im=im.filter(ImageFilter.GaussianBlur(0.8))
    elif variant==4: im=ImageEnhance.Contrast(im).enhance(0.6)
    elif variant==5: im=im.rotate(-2.2,resample=Image.Resampling.BICUBIC,expand=True,fillcolor="white")
    if im.width*im.height > 1_800_000:
        raise RuntimeError("BLOCKED_OVERSIZED_SYNTHETIC_IMAGE")
    im.save(path,"PNG")
    if path.stat().st_size>_MAX_IMAGE:
        raise RuntimeError("BLOCKED_OVERSIZED_PNG")
    return expected


def benchmark() -> dict:
    font=ImageFont.truetype(str(_font()),34)
    rows=[]
    with tempfile.TemporaryDirectory(prefix="jw-v178-ocr-") as tmp:
        work=Path(tmp)
        for i in range(_COUNT):
            image=work/(f"case_{i:02d}.png")
            expected=_render(image,font,i)
            p=subprocess.run(
                ["tesseract",str(image),"stdout","-l","kor+eng",
                 "--psm","6"],capture_output=True,text=True,
                timeout=15,check=False,
            )
            if p.returncode!=0:
                raise RuntimeError("BLOCKED_TESSERACT_PROCESS_FAILED")
            predicted=parse_fields(p.stdout)
            rows.append({"expected":expected,"predicted":predicted})
    score=evaluate(rows,dataset="synthetic")
    if score["documents"] != _COUNT or set(score["fields"]) != _ALLOWED:
        raise RuntimeError("BLOCKED_INCOMPLETE_OCR_REPORT")
    if any(v["samples"]!=_COUNT for v in score["fields"].values()):
        raise RuntimeError("BLOCKED_PARTIAL_FIELD_COVERAGE")
    if score["production_quality_approved"] is not False:
        raise RuntimeError("BLOCKED_FALSE_PRODUCTION_CERTIFICATION")
    return {
        "metric": "V178_LABELED_SYNTHETIC_OCR_MEASUREMENT_ONLY",
        "documents":_COUNT,
        "variations":"upright,rotated,downsampled,blurred,low_contrast",
        "ocr_model":"locally_installed_tesseract_kor_eng",
        "report":score,
        "customer_document_accuracy_measured":False,
        "business_auto_registration_approved":False,
        "production_ocr_readiness":"BLOCKED",
    }


def main():
    result=benchmark()
    out=Path("v178-synthetic-ocr-report.json")
    out.write_text(json.dumps(result,ensure_ascii=False,
                              sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("PASS_V178_ACTUAL_OCR_EXECUTED_ON_24_LABELED_SYNTHETIC_DOCUMENTS")
    print("BLOCKED_V178_PRODUCTION_ACCURACY_NO_CONSENTED_REAL_BENCHMARK")
    print("AGGREGATE_RESULT="+json.dumps(result["report"]["fields"],
           sort_keys=True,ensure_ascii=False))


if __name__=="__main__":
    main()
