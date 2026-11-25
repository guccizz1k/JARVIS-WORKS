"""V17.9 isolated measured OCR field-specific multiview experiment.

This is a study over 24 synthetic forms, NOT a product OCR endpoint and not
an approval for uploaded scans. Preserve the V17.8 raw OCR baseline and
never publish a named company, number or amount from a customer.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile

from PIL import Image, ImageOps

from scripts.ci_v178_real_ocr_synthetic import _render, _font, parse_fields
from scripts.ocr_quality_gate_v77 import evaluate

N=24
FIELDS=("counterparty","business_number","total_amount")


def _image(original: Image.Image, mode: str) -> Image.Image:
    if mode=="raw":
        return original
    gray=ImageOps.autocontrast(ImageOps.grayscale(original))
    if mode=="autocontrast":
        return gray
    if mode=="binary":
        # Local synthetic study only. Threshold is not validated on customer
        # scans or other business document layouts.
        enlarged=gray.resize((original.width*2,original.height*2),
                             Image.Resampling.LANCZOS)
        return enlarged.point(lambda v:255 if v>160 else 0)
    raise ValueError("Unexpected OCR preprocessing mode")


def _ocr(pic: Image.Image, folder: Path, name: str) -> dict[str,str]:
    image=folder/(name+".png")
    pic.save(image)
    env={**os.environ,"OMP_THREAD_LIMIT":"1"}
    result=subprocess.run(
        ["tesseract",str(image),"stdout","-l","kor+eng","--psm","6"],
        capture_output=True,text=True,check=False,timeout=15,env=env,
    )
    if result.returncode!=0 or len(result.stdout)>20_000:
        raise RuntimeError("BLOCKED_TESSERACT_OR_UNBOUNDED_OUTPUT")
    return parse_fields(result.stdout)


def fused(raw: dict, autocontrast: dict, binary: dict) -> dict:
    """Conservatively recover money from two image views.

    Never use the binary view for a monetary field: in the synthetic data
    that mode produced false monetary amounts. If two nonempty money
    candidates disagree, abstain; never guess. Nonfinancial candidates
    use the binary view and still require manual customer confirmation.
    """
    out={}
    for key in ("counterparty","business_number"):
        val=binary.get(key)
        if val:
            out[key]=val
    r=raw.get("total_amount")
    c=autocontrast.get("total_amount")
    if r and c and r!=c:
        return out
    if r or c:
        out["total_amount"]=r or c
    return out


def study() -> dict:
    font=__import__("PIL.ImageFont",fromlist=["truetype"]).truetype(str(_font()),34)
    ground=[]
    baseline=[]
    fused_rows=[]
    with tempfile.TemporaryDirectory(prefix="jw-v179-synthetic-") as tmp:
        place=Path(tmp)
        for index in range(N):
            original=place/(f"source_{index:02d}.png")
            expected=_render(original,font,index)
            picture=Image.open(original)
            views={mode:_ocr(_image(picture,mode),place,f"{mode}_{index}")
                   for mode in ("raw","autocontrast","binary")}
            baseline.append({"expected":expected,"predicted":views["raw"]})
            fused_rows.append({"expected":expected,"predicted":
                               fused(views["raw"],views["autocontrast"],views["binary"])})
    baseline_report=evaluate(baseline,dataset="synthetic")
    fused_report=evaluate(fused_rows,dataset="synthetic")
    if (baseline_report["documents"]!=N or fused_report["documents"]!=N
            or any(fused_report["fields"][f]["samples"]!=N for f in FIELDS)
            or baseline_report["production_quality_approved"] is not False
            or fused_report["production_quality_approved"] is not False):
        raise RuntimeError("BLOCKED_INCOMPLETE_OCR_DATA_OR_FALSE_APPROVAL")
    # An experimentally promising result is NOT customer document fidelity.
    for field in FIELDS:
        if (fused_report["fields"][field]["incorrect_nonempty_predictions"]
                >baseline_report["fields"][field]["incorrect_nonempty_predictions"]):
            raise RuntimeError("FAIL_SYNTHETIC_OCR_FALSE_POSITIVE_REGRESSION")
    if fused_report["fields"]["total_amount"]["incorrect_nonempty_predictions"]!=0:
        raise RuntimeError("FAIL_SYNTHETIC_OCR_FINANCIAL_FALSE_POSITIVES")
    return {
        "experiment":"V179_FIELD_SPECIFIC_REAL_TESSERACT_SYNTHETIC_ONLY",
        "n":N,
        "source":"generated_and_labeled_Korean_synthetic_forms",
        "modes":["raw","autocontrast","binary"],
        "baseline":baseline_report,
        "field_fusion":fused_report,
        "real_customer_documents_tested":False,
        "physical_source_authenticity_verified":False,
        "business_auto_registration_approved":False,
        "production_ocr_readiness":"BLOCKED",
        "limits":"Synthetic single-layout corpus only; no production OCR acceptance",
    }


def main():
    report=study()
    Path("v179-synthetic-ocr-multiview.json").write_text(
        json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+"\n",
        encoding="utf-8",
    )
    print("PASS_V179_REAL_24_SYNTHETIC_MULTIVIEW_OCR")
    print("STUDY_AGGREGATE="+json.dumps(report["field_fusion"]["fields"],ensure_ascii=False,sort_keys=True))
    print("BLOCKED_V179_REAL_CUSTOMER_SCAN_QUALITY_AND_AUTOMATION_APPROVAL")


if __name__=="__main__":
    main()
