"""V18.6 research-only Korean REAL photographed receipt OCR pilot.

Fetch two publicly published KORIE sample photographs at pinned Git blob
hashes, run installed Korean Tesseract and report measured field recall.
The manual labels below are preliminary visual transcriptions, NOT an
independently verified customer/official annotation or 50-document benchmark.
No image is retained, redistributed, uploaded to product or used for training.
A successful measurement must NOT be labeled product OCR accuracy PASS.
Source: https://github.com/MahmoudSalah/KORIE (research sample photographs).
"""
from __future__ import annotations

from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import json
import os
import re
import subprocess

import httpx
from PIL import Image, ImageOps

ACK="RESEARCH_ONLY_PUBLIC_KORIE_TWO_SAMPLES"
SAMPLES=(
    ("IMG00632.png","28a9e5e99f63f582983a4d3401928e2b7608cb2f",
     "3018541046","3980"),
    ("IMG00764.jpeg","5ef33b9ff31cbdb7bcb6ee1586c38bc73082fde9",
     "6138180546","3560"),
)
BASE="https://raw.githubusercontent.com/MahmoudSalah/KORIE/main/Samples/"
RECALL_FIELDS=("business_number","final_paid_amount")


def numeric_candidates(output: str) -> set[str]:
    """Presence-only probe; not anchored key-value extraction."""
    if type(output) is not str or len(output)>20_000:
        return set()
    # Do not concatenate numbers across arbitrary labels or lines.
    matches=re.findall(r"(?<![\d-])(?:\d{3}-\d{2}-\d{5}|\d{1,3}(?:[,]\d{3})+|\d{4,12})(?![\d-])",output)
    return {re.sub(r"\D","",m) for m in matches}


def fetch_sample(client: httpx.Client,name: str,git_sha: str) -> Image.Image:
    if (name not in {s[0] for s in SAMPLES}
            or not re.fullmatch("[a-f0-9]{40}",git_sha)):
        raise ValueError("UNAPPROVED_OCR_SAMPLE")
    response=client.get(BASE+name)
    if response.status_code!=200 or len(response.content)>5_000_000:
        raise RuntimeError("BLOCKED_PUBLIC_OCR_DATASET_TRANSPORT")
    raw=response.content
    header=f"blob {len(raw)}\0".encode("ascii")
    if hashlib.sha1(header+raw).hexdigest()!=git_sha:
        raise AssertionError("PUBLIC_IMAGE_GIT_BLOB_HASH_CHANGED")
    img=Image.open(BytesIO(raw))
    img.verify()
    img=Image.open(BytesIO(raw))
    if img.width>5000 or img.height>5000 or img.width*img.height>20_000_000:
        raise RuntimeError("BLOCKED_OCR_IMAGE_DIMENSIONS")
    return img.convert("RGB")


def view(img: Image.Image, kind: str):
    if kind=="raw":return img
    gray=ImageOps.autocontrast(ImageOps.grayscale(img))
    if kind=="contrast":return gray
    if kind=="binary":return gray.point(lambda x:255 if x>160 else 0)
    raise ValueError("UNEXPECTED_IMAGE_MODE")


def run_ocr(img: Image.Image, folder: Path, name: str, psm: int) -> str:
    fname=folder/(name+".png")
    img.save(fname)
    result=subprocess.run(["tesseract",str(fname),"stdout","-l","kor+eng",
                           "--psm",str(psm)],
                          capture_output=True,text=True,timeout=30,
                          check=False,env={**os.environ,"OMP_THREAD_LIMIT":"1"})
    if result.returncode!=0 or len(result.stdout)>20_000:
        raise RuntimeError("BLOCKED_TESSERACT_KOREAN_EXECUTION")
    return result.stdout


def main() -> None:
    if (os.getenv("JW_ENV")!="review"
            or os.getenv("JW_V186_OCR_ACK")!=ACK
            or os.getenv("JW_RELEASE_APPROVED","").lower() in ("yes","1","true")):
        raise RuntimeError("BLOCKED_OCR_PUBLIC_RESEARCH_NOT_APPROVED")
    trials=[]
    with httpx.Client(timeout=25,verify=True,trust_env=False,follow_redirects=False) as client:
        with TemporaryDirectory(prefix="jw-v186-public-ocr-") as d:
            root=Path(d)
            for name,blob_sha,biz,amount in SAMPLES:
                image=fetch_sample(client,name,blob_sha)
                for mode in ("raw","contrast","binary"):
                    for psm in (6,11):
                        text=run_ocr(view(image,mode),root,name.replace(".","_")+"_"+mode+"_"+str(psm),psm)
                        candidates=numeric_candidates(text)
                        trials.append({"name":name,"mode":mode,"psm":psm,
                             "business_number_recalled":biz in candidates,
                             "final_paid_amount_recalled":amount in candidates})
    if len(trials)!=12:raise AssertionError("MISSING_OCR_PILOT_TRIALS")
    counts={
       "business_number":sum(x["business_number_recalled"] for x in trials),
       "final_paid_amount":sum(x["final_paid_amount_recalled"] for x in trials),
    }
    print("MEASURED_V186_REAL_KOREAN_RECEIPT_PHOTOS=2",flush=True)
    print("MEASURED_V186_IMAGE_PREPROCESSING_OCR_TRIALS=12",flush=True)
    print("MEASURED_V186_NUMERIC_PRESENCE_RECALL="+json.dumps(counts,sort_keys=True),flush=True)
    print("LIMIT_V186_ONLY_2_MANUALLY_TRANSCRIBED_PUBLIC_RECEIPTS_NOT_50_REAL_BUSINESS_DOCS",flush=True)
    print("LIMIT_V186_NUMERIC_PRESENCE_NOT_FIELD_EXTRACTION_ACCURACY",flush=True)
    print("LIMIT_V186_NOT_PRODUCTION_OCR_ACCEPTANCE",flush=True)
    print("PASS_V186_PUBLIC_SAMPLE_INTEGRITY_12_REAL_OCR_TRIALS_EXECUTED_NO_CUSTOMER_DATA",flush=True)


if __name__=="__main__":
    main()
