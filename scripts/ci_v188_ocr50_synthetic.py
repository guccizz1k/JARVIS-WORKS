"""V18.8 50 real Tesseract executions on labeled *synthetic* Korean quotes.

The number 50 is ONLY a synthetic robustness sample count, not the required
>=50 consented representative real customer documents for production OCR.
Never silently convert missing/contradictory fields into guessed values.
Does not alter production parser, upload engine or customer data.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from PIL import ImageFont

from scripts.ci_v178_real_ocr_synthetic import _font, _render, parse_fields
from scripts.ocr_quality_gate_v77 import evaluate

N=50
FIELDS=("counterparty","business_number","total_amount")


def run() -> None:
    if (os.getenv("JW_ENV")!="review"
        or os.getenv("JW_V188_OCR_ACK")!="SYNTHETIC_LOCAL_KOREAN_FORMS_ONLY"):
        raise RuntimeError("BLOCKED_V188_OCR_DATA_SCOPE")
    font=ImageFont.truetype(str(_font()),34)
    rows=[]
    with TemporaryDirectory(prefix="jw-v188-ocr50-") as tmp:
        directory=Path(tmp)
        for i in range(N):
            image=directory/(f"synthetic_quote_{i:02}.png")
            truth=_render(image,font,i)
            p=subprocess.run(["tesseract",str(image),"stdout",
                "-l","kor+eng","--psm","6"],
                capture_output=True,text=True,check=False,timeout=20,
                env={**os.environ,"OMP_THREAD_LIMIT":"1"})
            if p.returncode!=0 or len(p.stdout)>20_000:
                raise RuntimeError("FAIL_V188_TESSERACT_OR_OVERSIZED_OUTPUT")
            observed=parse_fields(p.stdout)
            rows.append({"expected":truth,"predicted":observed})
    scored=evaluate(rows,dataset="synthetic")
    if (scored["documents"]!=N or set(scored["fields"])!=set(FIELDS)
        or any(d["samples"]!=N for d in scored["fields"].values())
        or scored["production_quality_approved"] is not False):
        raise AssertionError("FAIL_V188_SYNTHETIC_MEASUREMENT_INTEGRITY")
    matches={field:sum(r["predicted"].get(field)==r["expected"][field] for r in rows)
             for field in FIELDS}
    incorrect={field:sum(field in r["predicted"] and
                         r["predicted"][field]!=r["expected"][field] for r in rows)
               for field in FIELDS}
    unknown={field:N-matches[field]-incorrect[field] for field in FIELDS}
    if any(matches[f]+incorrect[f]+unknown[f]!=N for f in FIELDS):
        raise AssertionError("FAIL_V188_SYNTHETIC_COUNTS")
    print("PASS_V188_50_REAL_TESSERACT_RUNS_ON_GENERATED_DOCUMENTS",flush=True)
    print("MEASURED_V188_50_SYNTHETIC_EXACT_MATCHES="+json.dumps(matches,sort_keys=True),flush=True)
    print("MEASURED_V188_50_SYNTHETIC_WRONG_NONEMPTY="+json.dumps(incorrect,sort_keys=True),flush=True)
    print("MEASURED_V188_50_SYNTHETIC_ABSTAIN="+json.dumps(unknown,sort_keys=True),flush=True)
    print("LIMIT_V188_ZERO_REAL_CONSENTED_BUSINESS_DOCS_AND_NO_PRODUCTION_ACCEPTANCE",flush=True)


if __name__=="__main__":
    run()
