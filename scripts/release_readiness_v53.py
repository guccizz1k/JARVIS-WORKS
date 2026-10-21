"""Non-authorizing eight-stage B2B release evidence audit.

This is an OFFLINE, read-only status report, never a production go signal.
User-supplied checklists cannot authorize deployment; only separately approved
operational review can do so. BLOCKED/NOT RUN remain explicit per gate.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sys

GATES = (
    ("01_evidence_relay", "Lossless messages, attachments, edits, receipt and read-position event replay"),
    ("02_backfill_restore", "Historical full backfill and audited restore"),
    ("03_web_postgresql", "Operational FastAPI write and read path with DB-backed tenant isolation"),
    ("04_company_onboarding", "Verified business identity and full employee invitation/revocation"),
    ("05_attachment_storage", "Encrypted object storage, malicious-file scanning and access policy"),
    ("06_product_ux", "Actual browser and cross-company end-to-end workflow checks"),
    ("07_security_operations", "Independent security review, load, backup restore and alerting"),
    ("08_beta_release", "Approved private beta, privacy/legal and production release"),
)
ALLOWED = frozenset({"PASS", "PARTIAL", "FAIL", "BLOCKED", "NOT RUN", "NOT MEASURED"})

class EvidenceError(ValueError):
    pass


def evaluate(data: dict) -> dict:
    if not isinstance(data, dict) or data.get("schema") != "jw-release-evidence-v1":
        raise EvidenceError("Invalid review evidence schema")
    got = data.get("gates")
    if not isinstance(got, dict) or set(got) != {x[0] for x in GATES}:
        raise EvidenceError("Missing or unexpected mandatory stage")
    out=[]
    for name, description in GATES:
        item=got[name]
        if not isinstance(item,dict):
            raise EvidenceError("Malformed stage")
        status=item.get("status")
        if status not in ALLOWED:
            raise EvidenceError("Invalid or fabricated stage status")
        evidence=item.get("evidence")
        if not isinstance(evidence,list) or not all(isinstance(x,str) and 0<len(x)<=300 for x in evidence):
            raise EvidenceError("Evidence references must be explicit")
        # Fail closed: a gate cannot pass on a claim without at least one test proof.
        if status=="PASS" and (not evidence or not any("PASS:" in e for e in evidence)):
            raise EvidenceError("PASS without verifiable evidence is refused")
        out.append({"id":name,"description":description,"status":status,"evidence":evidence})
    # Deliberately never authorize production based on a JSON checklist.
    return {"schema":"jw-release-report-v1", "gates":out,
            "full_completion_measured":False,
            "production_cutover_authorized":False,
            "release_authorized":False,
            "overall":"BLOCKED" if any(x["status"] in {"BLOCKED","FAIL","NOT RUN","NOT MEASURED"} for x in out) else "PARTIAL",
            "note":"Offline release evidence is not deployment or customer validation."}


def main(argv=None):
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("--evidence",default=str(Path(__file__).parents[1]/"docs"/"RELEASE_EVIDENCE_V53.json"))
    args=p.parse_args(argv)
    try:
        report=evaluate(json.loads(Path(args.evidence).read_text(encoding='utf-8')))
    except (OSError,ValueError,TypeError) as exc:
        print(f"FAIL: invalid release evidence ({type(exc).__name__})",file=sys.stderr)
        return 1
    print(json.dumps(report,ensure_ascii=False,indent=2))
    # A readiness check with outstanding mandatory gates must not exit success.
    return 2 if report['overall']!='PASS' else 0

if __name__=='__main__':
    raise SystemExit(main())
