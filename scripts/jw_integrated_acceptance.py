"""J1–J6 integrated product regression acceptance and fail-closed CI receipts.

This gate validates *actual JUnit XML* and a receipt manifest inside an isolated
GitHub Actions run. It does not unlock production or authenticate remote claims.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from xml.etree import ElementTree as ET

SHA = re.compile(r"^[a-f0-9]{40}$")
REQUIRED_DOMAINS = frozenset(("j1-j6-legacy-product","j1-j6-new-contract","j1-j6-pg-browser-restore","j1-j6-web-form","j1-j6-security"))
# The original pre-J6 suite had 589 cases; 43 J6 cases were added. The
# all-tests runner must not silently omit a whole original module.
LEGACY_MIN = 589
J6_MIN = 43


def audit_junit(path: Path) -> dict:
    root=ET.parse(path).getroot()
    cases=list(root.iter("testcase"))
    if not cases:
        raise AssertionError("JUnit contains no testcases")
    n=len(cases)
    if any(t.find("failure") is not None or t.find("error") is not None or t.find("skipped") is not None for t in cases):
        raise AssertionError("One or more JUnit testcases failed, errored, or skipped")
    names=[f"{t.attrib.get('classname','')}.{t.attrib.get('name','')}" for t in cases]
    j6=sum("test_jw_evidence_gate" in n or "test_j6_postgres_restore" in n for n in names)
    other=len(names)-j6
    if j6<J6_MIN or other<LEGACY_MIN:
        raise AssertionError(f"Suite coverage dropped: legacy+other={other} (min {LEGACY_MIN}), J6={j6} (min {J6_MIN})")
    for fragment in ("test_pg_auth_v85", "test_pg_v90_integrated_entry", "test_release_gate_v75", "test_jw_evidence_gate", "test_j6_postgres_restore"):
        if not any(fragment in name for name in names):
            raise AssertionError("Mandatory module absent: "+fragment)
    return {"passed":len(cases),"failed":0,"skipped":0,"legacy_plus_new_count":other,"j6_count":j6,
            "junit":str(path)}


def validate_receipts(data: object, head: str) -> list[str]:
    errors=[]
    if not isinstance(data,dict):
        return ["receipt manifest must be object"]
    if not SHA.fullmatch(head):
        return ["Invalid exact SHA"]
    if data.get("commit")!=head:
        errors.append("Receipt does not match exact CI HEAD")
    rec=data.get("checks")
    if not isinstance(rec,list):
        return errors+["checks must be list"]
    observed={}
    for item in rec:
        if not isinstance(item,dict):
            errors.append("Malformed check")
            continue
        name=item.get("id")
        if name in observed:
            errors.append("Duplicate check "+str(name))
        observed[name]=item
        if name not in REQUIRED_DOMAINS:
            errors.append("Unknown check "+str(name))
        if item.get("status")!="PASS" or item.get("synthetic") is not True:
            errors.append("Claim must have PASS/synthetic marker "+str(name))
        if not isinstance(item.get("proof"),str) or not item["proof"].strip():
            errors.append("Missing evidence "+str(name))
    if set(observed)!=set(REQUIRED_DOMAINS):
        errors.append("Required J1–J6 integrated checks missing")
    if data.get("release")!="BLOCKED" or data.get("production_deployed") is not False:
        errors.append("Review harness cannot authorize production")
    return errors


def main()->int:
    p=argparse.ArgumentParser()
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument("--junit",type=Path)
    g.add_argument("--receipts",type=Path)
    args=p.parse_args()
    try:
        if args.junit:
            print(json.dumps(audit_junit(args.junit),ensure_ascii=False))
        else:
            head=os.environ.get("GITHUB_SHA","")
            errors=validate_receipts(json.loads(args.receipts.read_text(encoding="utf-8")),head)
            if errors:
                raise AssertionError("; ".join(errors))
            print("PASS: J1–J6 CI receipts tied to exact SHA, five domains present, release BLOCKED")
        return 0
    except (ValueError,OSError,ET.ParseError,AssertionError) as exc:
        print("FAIL: "+str(exc),file=sys.stderr)
        return 1


if __name__=="__main__":
    raise SystemExit(main())
