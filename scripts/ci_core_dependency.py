"""Strict WORKS-to-CORE reusable workflow SHA/contract attestation; no side effects."""
from __future__ import annotations
import json
import re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CONTRACT=ROOT/"config/core_dependency.json"
WORKFLOW=ROOT/".github/workflows/jw-core-first-required.yml"
CORE_SHA="49317324331759d3d9e49338dc591d67af1517f3"

def verify(root=ROOT):
    root=Path(root)
    contract=root/"config/core_dependency.json"
    workflow=root/".github/workflows/jw-core-first-required.yml"
    if any(x.is_symlink() or not x.is_file() or x.stat().st_size>16384 for x in (contract,workflow)):
        raise ValueError("CORE_BOUNDARY_MISSING")
    data=json.loads(contract.read_text(encoding="utf8"))
    expected={"schema":"jw-core-first-dependency-v1","project":"jarvis-works",
             "core_repo":"guccizz1k/JARVIS-CORE","core_sha":CORE_SHA,
             "required":True,"fail_closed":True,"no_customer_data_transfer":True,
             "no_paid_model_runtime":True,"operation":"REVIEW_CI_ONLY"}
    if type(data) is not dict or data!=expected:
        raise ValueError("CORE_CONTRACT_CHANGED")
    code=workflow.read_text(encoding="utf8")
    expected_ref="guccizz1k/JARVIS-CORE/.github/workflows/core-works-preflight.yml@"+CORE_SHA
    if code.count(expected_ref)!=1:
        raise ValueError("CORE_WORKFLOW_NOT_PINNED")
    if not re.search(r"(?m)^  business-review:\n    needs: core-first\n",code):
        raise ValueError("CORE_PRECEDENCE_NOT_ENFORCED")
    if not all((root/path).is_file() for path in ("app/main.py","app/messenger.py","security/postgres_rls_proposal.sql")):
        raise ValueError("BUSINESS_SOURCE_NOT_PRESERVED")
    return {"status":"CORE_DEPENDENCY_DECLARATION_PASS","core_sha":CORE_SHA,
            "cross_repo_runtime":"NOT_ATTESTED","model_dispatch":"NOT_RUN",
            "full_product_regression":"SEPARATE_REQUIRED","release":"BLOCKED"}

if __name__=="__main__":
    print(json.dumps(verify(),sort_keys=True))
