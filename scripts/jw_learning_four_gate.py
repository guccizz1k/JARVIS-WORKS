"""Fail-closed acceptance audit for four requested learning capabilities.

Reports evidence availability, not AI execution. Never mutates app or production.
"""
import argparse
import json
from pathlib import Path

GATES = ("v9_checkpoint_integration", "actual_ai_code_repair", "independent_repair_evaluation", "external_skill_ab")

def assess(evidence):
    if not isinstance(evidence, dict):
        raise ValueError("Evidence must be object")
    result = {}
    for gate in GATES:
        entry = evidence.get(gate)
        if not isinstance(entry, dict):
            result[gate] = {"status": "BLOCKED", "reason": "Missing evidence"}
            continue
        required = {
            "v9_checkpoint_integration": ("source_commit", "integration_test", "checkpoint_restore_proof"),
            "actual_ai_code_repair": ("source_commit", "model_execution_receipt", "patch_sha", "isolated_test"),
            "independent_repair_evaluation": ("baseline_sha", "candidate_sha", "independent_evaluator", "regression_report"),
            "external_skill_ab": ("baseline_sha", "candidate_sha", "same_cases", "skill_provenance", "independent_results"),
        }[gate]
        missing = [field for field in required if not isinstance(entry.get(field), str) or not entry[field].strip()]
        # User supplied strings are NOT independent attestation; never auto-pass.
        result[gate] = {"status": "REVIEW_REQUIRED" if not missing else "BLOCKED",
                        "missing": missing, "independently_authenticated": False}
    return {"schema": "jw-learning-four-gate-v1", "gates": result,
            "all_pass": False, "production_allowed": False, "main_merge_allowed": False}

def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--evidence", type=Path, required=True)
    args = p.parse_args(argv)
    report = assess(json.loads(args.evidence.read_text(encoding="utf-8")))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
