"""Evidence-driven V7.8 pre-release decision; never authorizes deployment.

Local tests do not turn real PostgreSQL, customer OCR, iOS or security audits
into PASS. Inputs are only release evidence identifiers, not boolean shortcuts.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
from scripts.release_gate_v75 import evaluate as old_gate


def evaluate():
    base=old_gate()
    base.update({
        'review_scope':'V7.8 local engineering review',
        'decision':'BLOCKED',
        'schema_policies':'35-table SELECT-only lab draft generated; NOT executed',
        'runtime_guard':'Production startup forbidden while SQLite adapter remains',
        'postgres_live_attack_test':'NOT_RUN',
        'postgres_full_business_adapter':'NOT_IMPLEMENTED',
        'representative_consent_customer_ocr':'NOT_RUN',
        'physical_iphone_safari':'NOT_RUN',
        'external_security_audit':'NOT_RUN',
        'production_rehearsal':'NOT_RUN',
        'ui_visual_redesign':'DEFERRED_until_functional_freeze',
        'remote_git_push':'NOT_PERFORMED',
    })
    return base


if __name__=='__main__':
    print(json.dumps(evaluate(),ensure_ascii=False,indent=2))
    raise SystemExit(2)
