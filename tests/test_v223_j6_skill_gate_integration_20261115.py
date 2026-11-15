"""Regression: V22.3 integration must not silently drop main's J6 skill-policy gate.

Pure Python/monkeypatch: no DB, file mutation, network, or real credentials.
"""
from pathlib import Path

from scripts import jw_evidence_gate
import scripts.jw_skill_contract as skills


def test_project_gate_invokes_registered_skill_audit(monkeypatch):
    root = Path(__file__).resolve().parents[1]
    marker = "BLOCKED: synthetic unreviewed skill"
    called = []

    def reject_unreviewed(actual_root):
        called.append(actual_root)
        return [marker]

    monkeypatch.setattr(skills, "audit", reject_unreviewed)
    assert marker in jw_evidence_gate.verify_project(root), (
        "V22.3 integrated project verification bypasses the J6 skill safety audit "
        "that exists in main"
    )
    assert called == [root]


def test_current_skill_registry_is_auditable_without_network():
    root = Path(__file__).resolve().parents[1]
    assert skills.audit(root) == [], "J6 registry and external advisory pins are not aligned"
