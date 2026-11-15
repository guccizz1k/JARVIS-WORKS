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


def _isolated_skill_tree(tmp_path):
    """Copy read-only sample metadata to a disposable scratch directory."""
    import shutil
    repo = Path(__file__).resolve().parents[1]
    for file in ("AGENTS.md", "docs/agents/J6_EVIDENCE_GATED_ENGINEERING.md",
                 "scripts/jw_v223_external_skill_pins.json"):
        target = tmp_path / file
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repo / file, target)
    names = skills.APPROVED | skills.EXTERNAL_REVIEW_ONLY
    for name in names:
        shutil.copytree(repo / ".agents/skills" / name,
                        tmp_path / ".agents/skills" / name)
    return tmp_path


def test_external_advisory_byte_tamper_is_detected(tmp_path):
    root = _isolated_skill_tree(tmp_path)
    file = root / ".agents/skills/ponytail/SKILL.md"
    file.write_bytes(file.read_bytes() + b"\\n# synthetic tamper\\n")
    assert any("external advisory blob modified" in issue for issue in skills.audit(root))


def test_external_advisory_unreviewed_file_is_detected(tmp_path):
    root = _isolated_skill_tree(tmp_path)
    (root / ".agents/skills/change-impact/unreviewed-install.sh").write_text("echo unreviewed")
    assert "external advisory file inventory changed" in skills.audit(root)


def test_external_advisory_symlink_is_detected(tmp_path):
    root = _isolated_skill_tree(tmp_path)
    f = root / ".agents/skills/ponytail/SKILL.md"
    f.unlink()
    f.symlink_to(root / "AGENTS.md")
    assert any("symlink in external advisory skill" in issue for issue in skills.audit(root))
