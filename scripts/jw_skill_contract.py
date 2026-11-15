"""JARVIS-WORKS local Codex Skill safety and metadata gate.

Offline file contracts only: not a claim that skills ran, tests passed or
production is safe. Never executes any skill code or makes network requests.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

OLD = frozenset({'jw-verified-delivery', 'jw-evidence-retro'})
NEW = frozenset({'jw-tenant-security-review', 'jw-trade-document-integrity',
                 'jw-messenger-ocr-recovery', 'jw-render-capacity-cost',
                 'jw-ui-ux-accessibility', 'jw-root-cause-debugging',
                 'jw-solution-innovation', 'jw-external-intelligence',
                 'jw-api-property-testing',
                 'jt-design-system-bridge', 'jt-audio-research',
                 'jt-local-model-evaluation', 'jt-workflow-adapter'})
APPROVED = OLD | NEW
META = re.compile(r'\A---\nname: ([a-z][a-z0-9-]*)\ndescription: ([^\n]{35,500})\n---\n\n')
DANGEROUS = (
    re.compile(r'\b(?:curl|wget)\b[^\n]{0,150}\|\s*(?:bash|sh)\b', re.I),
    re.compile(r'\bgit\s+push\s+(?:origin\s+)?main\b', re.I),
    re.compile(r'\b(?:npm\s+install\s+-g|pip\s+install\s+https?://)', re.I),
)


def audit(root: Path) -> list[str]:
    root = Path(root)
    problems: list[str] = []
    guide = root / 'AGENTS.md'
    policy = root / 'docs/agents/J6_EVIDENCE_GATED_ENGINEERING.md'
    folder = root / '.agents/skills'
    for file in (guide, policy):
        if not file.is_file() or file.is_symlink():
            problems.append('missing/unsafe governance file: ' + file.name)
    if not folder.is_dir() or folder.is_symlink():
        return sorted(set(problems + ['missing/unsafe .agents/skills folder']))
    try:
        present = {p.name for p in folder.iterdir()}
    except OSError:
        return sorted(set(problems + ['unreadable skill registry']))
    for unknown in sorted(present - APPROVED):
        problems.append('unreviewed skill: ' + unknown)
    for missing in sorted(APPROVED - present):
        problems.append('missing approved skill: ' + missing)
    for name in sorted(present & APPROVED):
        skill_dir = folder / name
        file = skill_dir / 'SKILL.md'
        if (skill_dir.is_symlink() or not skill_dir.is_dir()
                or file.is_symlink() or not file.is_file()):
            problems.append('unsafe skill path: ' + name)
            continue
        try:
            members = {p.name for p in skill_dir.iterdir()}
            raw = file.read_bytes()
            if b'\x00' in raw or len(raw) > 16384:
                problems.append('binary/oversized skill: ' + name)
                continue
            content = raw.decode('utf-8')
        except (OSError, UnicodeError):
            problems.append('unreadable skill: ' + name)
            continue
        if members != {'SKILL.md'}:
            problems.append('extra unreviewed skill files: ' + name)
        front = META.match(content)
        if not front or front.group(1) != name:
            problems.append('invalid SKILL.md metadata: ' + name)
            continue
        if name in NEW:
            for word in ('J1–J6', 'BLOCKED', 'PASS', 'review', 'main'):
                if word not in content:
                    problems.append('missing safety policy '+word+': '+name)
        for pattern in DANGEROUS:
            if pattern.search(content):
                problems.append('unsafe execution instruction: ' + name)
    if guide.is_file() and not guide.is_symlink():
        try:
            instructions = guide.read_text('utf-8')
            for name in APPROVED:
                if name not in instructions:
                    problems.append('AGENTS.md does not route: ' + name)
            for required in ('J1–J6', 'GLOSSARY.md', 'J6', 'BLOCKED', 'main', 'jw_evidence_gate.py'):
                if required not in instructions:
                    problems.append('existing harness guard missing: ' + required)
        except (OSError, UnicodeError):
            problems.append('unreadable AGENTS.md')
    return sorted(set(problems))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    errors = audit(parser.parse_args().root)
    for problem in errors:
        print('FAIL: ' + problem)
    if errors:
        return 3
    print('PASS: local skill metadata/routing/safety only; runtime not tested, release BLOCKED')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
