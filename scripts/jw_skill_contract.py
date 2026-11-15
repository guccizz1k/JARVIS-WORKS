"""JARVIS-WORKS local Codex Skill safety and metadata gate.

Offline file contracts only: not a claim that skills ran, tests passed or
production is safe. Never executes any skill code or makes network requests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
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
# V22.3 already ships four separate third-party advisory skill trees.
# These are not J TEAM-internal skills and may NOT execute automatically.
# Their files are instead verified byte-for-byte against a fixed review SHA.
EXTERNAL_REVIEW_ONLY = frozenset({'security-audit', 'ponytail', 'change-impact', 'impeccable'})
EXTERNAL_PIN_SOURCE = '4a9af856b3aa29b848b5fa8f7cf0cc35899549c3'


def _audit_external_pins(root: Path, present: set[str]) -> list[str]:
    external = present & EXTERNAL_REVIEW_ONLY
    if not external:
        return []  # Older projects and minimal isolated test fixtures need no vendor bundle.
    if external != EXTERNAL_REVIEW_ONLY:
        return ['partial external advisory skill inventory']

    manifest_path = root / 'scripts' / 'jw_v223_external_skill_pins.json'
    if manifest_path.is_symlink() or not manifest_path.is_file():
        return ['missing/unsafe external advisory pin manifest']
    try:
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        if manifest.get('source_review_sha') != EXTERNAL_PIN_SOURCE:
            return ['external advisory baseline identity mismatch']
        expected = manifest.get('files')
        if not isinstance(expected, dict) or not expected:
            return ['invalid external advisory pin manifest']
    except (OSError, UnicodeError, ValueError, AttributeError):
        return ['unreadable external advisory pin manifest']

    observed: dict[str, Path] = {}
    for name in sorted(EXTERNAL_REVIEW_ONLY):
        folder = root / '.agents' / 'skills' / name
        if folder.is_symlink() or not folder.is_dir():
            return ['missing/unsafe external advisory directory: ' + name]
        for candidate in folder.rglob('*'):
            if candidate.is_symlink():
                return ['symlink in external advisory skill: ' + name]
            if not candidate.is_file():
                continue
            relative = candidate.relative_to(root).as_posix()
            observed[relative] = candidate
    if set(observed) != set(expected):
        return ['external advisory file inventory changed']
    problems: list[str] = []
    for relative, filename in sorted(observed.items()):
        pin = expected.get(relative)
        if not isinstance(pin, str) or not re.fullmatch(r'[0-9a-f]{40}', pin):
            problems.append('invalid external advisory pin: ' + relative)
            continue
        try:
            size = filename.stat().st_size
            if size > 262144:
                problems.append('oversized external advisory file: ' + relative)
                continue
            data = filename.read_bytes()
            git_oid = hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()
        except OSError:
            problems.append('unreadable external advisory file: ' + relative)
            continue
        if git_oid != pin:
            problems.append('external advisory blob modified: ' + relative)
    return problems
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
    problems.extend(_audit_external_pins(root, present))
    for unknown in sorted(present - APPROVED - EXTERNAL_REVIEW_ONLY):
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
