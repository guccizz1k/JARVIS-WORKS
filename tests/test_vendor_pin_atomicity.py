"""Offline negative tests for coordinated vendor pin tampering (synthetic fixtures only)."""
from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import jw_skill_contract as mod


def oid(data: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()


class TestVendorPinAtomicity(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.vendor = self.root / '.agents' / 'skills'
        self.entries = {}
        for name in sorted(mod.EXTERNAL_REVIEW_ONLY):
            file = self.vendor / name / 'SKILL.md'
            file.parent.mkdir(parents=True)
            file.write_text('---\nname: ' + name + '\n---\nSynthetic only\n', encoding='utf8')
            self.entries[file.relative_to(self.root).as_posix()] = oid(file.read_bytes())
        self.manifest = self.root / 'scripts' / 'jw_v223_external_skill_pins.json'
        self.manifest.parent.mkdir(parents=True)
        self.write_manifest(self.entries)
        self.approved_oid = oid(self.manifest.read_bytes())

    def write_manifest(self, entries):
        self.manifest.write_text(json.dumps(
            {'source_review_sha': mod.EXTERNAL_PIN_SOURCE, 'files': entries},
            sort_keys=True), encoding='utf8')

    def check(self):
        with patch.object(mod, 'EXTERNAL_PIN_MANIFEST_BLOB_OID', self.approved_oid):
            return mod._audit_external_pins(self.root, set(mod.EXTERNAL_REVIEW_ONLY))

    def remove_all_vendor(self):
        for name in mod.EXTERNAL_REVIEW_ONLY:
            shutil.rmtree(self.vendor / name)

    def test_valid_synthetic_manifest(self):
        self.assertEqual(self.check(), [])

    def test_vendor_byte_change_rejected(self):
        file = self.vendor / 'ponytail' / 'SKILL.md'
        file.write_bytes(file.read_bytes() + b'wrong')
        self.assertTrue(any('blob modified' in e for e in self.check()))

    def test_vendor_and_manifest_changed_together_rejected(self):
        file = self.vendor / 'ponytail' / 'SKILL.md'
        file.write_bytes(file.read_bytes() + b'wrong')
        values = dict(self.entries)
        values[file.relative_to(self.root).as_posix()] = oid(file.read_bytes())
        self.write_manifest(values)
        self.assertTrue(any('manifest modified' in e for e in self.check()))

    def test_all_vendor_removed_manifest_remains_rejected(self):
        self.remove_all_vendor()
        self.assertTrue(any('inventory missing' in e
                            for e in mod._audit_external_pins(self.root, set())))

    def test_adopted_policy_survives_total_vendor_manifest_deletion(self):
        path = self.root / 'docs' / 'agents' / 'JW_V208_FOUR_SKILLS.md'
        path.parent.mkdir(parents=True)
        path.write_text('reviewed policy', encoding='utf8')
        self.remove_all_vendor()
        self.manifest.unlink()
        self.assertTrue(any('inventory missing' in e
                            for e in mod._audit_external_pins(self.root, set())))

    def test_agents_policy_alone_blocks_total_deletion(self):
        guide = self.root / 'AGENTS.md'
        guide.write_text('## V20.8 external skills, advisory only', encoding='utf8')
        self.remove_all_vendor()
        self.manifest.unlink()
        self.assertTrue(any('inventory missing' in e
                            for e in mod._audit_external_pins(self.root, set())))

    def test_external_policy_manifest_alone_blocks_total_deletion(self):
        path = self.root / 'docs' / 'agents' / 'JW_V208_FOUR_SKILLS_MANIFEST.json'
        path.parent.mkdir(parents=True)
        path.write_text('{}', encoding='utf8')
        self.remove_all_vendor()
        self.manifest.unlink()
        self.assertTrue(any('inventory missing' in e
                            for e in mod._audit_external_pins(self.root, set())))

    def test_minimal_legacy_without_adoption_still_valid(self):
        self.remove_all_vendor()
        self.manifest.unlink()
        self.assertEqual(mod._audit_external_pins(self.root, set()), [])

    def test_symlink_vendor_rejected(self):
        file = self.vendor / 'ponytail' / 'SKILL.md'
        file.unlink()
        file.symlink_to(self.vendor / 'impeccable' / 'SKILL.md')
        self.assertTrue(any('symlink' in e for e in self.check()))

    def test_bad_manifest_rejected(self):
        self.manifest.write_text('{', encoding='utf8')
        self.assertTrue(any('manifest modified' in e for e in self.check()))


if __name__ == '__main__':
    unittest.main()
