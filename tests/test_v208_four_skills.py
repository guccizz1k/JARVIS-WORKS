"""Independent adversarial source-integrity tests for four third-party skills."""
import copy
import json
from pathlib import Path
import unittest
from scripts.ci_v208_four_skills import BASE, blob, safe_path, check_sources

class Cases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root=Path(".").resolve()
        cls.data=json.loads((cls.root/"docs/agents/JW_V208_FOUR_SKILLS_MANIFEST.json").read_text())

    def test_verified_originals(self): self.assertEqual(check_sources(self.root,self.data),38)
    def test_baseline(self): self.assertEqual(self.data["baseline_sha"],BASE)
    def test_review_only(self): self.assertTrue(self.data["review_only"])
    def test_release_blocked(self): self.assertEqual(self.data["operational_release"],"BLOCKED")
    def test_no_auto_run(self): self.assertIs(self.data["auto_run_external_tools"],False)
    def test_blob_empty(self): self.assertEqual(blob(b""),"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")
    def test_four_licenses(self): self.assertEqual(sum("/licenses/" in k for k in self.data["third_party_files"]),4)
    def test_cloudflare_test_tools(self):
        self.assertTrue((self.root/".agents/skills/security-audit/validate-findings.test.cjs").is_file())
        self.assertTrue((self.root/".agents/skills/security-audit/validate-coverage-ledger.test.cjs").is_file())
    def test_no_impeccable_external_engine(self):
        self.assertFalse((self.root/".agents/skills/impeccable/scripts/impeccable").exists())
    def test_tampered_sha_detected(self):
        f=copy.deepcopy(self.data)
        name=".agents/skills/ponytail/SKILL.md"
        f["third_party_files"][name]["git_blob"]="0"*40
        with self.assertRaises(AssertionError):check_sources(self.root,f)
    def test_missing_license_detected(self):
        f=copy.deepcopy(self.data)
        name=next(k for k in f["third_party_files"] if "/licenses/" in k)
        del f["third_party_files"][name]
        with self.assertRaises(AssertionError):check_sources(self.root,f)
    def test_unsafe_activation_detected(self):
        f=copy.deepcopy(self.data)
        f["auto_run_external_tools"]=True
        with self.assertRaises(AssertionError):check_sources(self.root,f)
    def test_path_injection_detected(self):
        f=copy.deepcopy(self.data)
        name=next(iter(f["third_party_files"]))
        f["third_party_files"]["../secrets"]=f["third_party_files"].pop(name)
        with self.assertRaises(AssertionError):check_sources(self.root,f)

def case(name, valid):
    def go(self):self.assertIs(safe_path(name),valid,msg=name)
    return go

# Individually enumerated, negative, independent and fail-closed testcases
bad=("../secret","/etc/passwd","a/../b","./app","foo//bar","foo/./bar",
     "a/../../.env","/","../","a/..",".","","src/../../../secrets",
     "docs/../../.env","x/../../x","a/../.git","../AGENTS.md",
     "a/b/..","a/../vendor","a//x","x/./x","/root/.ssh/id_rsa")
good=(".agents/skills/ponytail/SKILL.md",".agents/skills/change-impact/SKILL.md",
      ".agents/skills/security-audit/AI-AND-LLM.md",
      ".agents/skills/impeccable/reference/audit.md",
      "docs/third_party/licenses/cloudflare--security-audit-skill.LICENSE")
for i,name in enumerate(bad):setattr(Cases,f"test_invalid_path_{i:02d}",case(name,False))
for i,name in enumerate(good):setattr(Cases,f"test_valid_path_{i:02d}",case(name,True))
if __name__=="__main__":unittest.main()
