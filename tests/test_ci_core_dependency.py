import copy
import json
import tempfile
import unittest
from pathlib import Path
from scripts.ci_core_dependency import verify, CORE_SHA, ROOT

class CoreDependencyTests(unittest.TestCase):
    def test_current_contract_pins_core_and_stays_readonly(self):
        result=verify()
        self.assertEqual(result["core_sha"],CORE_SHA)
        self.assertEqual(result["cross_repo_runtime"],"NOT_ATTESTED")
        self.assertEqual(result["release"],"BLOCKED")
    def test_business_code_is_not_replaced(self):
        for name in ("app/main.py","app/messenger.py","security/postgres_rls_proposal.sql"):
            self.assertTrue((ROOT/name).is_file())
    def fixture(self,edit):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/"config").mkdir();(root/".github/workflows").mkdir(parents=True)
            for name in ("config/core_dependency.json",".github/workflows/jw-core-first-required.yml","app/main.py","app/messenger.py","security/postgres_rls_proposal.sql"):
                dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True)
                dest.write_bytes((ROOT/name).read_bytes())
            edit(root)
            with self.assertRaises(ValueError):
                verify(root)
    def test_missing_attestation_fails(self):
        self.fixture(lambda root:(root/"config/core_dependency.json").unlink())
    def test_contract_cannot_disable_core(self):
        def edit(root):
            file=root/"config/core_dependency.json";data=json.loads(file.read_text());data["required"]=False;file.write_text(json.dumps(data))
        self.fixture(edit)
    def test_core_sha_tamper_fails(self):
        def edit(root):
            file=root/"config/core_dependency.json";data=json.loads(file.read_text());data["core_sha"]="0"*40;file.write_text(json.dumps(data))
        self.fixture(edit)
    def test_cross_repo_workflow_cannot_be_removed(self):
        self.fixture(lambda root:(root/".github/workflows/jw-core-first-required.yml").unlink())
    def test_order_cannot_be_reversed(self):
        def edit(root):
            file=root/".github/workflows/jw-core-first-required.yml";file.write_text(file.read_text().replace("needs: core-first","needs: []"))
        self.fixture(edit)
    def test_policy_symlink_denied(self):
        def edit(root):
            path=root/"config/core_dependency.json";data=path.read_bytes();path.unlink();p=root/"data.json";p.write_bytes(data);path.symlink_to(p)
        self.fixture(edit)
    def test_project_full_gate_depends_on_core(self):
        caller=(ROOT/".github/workflows/jw-core-first-required.yml").read_text(encoding="utf8")
        suite=(ROOT/".github/workflows/jw-j1-j6-unified-acceptance.yml").read_text(encoding="utf8")
        self.assertIn("needs: core-first", caller)
        self.assertIn("uses: ./.github/workflows/jw-j1-j6-unified-acceptance.yml", caller)
        self.assertIn("  workflow_call:", suite)
        self.assertIn("j1-j6-independent-aggregate:", suite)

if __name__=="__main__":
    unittest.main()
