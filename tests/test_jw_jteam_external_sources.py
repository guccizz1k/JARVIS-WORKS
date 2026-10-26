"""J1-J6 external intelligence integration and negative safety cases."""
import io
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from scripts.jw_jteam_external_sources import (
    ROLES, PHASES, fabric_instructions, load_contract, local_public_digest,
)
from scripts import jw_jteam_openai_runner as runner


class JTeamExternalSourcesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="jteam-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "README.md").write_text("# Safe synthetic source\n", encoding="utf-8")
        (self.root / "sample.py").write_text("value = 42\n", encoding="utf-8")

    def stub_ingest(self, path):
        files = sorted(p for p in Path(path).rglob("*") if p.is_file())
        return ("summary", "\n".join(p.name for p in files),
                "\n".join(p.read_text(encoding="utf-8") for p in files))

    def test_exact_six_j_phases_and_five_roles(self):
        contract = load_contract()
        self.assertEqual(set(contract["phases"]), set(PHASES))
        self.assertEqual(set(contract["role_phases"]), set(ROLES))
        self.assertEqual(len(contract["tools"]), 2)

    def test_all_roles_have_real_project_owned_patterns(self):
        for role in ROLES:
            prompt = fabric_instructions(role)
            self.assertIn("J1-J6", prompt)
            for phase in load_contract()["role_phases"][role]:
                self.assertIn("[" + phase + ":", prompt)
            self.assertIn("# HARD GATES", prompt)

    def test_unknown_role_blocked(self):
        with self.assertRaisesRegex(ValueError, "UNKNOWN_ROLE"):
            fabric_instructions("random-agent")

    def test_rejects_external_network_permission_change(self):
        changed = deepcopy(load_contract())
        changed["tools"][1]["remote_ingest"] = "ALLOWED"
        temp = self.root / "mutated.json"
        temp.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "UNSAFE_UPSTREAM_CONTRACT"):
            load_contract(temp)

    def test_local_pilot_sanitizes_and_measures_without_upload(self):
        observed = {}
        def ingest(path):
            observed["path"] = path
            self.assertNotEqual(Path(path).resolve(), self.root.resolve())
            return self.stub_ingest(path)
        out = local_public_digest(self.root, ingest_fn=ingest)
        self.assertEqual(out["file_count"], 2)
        self.assertEqual(out["status"], "LOCAL_PUBLIC_PILOT_MEASURED")
        self.assertIs(out["remote_upload"], False)
        self.assertEqual(out["api_calls"], 0)
        self.assertEqual(out["release"], "BLOCKED")
        self.assertGreaterEqual(out["candidate_elapsed_ns"], 0)

    def test_secret_content_prevents_any_ingest_call(self):
        (self.root / "config.txt").write_text("password = do-not-export\n", encoding="utf-8")
        calls = []
        with self.assertRaisesRegex(PermissionError, "POTENTIAL_SECRET"):
            local_public_digest(self.root, ingest_fn=lambda p: calls.append(p))
        self.assertEqual(calls, [])

    def test_dotfiles_are_not_included(self):
        (self.root / ".env").write_text("SECRET=private", encoding="utf-8")
        output = local_public_digest(self.root, ingest_fn=self.stub_ingest)
        self.assertEqual(output["file_count"], 2)

    def test_symlink_rejected(self):
        (self.root / "link.py").symlink_to(self.root / "sample.py")
        with self.assertRaisesRegex(PermissionError, "SYMLINK"):
            local_public_digest(self.root, ingest_fn=self.stub_ingest)

    def test_non_temp_source_rejected(self):
        with self.assertRaisesRegex(PermissionError, "ONLY_DISPOSABLE_TEMP_FIXTURES"):
            local_public_digest(Path(__file__).resolve().parents[1], ingest_fn=self.stub_ingest)

    def test_no_secret_or_full_text_in_result(self):
        result = local_public_digest(self.root, ingest_fn=self.stub_ingest)
        self.assertNotIn("value = 42", str(result))
        self.assertNotIn("Safe synthetic source", str(result))
        self.assertEqual(len(result["candidate_sha256"]), 64)

    def test_invalid_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, "INVALID_OR_UNSAFE_DIGEST"):
            local_public_digest(self.root, ingest_fn=lambda path: ("summary", "tree", "password = leaked"))

    def test_runner_injects_fabric_without_calling_real_api(self):
        seen = []
        def fake_urlopen(request, timeout):
            seen.append((json.loads(request.data.decode()), timeout))
            response = {"id":"offline-test-response", "model":"fixture", "output":[], "usage":{}, "status":"completed"}
            return io.BytesIO(json.dumps(response).encode())
        with patch.object(runner.urllib.request, "urlopen", side_effect=fake_urlopen):
            item = runner.request_one("director", "offline synthetic review", [], "fixture", "not-a-real-key", 100)
        self.assertEqual(item["response_id"], "offline-test-response")
        self.assertEqual(len(seen), 1)
        prompt = seen[0][0]["instructions"]
        self.assertIn("[J3:", prompt)
        self.assertIn("[J5:", prompt)
        self.assertIn("[J6:", prompt)
        self.assertIs(seen[0][0]["store"], False)


if __name__ == "__main__":
    unittest.main()
