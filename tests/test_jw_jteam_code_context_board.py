"""Synthetic Codebase Memory graph + Paperclip view pilot, J1–J6 guarded."""
from __future__ import annotations
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from scripts.jw_jteam_code_context_board import (
    advise, analyze_code_graph, project_paperclip_board,
    read_contract, role_instructions,
)

SHA = "a" * 40
FILES = ["src/safety.py", "src/app.py", "tests/test_safety.py"]
GRAPH = {
    "sha": SHA, "indexed_sha": SHA,
    "files": FILES, "changed": ["src/safety.py"],
    "edges": [{"src": "src/app.py", "dst": "src/safety.py"},
              {"src": "tests/test_safety.py", "dst": "src/app.py"}],
    "related_tests": ["tests/test_safety.py"],
}
BOARD = {"team_id": "jarvis-works-one-team", "sha": SHA,
         "items": [{"id": "JT-001", "owner": "manager",
                    "status": "in_review", "j5_checkpoint_id": "j5-a13",
                    "approved": False},
                   {"id": "JT-002", "owner": "jarvis_lead",
                    "status": "done", "j5_checkpoint_id": None,
                    "approved": True}]}


class ContextBoardTests(unittest.TestCase):
    def test_exact_policy_and_cost_caps(self):
        data = read_contract()
        self.assertEqual(data["harness"], ["J1", "J2", "J3", "J4", "J5", "J6"])
        self.assertEqual(data["authority"], "J5_IS_SOURCE_OF_TRUTH")
        self.assertEqual(data["budget_actions_extra_usd"], 5)
        self.assertEqual(data["budget_api_krw"], 50000)
        self.assertTrue(data["no_heartbeats"])

    def test_changed_manifest_denied(self):
        obj = deepcopy(read_contract())
        obj["no_heartbeats"] = False
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / "manifest.json"
            file.write_text(json.dumps(obj))
            with self.assertRaisesRegex(ValueError, "CONTEXT_POLICY_TAMPERED"):
                read_contract(file)

    def test_symlink_manifest_denied(self):
        with tempfile.TemporaryDirectory() as d:
            original = Path(d) / "original.json"
            original.write_text("{}")
            sym = Path(d) / "alias.json"
            sym.symlink_to(original)
            with self.assertRaisesRegex(ValueError, "UNSAFE_CONTEXT_CONTRACT"):
                read_contract(sym)

    def test_codegraph_reaches_test_dependency(self):
        result = analyze_code_graph(GRAPH)
        self.assertEqual(result["status"], "GRAPH_EXPORT_REVIEW")
        self.assertEqual(result["impact_candidate_paths"], sorted(FILES))
        self.assertEqual(result["related_test_candidates"], ["tests/test_safety.py"])
        self.assertTrue(result["full_regression_required"])
        self.assertFalse(result["vendor_binary_executed"])
        self.assertEqual(result["release"], "BLOCKED")

    def test_stale_index_blocks_impact_claim(self):
        g = deepcopy(GRAPH)
        g["indexed_sha"] = "b" * 40
        result = analyze_code_graph(g)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["fresh_index"])

    def test_partial_index_blocks(self):
        g = deepcopy(GRAPH)
        g["changed"] = ["src/missing.py"]
        out = analyze_code_graph(g)
        self.assertEqual(out["missing_indexed_paths"], ["src/missing.py"])
        self.assertEqual(out["status"], "BLOCKED")

    def test_unknown_graph_file_rejected(self):
        g = deepcopy(GRAPH)
        g["edges"].append({"src": "external/unsafe.py", "dst": "src/safety.py"})
        with self.assertRaisesRegex(ValueError, "GRAPH_EDGE_OUTSIDE_INDEX"):
            analyze_code_graph(g)

    def test_no_production_keys_in_graph(self):
        for name in ("../secrets/config.py", ".env", "/etc/passwd",
                     "a//b.py", "credentials/admin.py", "key.pem",
                     "folder\\unsafe.py"):
            g = deepcopy(GRAPH)
            g["changed"] = [name]
            with self.subTest(name=name), self.assertRaises((ValueError, PermissionError)):
                analyze_code_graph(g)

    def test_graph_extra_fields_rejected(self):
        g = deepcopy(GRAPH)
        g["source_content"] = "private data"
        with self.assertRaisesRegex(ValueError, "INVALID_GRAPH_EXPORT_FIELDS"):
            analyze_code_graph(g)

    def test_no_fake_related_test_when_not_linked(self):
        g = deepcopy(GRAPH)
        g["edges"] = []
        result = analyze_code_graph(g)
        self.assertEqual(result["related_test_candidates"], [])
        self.assertTrue(result["full_regression_required"])

    def test_paperclip_board_roles_and_j5_links(self):
        out = project_paperclip_board(BOARD)
        self.assertEqual(out["items_count"], 2)
        self.assertEqual(out["state_counts"], {"done": 1, "in_review": 1})
        self.assertEqual(out["checkpoint_links"], 1)
        self.assertEqual(out["J5_authority"], "UNCHANGED")
        self.assertEqual(out["heartbeats_invoked"], 0)
        self.assertEqual(out["spend_measured"], "NOT_MEASURED")
        self.assertEqual(out["release"], "BLOCKED")

    def test_duplicate_tasks_denied(self):
        b = deepcopy(BOARD)
        b["items"].append(deepcopy(b["items"][0]))
        with self.assertRaisesRegex(ValueError, "INVALID_OR_DUPLICATE_TASK"):
            project_paperclip_board(b)

    def test_duplicate_checkpoint_denied(self):
        b = deepcopy(BOARD)
        b["items"][1]["j5_checkpoint_id"] = "j5-a13"
        with self.assertRaisesRegex(ValueError, "INVALID_OR_DUPLICATE_J5_CHECKPOINT"):
            project_paperclip_board(b)

    def test_unapproved_done_denied(self):
        b = deepcopy(BOARD)
        b["items"][1]["approved"] = False
        with self.assertRaisesRegex(PermissionError, "UNAPPROVED_DONE_CLAIM"):
            project_paperclip_board(b)

    def test_foreign_team_denied(self):
        b = deepcopy(BOARD)
        b["team_id"] = "another-company"
        with self.assertRaisesRegex(PermissionError, "FOREIGN_TEAM_BLOCKED"):
            project_paperclip_board(b)

    def test_untrusted_board_fields_denied(self):
        b = deepcopy(BOARD)
        b["items"][0]["token"] = "secret"
        with self.assertRaisesRegex(ValueError, "INVALID_TASK_FIELDS"):
            project_paperclip_board(b)

    def test_advisor_only_when_needed(self):
        code = advise("코드 수정 영향 분석", domain="software")
        self.assertEqual(code["candidates"][0]["id"], "codebase-memory-mcp")
        self.assertEqual(code["alternative"], "trail-code")
        board = advise("J TEAM 에이전트 업무 현황", domain="everyday")
        self.assertEqual(board["candidates"][0]["id"], "paperclip")
        self.assertEqual(advise("오늘 날씨", domain="everyday")["candidates"], [])
        self.assertEqual(advise("인스타 릴스 글", domain="social_media")["candidates"], [])
        self.assertFalse(board["external_runtime_executed"])
        self.assertEqual(board["cost_usd"], 0)

    def test_no_invalid_domain(self):
        with self.assertRaisesRegex(ValueError, "INVALID_DOMAIN"):
            advise("업무", domain="god_mode")

    def test_secret_in_task_denied(self):
        with self.assertRaisesRegex(PermissionError, "SECRET_IN_WORK_ORDER"):
            advise("코드 password=abc123", domain="software")

    def test_five_roles_have_guardrails(self):
        for role in ("deputy", "deputy_manager", "manager", "director", "jarvis_lead"):
            self.assertIn("OPTIONAL_CODE_CONTEXT_WORKBOARD_V134", role_instructions(role))
        with self.assertRaisesRegex(ValueError, "INVALID_ROLE"):
            role_instructions("outsider")


    def test_dependency_chain_beyond_six_hops_is_not_silently_truncated(self):
        g = {
            "sha": SHA, "indexed_sha": SHA,
            "files": [f"src/chain{i}.py" for i in range(9)] + ["tests/test_chain.py"],
            "changed": ["src/chain0.py"],
            "edges": [{"src": f"src/chain{i+1}.py",
                       "dst": f"src/chain{i}.py"} for i in range(8)]
                     + [{"src": "tests/test_chain.py", "dst": "src/chain8.py"}],
            "related_tests": ["tests/test_chain.py"],
        }
        out = analyze_code_graph(g)
        self.assertEqual(len(out["impact_candidate_paths"]), 10)
        self.assertEqual(out["related_test_candidates"], ["tests/test_chain.py"])
        self.assertEqual(out["status"], "GRAPH_EXPORT_REVIEW")

    def test_exported_test_not_in_index_is_rejected(self):
        g = deepcopy(GRAPH)
        g["related_tests"] = ["tests/test_missing.py"]
        with self.assertRaisesRegex(ValueError, "GRAPH_TEST_OUTSIDE_INDEX"):
            analyze_code_graph(g)


if __name__ == "__main__":
    unittest.main()
