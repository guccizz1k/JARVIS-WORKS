"""J team universal work orders: five-domain routing, real API isolation and safety."""
import io
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from scripts.jw_jteam_universal_work_order import (
    DOMAINS, ROLES, STAGES, check_instruction, domain_for, plan,
    read_contract, role_guidance,
)
from scripts import jw_jteam_openai_runner as runner


class UniversalJTeamOrderTests(unittest.TestCase):
    def test_manifest_preserves_exact_roles_and_j1_j6(self):
        contract = read_contract()
        self.assertEqual(contract["role_order"], list(ROLES))
        self.assertEqual(contract["harness"], ["J1", "J2", "J3", "J4", "J5", "J6"])
        self.assertEqual(set(contract["allowed_domains"]), set(DOMAINS))
        self.assertEqual(contract["monthly_extra_cost_preference_krw"], 0)

    def test_software_order(self):
        self.assertEqual(domain_for("파이썬 코드 오류 수정 및 테스트"), "software")

    def test_social_instagram_and_youtube(self):
        for task in ("인스타 릴스 운영해", "유튜브 쇼츠를 제작하고 업로드해"):
            self.assertEqual(domain_for(task), "social_media")

    def test_social_wins_tied_software(self):
        self.assertEqual(domain_for("인스타그램 자동 업로드 프로그램 개발"), "social_media")

    def test_business_domain(self):
        self.assertEqual(domain_for("자본금 모으는 수익 모델 사업계획"), "business")

    def test_everyday_domain(self):
        self.assertEqual(domain_for("내 일정 정리하고 리마인더 만들어"), "everyday")

    def test_research_is_safe_default(self):
        self.assertEqual(domain_for("메모 써줘"), "research")

    def test_explicit_domain(self):
        self.assertEqual(domain_for("메일 일정", domain="software"), "software")

    def test_unknown_domain_denied(self):
        with self.assertRaisesRegex(ValueError, "UNSUPPORTED_DOMAIN"):
            domain_for("test", domain="superuser")

    def test_bad_role_denied(self):
        with self.assertRaisesRegex(ValueError, "UNKNOWN_JTEAM_ROLE"):
            role_guidance("admin", "인스타 콘텐츠")

    def test_work_order_only_plans_and_never_claims_execution(self):
        order = plan("인스타그램 릴스와 유튜브 쇼츠를 만들고 자동 업로드해줘")
        self.assertEqual(order["domain"], "social_media")
        self.assertEqual(order["status"], "PLAN_ONLY")
        self.assertEqual(order["paid_calls"], 0)
        self.assertEqual(order["independent_models_run"], 0)
        self.assertIs(order["publication_performed"], False)
        self.assertEqual(order["release"], "BLOCKED")
        self.assertEqual([x["role"] for x in order["roles"]], list(ROLES))
        self.assertEqual([x["stage"] for x in order["stages"]], list(STAGES))
        self.assertTrue(all(x["status"] == "NOT_RUN" for x in order["stages"]))
        self.assertIn("PUBLISHING_AUTHORIZATION_NOT_VERIFIED", order["issues"])
        self.assertNotIn("릴스와", json.dumps(order, ensure_ascii=False))

    def test_account_sale_risk_is_explicit(self):
        order = plan("인스타그램 계정 판매를 준비해")
        self.assertIn("INSTAGRAM_ACCOUNT_SALE_POLICY_REVIEW", order["issues"])
        self.assertIs(order["publication_performed"], False)

    def test_secret_and_password_like_text_denied(self):
        for task in ("password = test123", "API_KEY=secret", "sk-ABCDEFGHIJKLMNOPQRSTUV"):
            with self.assertRaisesRegex(PermissionError, "POTENTIAL_SECRET"):
                plan(task)

    def test_invalid_or_overlong_input(self):
        for task in ("  ", "x" * 5001):
            with self.assertRaisesRegex(ValueError, "INVALID_INSTRUCTION"):
                check_instruction(task)

    def test_policy_tampering_detected(self):
        changed = deepcopy(read_contract())
        changed["action_policy"]["external_posting"] = "ALLOW_ANYONE"
        with tempfile.TemporaryDirectory() as root:
            f = Path(root) / "contract.json"
            f.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "WORK_ORDER_POLICY_MISMATCH"):
                read_contract(f)

    def test_all_role_guidance_preserves_real_vs_simulated_boundary(self):
        for role in ROLES:
            instructions = role_guidance(role, "유튜브 영상 기획", domain="social_media")
            self.assertIn("JTEAM_DOMAIN=social_media", instructions)
            self.assertIn("independent model execution", instructions)
            self.assertIn("J1-J6", instructions)

    def test_runner_includes_social_instructions_with_mock_network_only(self):
        seen = []
        def fake_urlopen(request, timeout):
            payload = json.loads(request.data)
            seen.append(payload)
            fake = {"id": "offline-dummy-id", "model": "test-local",
                    "output": [], "usage": {}, "status": "completed"}
            return io.BytesIO(json.dumps(fake).encode())
        with patch.object(runner.urllib.request, "urlopen", side_effect=fake_urlopen):
            result = runner.request_one("deputy_manager", "인스타그램 릴스 업로드", [], "offline-fixture", "fake-key", 100)
        self.assertEqual(result["response_id"], "offline-dummy-id")
        self.assertEqual(len(seen), 1)
        self.assertIn("JTEAM_DOMAIN=social_media", seen[0]["instructions"])
        self.assertIn("[J1:", seen[0]["instructions"])
        self.assertIs(seen[0]["store"], False)

    def test_format_transfer_always_in_youtube_instagram_writing(self):
        for role in ROLES:
            s = role_guidance(role, "인스타그램 캡션", domain="social_media")
            self.assertIn("MANDATORY_SOCIAL_FORMAT_TRANSFER_V132", s)
            self.assertIn("UNVERIFIED", s)

    def test_format_strategy_read_only_and_not_in_software_domain(self):
        result = plan("유튜브 쇼츠 제목 작성", domain="social_media")
        self.assertEqual(result["social_format_strategy"]["pilot_posts"], 3)
        self.assertEqual(result["social_format_strategy"]["source_effectiveness"],
                         "NOT_VERIFIED_WITHOUT_INDEPENDENT_SOURCE")
        self.assertIsNone(plan("Python 버그", domain="software")["social_format_strategy"])
        self.assertFalse(result["publication_performed"])
        self.assertEqual(result["paid_calls"], 0)


    def test_tools_select_for_social_research_and_media_workflows(self):
        research = plan("유튜브 바이럴 영상 포맷 조사", domain="social_media")
        selected = research["contextual_tool_advice"]["selected"]
        self.assertEqual([t["tool"] for t in selected],
                         ["existing_public_research", "viralityai"])
        self.assertTrue(all(not t["executed"] for t in selected))
        self.assertFalse(research["publication_performed"])
        subtitle = plan("쇼츠 자막 편집", domain="social_media")
        self.assertEqual(
            [t["tool"] for t in subtitle["contextual_tool_advice"]["selected"]],
            ["existing_whisper_ffmpeg", "delphi"])

    def test_private_information_does_not_route_to_vendor(self):
        task = plan("유튜브 고객정보 첨부된 영상 분석", domain="social_media")
        advice = task["contextual_tool_advice"]
        self.assertEqual(advice["data_scope"], "RESTRICTED_LOCAL_ONLY")
        self.assertEqual([x["tool"] for x in advice["selected"]],
                         ["existing_local_jteam"])
        self.assertEqual(advice["external_calls"], 0)

    def test_non_social_development_not_randomly_assigned_delphi(self):
        plan_result = plan("Python 코드 버그 수정", domain="software")
        self.assertEqual(plan_result["contextual_tool_advice"]["selected"], [])
        self.assertEqual(plan_result["release"], "BLOCKED")

    def test_all_role_guidance_includes_contextual_advisory(self):
        for role in ROLES:
            guidance = role_guidance(role, "인스타 콘텐츠", domain="social_media")
            self.assertIn("MANDATORY_CONTEXTUAL_TOOLS_V133", guidance)
            self.assertIn("MANDATORY_SOCIAL_FORMAT_TRANSFER_V132", guidance)



    def test_codebase_memory_impact_hint_in_actual_work_order(self):
        result = plan("코드 함수 수정 영향 테스트", domain="software")
        evidence = result["code_context_workboard_advice"]
        self.assertEqual(evidence["candidates"][0]["id"], "codebase-memory-mcp")
        self.assertEqual(evidence["alternative"], "trail-code")
        self.assertEqual(evidence["system_of_record"], "J5")
        self.assertFalse(evidence["external_runtime_executed"])
        self.assertEqual(result["independent_models_run"], 0)

    def test_paperclip_dashboard_is_read_only_plan(self):
        result = plan("J TEAM 에이전트 작업 현황 확인", domain="everyday")
        note = result["code_context_workboard_advice"]
        self.assertEqual(note["candidates"][0]["id"], "paperclip")
        self.assertFalse(note["configuration_written"])
        self.assertEqual(note["cost_usd"], 0)
        self.assertEqual(note["release"], "BLOCKED")
        self.assertFalse(result["publication_performed"])

    def test_codeboard_not_for_instagram_writing(self):
        result = plan("인스타그램 콘텐츠 글 써줘", domain="social_media")
        self.assertEqual(result["code_context_workboard_advice"]["candidates"], [])
        self.assertIn("MANDATORY_SOCIAL_FORMAT_TRANSFER_V132",
                      role_guidance("manager", "인스타 글", domain="social_media"))

    def test_role_review_no_hidden_autonomous_execution(self):
        for role in ROLES:
            policy = role_guidance(role, "코드 수정", domain="software")
            self.assertIn("OPTIONAL_CODE_CONTEXT_WORKBOARD_V134", policy)


if __name__ == "__main__":
    unittest.main()
