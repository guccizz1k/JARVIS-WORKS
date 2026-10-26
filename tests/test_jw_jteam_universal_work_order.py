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


    def test_social_request_includes_compulsory_proven_format_research(self):
        for task in ("유튜브 쇼츠 스크립트 작성", "인스타그램 게시글 작성"):
            order = plan(task)
            self.assertIn("social_content_format", order)
            self.assertEqual(order["social_content_format"]["source_market_evidence"], "NOT_VERIFIED")
            self.assertEqual(len(order["social_content_format"]["pilot"]), 3)
            self.assertEqual(len(order["social_content_format"]["first_seven"]), 7)
            self.assertEqual(order["paid_calls"], 0)
            self.assertEqual(order["publication_performed"], False)
        text = role_guidance("manager", "인스타그램 캡션 작성")
        self.assertIn("3 original pilot posts", text)

if __name__ == "__main__":
    unittest.main()
