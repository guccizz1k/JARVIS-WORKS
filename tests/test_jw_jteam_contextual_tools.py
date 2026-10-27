"""No-network J TEAM contextual tool selection; negative controls."""
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from scripts.jw_jteam_contextual_tools import (
    read_contract, recommend, role_guidance,
)


class ContextualToolSelectionTests(unittest.TestCase):
    def selected(self, task, domain=None):
        return recommend(task, domain=domain)["selected"]

    def tools(self, task, domain=None):
        return [x["tool"] for x in self.selected(task, domain=domain)]

    def test_contract_keeps_exact_vendor_urls_manual(self):
        data = read_contract()
        self.assertEqual([x["id"] for x in data["services"]],
                         ["viralityai", "delphi"])
        self.assertEqual(data["execution"],
                         "RECOMMEND_ONLY_NO_EXTERNAL_TOOL_EXECUTION")
        self.assertTrue(all("MANUAL" in x["access"]
                            for x in data["services"]))

    def test_tampered_policy_is_blocked(self):
        modified = deepcopy(read_contract())
        modified["services"][0]["access"] = "AUTO_SCRAPE"
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "policy.json"
            file.write_text(json.dumps(modified), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "TOOL_ROUTING_POLICY_CHANGED"):
                read_contract(file)

    def test_symlink_policy_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "policy.json"
            file.write_text("{}", encoding="utf-8")
            alias = Path(tmp) / "alias.json"
            alias.symlink_to(file)
            with self.assertRaisesRegex(ValueError, "UNSAFE_ROUTING_CONTRACT"):
                read_contract(alias)

    def test_viral_ideas_choose_existing_evidence_first(self):
        selected = self.selected("유튜브 바이럴 콘텐츠 아이디어 조사", domain="social_media")
        self.assertEqual([x["tool"] for x in selected],
                         ["existing_public_research", "viralityai"])
        self.assertEqual(selected[0]["priority"], "FIRST")
        self.assertEqual(selected[1]["priority"], "OPTIONAL_MANUAL")

    def test_plain_instagram_caption_does_not_scrape(self):
        result = recommend("인스타그램 캡션 작성", domain="social_media")
        self.assertEqual(result["selected"], [])
        self.assertEqual(result["external_calls"], 0)
        self.assertEqual(result["publication"], "NOT_RUN")

    def test_video_subtitle_native_first(self):
        self.assertEqual(self.tools("쇼츠 자막 만들어줘"),
                         ["existing_whisper_ffmpeg", "delphi"])

    def test_social_crop_native_first(self):
        self.assertEqual(self.tools("인스타 릴스 9:16 크롭"),
                         ["existing_ffmpeg", "delphi"])

    def test_video_frames_native_first(self):
        self.assertEqual(self.tools("유튜브 영상 프레임 추출"),
                         ["existing_ffmpeg", "delphi"])

    def test_background_remover_fallback(self):
        self.assertEqual(self.tools("영상 배경 제거"),
                         ["existing_project_image_pipeline", "delphi"])

    def test_palette_and_contrast(self):
        self.assertEqual(self.tools("디자인 색상 대비"),
                         ["existing_design_qa", "delphi"])

    def test_confidential_blocks_all_external_tools(self):
        for task in ("고객정보 포함된 인스타 릴스 자막",
                     "사업자번호 견적서의 색상 추출",
                     "private repo youtube 트렌드",
                     "운영 DB 영상 프레임 분석"):
            with self.subTest(task=task):
                result = recommend(task, domain="social_media")
                self.assertEqual(result["data_scope"], "RESTRICTED_LOCAL_ONLY")
                self.assertEqual(self.tools(task, domain="social_media"),
                                 ["existing_local_jteam"])

    def test_tokens_credentials_rejected(self):
        for value in ("유튜브 password=abc", "인스타 OPENAI_API_KEY=x",
                      "유튜브 sk-Abcdefghijklmnop"):
            with self.assertRaisesRegex(PermissionError, "SECRET_BEARING_TASK"):
                recommend(value)

    def test_no_inert_expenses_or_hidden_requests(self):
        result = recommend("유튜브 인기 영상 조사 및 9:16 크롭", domain="social_media")
        self.assertEqual(result["external_calls"], 0)
        self.assertEqual(result["vendor_tools_installed"], 0)
        self.assertEqual(result["subscriptions_started"], 0)
        self.assertEqual(result["files_uploaded"], 0)
        self.assertEqual(result["cost_usd"], 0)
        self.assertEqual(result["release"], "BLOCKED")
        self.assertTrue(all(x["status"] == "NOT_RUN" and not x["executed"]
                            for x in result["selected"]))

    def test_no_duplicates_with_combined_job(self):
        selected = self.selected("릴스 자막 자막 srt 크롭 9:16")
        self.assertEqual(len(selected),
                         len({(x["tool"], x["operation"]) for x in selected}))

    def test_unknown_domain_refused(self):
        with self.assertRaisesRegex(ValueError, "UNKNOWN_DOMAIN"):
            recommend("영상", domain="super_admin")

    def test_invalid_text_refused(self):
        for value in ("", "x"*5001):
            with self.assertRaisesRegex(ValueError, "INVALID_TASK"):
                recommend(value)

    def test_private_code_not_sent_even_if_requested(self):
        result = recommend("private repo 유튜브 바이럴 콘텐츠", domain="social_media")
        self.assertEqual(result["selected"][0]["tool"], "existing_local_jteam")
        self.assertNotIn("viralityai", [x["tool"] for x in result["selected"]])

    def test_all_five_roles_receive_explicit_policy(self):
        for role in ("deputy", "deputy_manager", "manager", "director", "jarvis_lead"):
            self.assertIn("MANDATORY_CONTEXTUAL_TOOLS_V133", role_guidance(role))
        with self.assertRaisesRegex(ValueError, "UNKNOWN_ROLE"):
            role_guidance("outside_admin")

    def test_domain_research_not_forced_to_vendor(self):
        self.assertEqual(self.tools("시장 보고서 작성", domain="research"), [])
        self.assertEqual(self.tools("파이썬 코드 수정", domain="software"), [])


if __name__ == "__main__":
    unittest.main()
