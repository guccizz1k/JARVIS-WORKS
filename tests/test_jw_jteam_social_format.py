"""Social format transfer baseline: positive and adversarial safety examples."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.jw_jteam_social_format import (
    baseline_for, load_policy, platforms_for, role_instructions,
    record_external_examples, whitespace_assessment,
)
from scripts.jw_jteam_universal_work_order import plan, role_guidance


class TestSocialFormatBaseline(unittest.TestCase):
    def test_contract_exact_required_evidence(self):
        p = load_policy()
        self.assertEqual(p["default_for"], ["instagram", "youtube"])
        self.assertEqual(p["formats"], ["POV", "TIER_LIST"])
        self.assertEqual(p["pilot_posts"], 3)
        self.assertEqual(p["starter_episodes"], 7)
        self.assertEqual(p["market_gap_policy"], "SEARCH_ABSENCE_IS_NOT_MARKET_PROOF")

    def test_manifest_changes_fail_closed(self):
        p = load_policy()
        p["pilot_posts"] = 30
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "policy.json"
            f.write_text(json.dumps(p), encoding="utf8")
            with self.assertRaisesRegex(ValueError, "SOCIAL_FORMAT_POLICY_TAMPERED"):
                load_policy(f)

    def test_policy_symlink_denied(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "original.json"
            p.write_text("{}", encoding="utf8")
            l = Path(d) / "link.json"
            l.symlink_to(p)
            with self.assertRaisesRegex(ValueError, "UNSAFE_SOCIAL_POLICY_PATH"):
                load_policy(l)

    def test_platform_inference(self):
        self.assertEqual(platforms_for("인스타그램 릴스"), ["instagram"])
        self.assertEqual(platforms_for("유튜브 쇼츠"), ["youtube"])
        self.assertEqual(platforms_for("인스타 릴스와 유튜브 쇼츠"), ["instagram", "youtube"])
        self.assertEqual(platforms_for("콘텐츠 작성"), ["instagram", "youtube"])

    def test_baseline_has_no_fabricated_research_or_publications(self):
        q = "인스타 콘텐츠로 돈 벌도록 글 작성"
        r = baseline_for(q)
        self.assertEqual(r["source_market_evidence"], "NOT_VERIFIED")
        self.assertEqual(r["target_market_gap"], "NOT_VERIFIED")
        self.assertEqual(r["selected_format"], None)
        self.assertEqual(len(r["pilot"]), 3)
        self.assertEqual(len(r["first_seven"]), 7)
        self.assertTrue(all(z["status"] == "NOT_RUN" for z in r["pilot"]))
        self.assertTrue(all(z["unique_original_value"] == "REQUIRED" for z in r["first_seven"]))
        self.assertEqual(r["publication"], "NOT_PERFORMED")
        self.assertEqual(r["status"], "RESEARCH_REQUIRED")
        self.assertNotIn(q, json.dumps(r, ensure_ascii=False))

    def test_no_social_format_leakage_to_other_work(self):
        o = plan("코드 오류 수정", domain="software")
        self.assertNotIn("social_content_format", o)
        self.assertNotIn("DEFAULT SOCIAL FORMAT", role_guidance("manager", "코드 오류 수정"))
        self.assertIn("social_content_format", plan("유튜브 쇼츠 작성"))
        self.assertIn("social_content_format", plan("인스타 글 작성"))

    def test_default_applies_to_all_five_roles_including_runner(self):
        for role in ("deputy", "deputy_manager", "manager", "director", "jarvis_lead"):
            text = role_guidance(role, "인스타 게시물 작성")
            self.assertIn("DEFAULT SOCIAL FORMAT BASELINE", text)
            self.assertIn("POV", text)
            self.assertIn("TIER_LIST", text)
            self.assertIn("3 original pilot posts", text)
            self.assertIn("7-episode", text)
        with self.assertRaisesRegex(ValueError, "UNKNOWN_JTEAM_ROLE"):
            role_instructions("admin")

    def test_source_evidence_is_recorded_but_not_certified(self):
        r = record_external_examples([{
            "platform": "youtube", "source_market": "fictional overseas hobby",
            "post_url": "https://www.youtube.com/watch?v=abc123",
            "format": "POV", "views": 2690000, "captured_on": "2026-10-27"
        }], "original software audience")
        self.assertFalse(r["source_metrics_independently_confirmed"])
        self.assertFalse(r["transfer_success_proven"])
        self.assertEqual(r["examples"][0]["status"], "UNVERIFIED_OBSERVATION")

    def test_duplicate_source_is_denied(self):
        ex = {"platform": "instagram", "source_market": "gardening",
              "post_url": "https://www.instagram.com/p/ABCDE/",
              "format": "TIER_LIST", "views": 5000, "captured_on": "2026-10-27"}
        with self.assertRaisesRegex(ValueError, "DUPLICATE_SOURCE_URL"):
            record_external_examples([ex, ex], "sport")

    def test_source_platform_mismatch_denied(self):
        ex = {"platform": "instagram", "source_market": "gardening",
              "post_url": "https://youtu.be/abc123",
              "format": "POV", "views": 5000, "captured_on": "2026-10-27"}
        with self.assertRaisesRegex(ValueError, "SOURCE_PLATFORM_MISMATCH"):
            record_external_examples([ex], "sport")

    def test_source_untrusted_host_and_insecure_scheme_denied(self):
        proto = {"platform": "youtube", "source_market": "gardening",
                 "format": "POV", "views": 5000, "captured_on": "2026-10-27"}
        for url in ("https://youtube.com.evil.example/watch?v=x",
                    "http://www.youtube.com/watch?v=x",
                    "https://user:pass@www.youtube.com/watch?v=x"):
            with self.assertRaises(ValueError):
                record_external_examples([{**proto, "post_url": url}], "sport")

    def test_views_must_be_valid_integer(self):
        p = {"platform": "youtube", "source_market": "gardening",
             "post_url": "https://www.youtube.com/watch?v=abc123",
             "format": "POV", "captured_on": "2026-10-27"}
        for n in (-1, True, "10000", 10**13):
            with self.assertRaises(ValueError):
                record_external_examples([{**p, "views": n}], "sport")

    def test_unknown_or_invalid_source_date_denied(self):
        p = {"platform": "youtube", "source_market": "gardening",
             "post_url": "https://www.youtube.com/watch?v=abc123",
             "format": "POV", "views": 20}
        for date in ("not-date", "2014-01-01"):
            with self.assertRaises(ValueError):
                record_external_examples([{**p, "captured_on": date}], "sport")

    def test_zero_results_do_not_prove_white_space(self):
        searches = [{"query": f"format query {i}", "platform": "youtube",
                     "observed_matches": 0} for i in range(3)]
        r = whitespace_assessment(searches)
        self.assertFalse(r["market_gap_proven"])
        self.assertEqual(r["status"], "HYPOTHESIS_ONLY")

    def test_duplicate_or_insufficient_search_denied(self):
        one = {"query": "POV market", "platform": "youtube", "observed_matches": 0}
        with self.assertRaises(ValueError):
            whitespace_assessment([one])
        with self.assertRaises(ValueError):
            whitespace_assessment([one, one, one])

    def test_reject_secret_in_research_material(self):
        with self.assertRaises(PermissionError):
            baseline_for("유튜브 password=abc")
        with self.assertRaises(PermissionError):
            record_external_examples([{
                "platform": "youtube", "source_market": "api_key=xxx",
                "post_url": "https://youtu.be/abc123",
                "format": "POV", "views": 1, "captured_on": "2026-10-27",
            }], "AI")


if __name__ == "__main__":
    unittest.main()
