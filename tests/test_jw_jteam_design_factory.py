"""Independent offline design contract and adversarial component intake tests."""
from __future__ import annotations
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from scripts.jw_jteam_design_factory import (
    audit_tokens, compile_css, contrast, intake_21st_component, read_policy,
)

EXAMPLE = {
    "source_url": "https://21st.dev/components/cards",
    "framework": "vanilla",
    "title": "분석 카드",
    "summary": "파일을 검토합니다.",
    "button": "확인",
}


class DesignFactoryTests(unittest.TestCase):
    def test_valid_exact_manifest(self):
        data = read_policy()
        self.assertEqual(data["product_stack"], "HTML_CSS_VANILLA_JS_FASTAPI")
        self.assertTrue(all(data[k] for k in ("no_auto_install",
                             "no_auto_mcp_connection", "no_provider_keys",
                             "no_external_upload", "no_main_merge")))
        self.assertEqual(data["sources"][1]["version"], "14.6.0")

    def test_manifest_tampering_denied(self):
        data = deepcopy(read_policy())
        data["no_provider_keys"] = False
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "wrong.json"
            path.write_text(json.dumps(data), encoding="utf8")
            with self.assertRaisesRegex(ValueError, "DESIGN_POLICY_TAMPERED"):
                read_policy(path)

    def test_symlink_policy_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "a.json"
            source.write_text("{}")
            alias = Path(tmp) / "b.json"
            alias.symlink_to(source)
            with self.assertRaisesRegex(ValueError, "UNSAFE_DESIGN_POLICY"):
                read_policy(alias)

    def test_aa_text_and_cta_contrast(self):
        ratios = audit_tokens(read_policy()["colors"])
        self.assertEqual(ratios["status"], "PASS")
        self.assertGreaterEqual(min(v for k, v in ratios["ratios"].items()
                                   if k != "focus"), 4.5)
        self.assertGreaterEqual(ratios["ratios"]["focus"], 3.0)

    def test_bad_palette_fails(self):
        colors = dict(read_policy()["colors"])
        colors["text"] = "#ffffff"
        self.assertIn("body", audit_tokens(colors)["failed"])

    def test_invalid_hex_and_schema(self):
        colors = dict(read_policy()["colors"])
        colors["text"] = "var(--evil)"
        with self.assertRaisesRegex(ValueError, "INVALID_TOKEN_COLOR"):
            audit_tokens(colors)
        with self.assertRaisesRegex(ValueError, "UNKNOWN_TOKEN_SET"):
            audit_tokens({"unknown": "#ffffff"})

    def test_color_formula_known_values(self):
        self.assertAlmostEqual(contrast("#000000", "#ffffff"), 21.0, places=5)
        self.assertAlmostEqual(contrast("#ffffff", "#ffffff"), 1.0, places=5)

    def test_css_build_is_deterministic(self):
        from scripts.jw_jteam_design_factory import DEMO_CSS
        self.assertEqual(compile_css(), DEMO_CSS.read_text(encoding="utf8"))
        self.assertIn("@media(prefers-reduced-motion:reduce)", compile_css())
        self.assertIn(":focus-visible", compile_css())
        self.assertIn("min-height:44px", compile_css())

    def test_safe_component_structured_html(self):
        result = intake_21st_component(EXAMPLE)
        self.assertEqual(result["status"], "LOCAL_SAFE_PREVIEW")
        self.assertIn("type=\"button\"", result["preview"])
        self.assertEqual(result["provider_calls"], 0)
        self.assertFalse(result["external_code_executed"])
        self.assertEqual(result["release"], "BLOCKED")

    def test_xss_escaped_not_executed(self):
        data = dict(EXAMPLE, title='<img src=x onerror=alert(1)>')
        preview = intake_21st_component(data)["preview"]
        self.assertNotIn("<img", preview)
        self.assertIn("&lt;img", preview)

    def test_url_allowlist(self):
        for url in ("http://21st.dev/unsafe", "https://21st.dev.evil.tld/c",
                    "https://admin:secret@21st.dev/cards", "https://evil.dev/cards"):
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, "UNTRUSTED"):
                intake_21st_component(dict(EXAMPLE, source_url=url))

    def test_react_requires_human_review(self):
        result = intake_21st_component(dict(EXAMPLE, framework="react"))
        self.assertEqual(result["status"], "REVIEW_REQUIRED_REACT_TO_VANILLA")
        self.assertIsNone(result["preview"])

    def test_unknown_markup_fields_rejected(self):
        with self.assertRaisesRegex(ValueError, "UNSAFE_COMPONENT_FIELDS"):
            intake_21st_component(dict(EXAMPLE, dangerouslySetInnerHTML="<script>"))

    def test_javascript_control_char_rejected(self):
        with self.assertRaisesRegex(ValueError, "CONTROL_CHARACTER"):
            intake_21st_component(dict(EXAMPLE, title="x\ny"))

    def test_unsupported_framework(self):
        with self.assertRaisesRegex(ValueError, "UNSUPPORTED_FRAMEWORK"):
            intake_21st_component(dict(EXAMPLE, framework="svelte"))

if __name__ == "__main__":
    unittest.main()
