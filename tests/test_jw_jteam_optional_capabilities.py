"""Negative controls and deterministic positive tests for four optional J TEAM skills."""
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.jw_jteam_optional_capabilities import (
    inspect_manifest, penpot_token_diff, whisper_transcript_gate,
    ollama_loopback_probe, n8n_review_event, _local_open, _DenyRedirect,
)
import urllib.request
from unittest.mock import patch


class FakeResponse(io.BytesIO):
    def __init__(self, data, status=200):
        super().__init__(data)
        self.status = status
    def getcode(self):
        return self.status


class TestJTeamOptionalCapabilities(unittest.TestCase):
    def test_manifest_exact_pins_and_disabled(self):
        data = inspect_manifest()
        self.assertEqual(len(data["capabilities"]), 4)
        self.assertTrue(all(x["status"] == "OFF_BY_DEFAULT" for x in data["capabilities"]))
        self.assertEqual(data["external_network"], "DENY_BY_DEFAULT")
        self.assertTrue(data["no_production_deploy"])

    def test_modified_manifest_fails_closed(self):
        data = inspect_manifest()
        data["external_network"] = "ALLOW_ALL"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cfg.json"
            path.write_text(json.dumps(data), encoding="utf8")
            with self.assertRaisesRegex(ValueError, "CAPABILITY_POLICY_MISMATCH"):
                inspect_manifest(path)

    def test_symlinked_manifest_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / "manifest.json"
            original.write_text("{}", encoding="utf8")
            alias = Path(tmp) / "alias.json"
            alias.symlink_to(original)
            with self.assertRaisesRegex(ValueError, "UNSAFE_CAPABILITY_MANIFEST"):
                inspect_manifest(alias)

    def test_penpot_same_tokens_not_visual_proof(self):
        result = penpot_token_diff({"color.primary": "#123456", "space.sm": 8},
                                   {"color.primary": "#123456", "space.sm": 8})
        self.assertEqual(result["status"], "TOKEN_MATCH_ONLY")
        self.assertEqual(result["browser_visual_proof"], "NOT_RUN")

    def test_penpot_mismatches_or_missing_are_detected(self):
        result = penpot_token_diff({"a.color": "#000", "b.size": 4},
                                   {"a.color": "#fff"})
        self.assertEqual(result["status"], "TOKEN_DRIFT")
        self.assertEqual(result["mismatched"], ["a.color", "b.size"])

    def test_penpot_rejects_nested_data(self):
        with self.assertRaisesRegex(ValueError, "INVALID_TOKEN_VALUE"):
            penpot_token_diff({"x": {"arbitrary": "data"}}, {"x": 1})

    def test_penpot_rejects_nonnumeric_float(self):
        with self.assertRaisesRegex(ValueError, "INVALID_TOKEN_VALUE"):
            penpot_token_diff({"space.large": float("nan")}, {"space.large": 6})

    def test_whisper_validated_transcript_not_asr_claim(self):
        data = [{"start": 0, "end": 1.2, "text": "테스트"},
                {"start": 1.2, "end": 2.0, "text": "샘플"}]
        report = whisper_transcript_gate(data)
        self.assertEqual(report["status"], "TRANSCRIPT_STRUCTURE_PASS")
        self.assertEqual(report["audio_recognition_accuracy"], "NOT_MEASURED")
        self.assertEqual(len(report["content_sha256"]), 64)

    def test_whisper_overlapping_timestamps_denied(self):
        with self.assertRaisesRegex(ValueError, "INVALID_TIMESTAMPS"):
            whisper_transcript_gate([{"start": 0, "end": 3, "text": "a"},
                                    {"start": 2, "end": 4, "text": "b"}])

    def test_whisper_secret_rejected(self):
        with self.assertRaisesRegex(PermissionError, "SECRET"):
            whisper_transcript_gate([{"start": 0, "end": 1,
                                      "text": "OPENAI_API_KEY=unsafe"}])

    def test_ollama_no_connection_without_approval(self):
        called = []
        def network(*args, **kwargs):
            called.append(True)
            raise RuntimeError("should not connect")
        with self.assertRaises(PermissionError):
            ollama_loopback_probe("demo", "synthetic", transport=network)
        self.assertEqual(called, [])

    def test_ollama_only_fixed_loopback_and_bounded_payload(self):
        seen = []
        def fake(req, timeout):
            seen.append((req.full_url, timeout, json.loads(req.data)))
            return FakeResponse(json.dumps({"message": {"content": "42"}}).encode())
        report = ollama_loopback_probe("local-test:small", "synthetic example",
                                      approved=True, synthetic=True, transport=fake)
        self.assertEqual(report["model_calls"], 1)
        self.assertEqual(report["status"], "LOCAL_RESPONSE_UNVERIFIED")
        self.assertEqual(seen[0][0], "http://127.0.0.1:11434/api/chat")
        self.assertEqual(seen[0][1], 4)
        self.assertEqual(seen[0][2]["options"]["num_predict"], 128)

    def test_ollama_bad_model_and_secrets_denied(self):
        with self.assertRaises(ValueError):
            ollama_loopback_probe("http://evil.test?x=1", "synthetic",
                                  approved=True, synthetic=True)
        with self.assertRaises(PermissionError):
            ollama_loopback_probe("demo", "password=secret",
                                  approved=True, synthetic=True)

    def test_ollama_oversized_response_denied(self):
        def fake(req, timeout):
            return FakeResponse(b"x" * 16385)
        with self.assertRaisesRegex(ValueError, "OVERSIZED"):
            ollama_loopback_probe("demo", "synthetic",
                                  approved=True, synthetic=True, transport=fake)

    def test_default_transport_refuses_off_host_urls(self):
        req = urllib.request.Request("https://example.org/collect", data=b"synthetic")
        with self.assertRaisesRegex(PermissionError, "REMOTE_URL_FORBIDDEN"):
            _local_open(req, timeout=4)

    def test_local_transport_blocks_redirects_and_proxies(self):
        req = urllib.request.Request("http://127.0.0.1:11434/api/chat", data=b"{}")
        handler = _DenyRedirect()
        self.assertIsNone(handler.redirect_request(
            req, None, 302, "redirect", {}, "https://external.example/collect"))
        # A proxy-free handler with no proxies may be omitted from opener.handlers;
        # verify the actual production factory arguments instead.
        with patch("scripts.jw_jteam_optional_capabilities.urllib.request.build_opener") as factory:
            factory.return_value.open.return_value = FakeResponse(
                json.dumps({"message": {"content": "offline"}}).encode())
            result = ollama_loopback_probe(
                "demo", "synthetic", approved=True, synthetic=True)
            self.assertEqual(result["status"], "LOCAL_RESPONSE_UNVERIFIED")
            self.assertEqual(factory.call_count, 1)
            handlers = factory.call_args.args
            self.assertEqual(handlers[0].proxies, {})
            self.assertIsInstance(handlers[1], _DenyRedirect)

    def test_n8n_is_plan_only_without_dispatch(self):
        report = n8n_review_event("review_requested",
                                  {"sha": "a" * 40, "run_id": 3, "status": "PASS"})
        self.assertFalse(report["sent"])
        self.assertEqual(report["status"], "EVENT_PLAN_ONLY")

    def test_n8n_dispatch_requires_explicit_approval(self):
        with self.assertRaises(PermissionError):
            n8n_review_event("ci_finished",
                             {"sha": "a" * 40, "run_id": 3, "status": "PASS"},
                             dispatch=True)

    def test_n8n_rejects_extra_keys_and_unsafe_sha(self):
        with self.assertRaisesRegex(ValueError, "UNSAFE_EVENT_FIELDS"):
            n8n_review_event("ci_finished",
                             {"sha": "a"*40, "run_id": 3, "status": "PASS",
                              "tenant_data": "secret"})
        with self.assertRaisesRegex(ValueError, "UNSAFE_EVENT_VALUES"):
            n8n_review_event("ci_finished",
                             {"sha": "not-sha", "run_id": 3, "status": "PASS"})

    def test_n8n_bounded_local_dispatch_with_mock_transport(self):
        seen = []
        def fake(req, timeout):
            seen.append((req.full_url, json.loads(req.data), timeout))
            return FakeResponse(b"ok", 202)
        report = n8n_review_event("ci_finished",
                                  {"sha": "b"*40, "run_id": 100, "status": "PARTIAL"},
                                  dispatch=True, approved=True, transport=fake)
        self.assertEqual(report["status"], "LOCAL_EVENT_SENT_UNVERIFIED_DOWNSTREAM")
        self.assertFalse(report["external_actions_verified"])
        self.assertEqual(seen[0][0], "http://127.0.0.1:5678/webhook/jteam-review-only")
        self.assertEqual(set(seen[0][1]), {"event", "sha", "run_id", "status"})

    def test_n8n_http_error_denied(self):
        def fake(req, timeout):
            return FakeResponse(b"failed", 500)
        with self.assertRaisesRegex(ValueError, "N8N_BAD_RESPONSE"):
            n8n_review_event("ci_finished",
                             {"sha": "b"*40, "run_id": 100, "status": "FAIL"},
                             dispatch=True, approved=True, transport=fake)


if __name__ == "__main__":
    unittest.main()
