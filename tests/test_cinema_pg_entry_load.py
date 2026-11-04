"""Builds the real CINEMA entry page (fastapi.responses stubbed) and syntax-checks the result.

Proves: the original HTML is only extended at the single insertion point, the v3 bridge is part of
the served script, the CSP hash matches the final script, and the combined script is valid JavaScript
(no duplicate declarations between the original UI, v1, v2 and v3). It does not run a browser.
"""
import base64
import hashlib
import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = (ROOT / "app" / "static" / "cinema" / "JARVIS_WORKS_CINEMA.html").read_text(encoding="utf-8")


def build_page():
    stub = types.ModuleType("fastapi.responses")

    class HTMLResponse:
        def __init__(self, content, headers=None):
            self.body, self.headers = content, headers or {}

    stub.HTMLResponse = HTMLResponse
    pkg = types.ModuleType("fastapi")
    saved = {k: sys.modules.get(k) for k in ("fastapi", "fastapi.responses")}
    sys.modules["fastapi"], sys.modules["fastapi.responses"] = pkg, stub
    try:
        spec = importlib.util.spec_from_file_location("cinema_entry_under_test", ROOT / "app" / "cinema_entry_v1.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.cinema_main_response()
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


PAGE = build_page()


def script_of(html):
    return re.search(r"<script>(.*?)</script>", html, re.S).group(1)


def test_page_contains_all_three_bridges_once():
    for marker in ("CINEMA server boundary", "server-backed adapter v2", "PostgreSQL trade-ledger bridge v3"):
        assert PAGE.body.count(marker) == 1, marker


def test_only_the_insertion_point_differs_from_the_original():
    needle = "boot();\n})();"
    head, tail = ORIGINAL.split(needle)
    assert PAGE.body.startswith(head) and PAGE.body.endswith(tail)
    assert PAGE.body.count("cinemaBoot();\n})();") == 1


def test_csp_hash_matches_final_script():
    digest = base64.b64encode(hashlib.sha256(script_of(PAGE.body).encode("utf-8")).digest()).decode("ascii")
    assert f"'sha256-{digest}'" in PAGE.headers["Content-Security-Policy"]
    assert "unsafe-inline' https://fonts" in PAGE.headers["Content-Security-Policy"]  # style only
    assert "script-src 'self' 'sha256-" in PAGE.headers["Content-Security-Policy"]


def test_combined_script_is_valid_javascript():
    assert shutil.which("node")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "page.js"
        path.write_text(script_of(PAGE.body), encoding="utf-8")
        proc = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr[:1500]


def test_v3_is_loaded_after_v2_and_before_boot():
    body = PAGE.body
    assert body.index("server-backed adapter v2") < body.index("PostgreSQL trade-ledger bridge v3") < body.index("cinemaBoot();\n})();")
