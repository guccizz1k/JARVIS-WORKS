"""J TEAM enterprise design lab — deterministic tokens + safe 21st intake.

Zero provider calls, zero install side-effects, no production HTML rewrites.
Vendor-provided React/JSX is NEVER executed as trusted HTML.
"""
from __future__ import annotations
import argparse
import html
import json
import math
import re
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "agents/team/jarvis_v1/pro_design_system.json"
DEMO_CSS = ROOT / "design-lab/design.css"
COLORS = ("background", "surface", "text", "muted", "primary",
          "primary_hover", "border", "focus")
HEX = re.compile(r"^#[0-9a-fA-F]{6}$")
FIELDS = frozenset(("source_url", "framework", "title", "summary", "button"))
TRUSTED_HOSTS = ("21st.dev", "www.21st.dev")
CSS_TAIL = ".jw-lab{font-family:Inter,ui-sans-serif,system-ui,sans-serif;background:var(--jw-background);color:var(--jw-text);min-height:100vh;padding:clamp(16px,4vw,44px)}\n.jw-shell{max-width:1060px;margin-inline:auto}\n.jw-eyebrow{color:var(--jw-primary);font-size:.85rem;font-weight:800;letter-spacing:.08em}\n.jw-heading{font-size:clamp(1.7rem,3.2vw,2.8rem);letter-spacing:-.035em;line-height:1.2}\n.jw-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,280px),1fr));gap:16px}\n.jw-card{background:var(--jw-surface);color:var(--jw-text);border:1px solid var(--jw-border);border-radius:16px;padding:24px;box-shadow:0 8px 24px rgb(27 40 56 / 6%);min-width:0}\n.jw-card h2{margin:0 0 12px;font-size:1.15rem;line-height:1.4}\n.jw-card p{margin:0 0 18px;color:var(--jw-muted);line-height:1.6}\n.jw-action{display:inline-flex;align-items:center;justify-content:center;border:1px solid var(--jw-primary);border-radius:10px;background:var(--jw-primary);color:white;min-height:44px;padding:10px 18px;font:inherit;font-weight:700;cursor:pointer}\n.jw-action:hover{background:var(--jw-primary-hover)}\n.jw-action:focus-visible{outline:3px solid var(--jw-focus);outline-offset:3px}\n.jw-status{margin-top:16px;min-height:24px;color:var(--jw-muted)}\n@media(prefers-reduced-motion:reduce){.jw-lab *, .jw-lab *::before, .jw-lab *::after{animation-duration:.01ms!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}\n" 

def _policy_exact() -> dict:
    return {
      "schema": "jw-jteam-pro-design-v1", "harness": [f"J{x}" for x in range(1,7)],
      "owner": "jarvis_lead", "status": "REVIEW_ONLY",
      "product_stack": "HTML_CSS_VANILLA_JS_FASTAPI",
      "sources": [
        {"id": "ui-ux-pro-max", "url": "https://github.com/nextlevelbuilder/ui-ux-pro-max-skill",
         "use": "CURATED_DESIGN_GUIDANCE_NOT_AUTO_INSTALLED", "license": "MIT"},
        {"id": "motion", "url": "https://github.com/motiondivision/motion",
         "use": "PINNED_VANILLA_JS_PILOT", "version": "14.6.0", "license": "MIT"},
        {"id": "21st-mcp", "url": "https://github.com/21st-dev/magic-mcp",
         "use": "OFFLINE_COMPONENT_INTAKE_ONLY",
         "license": "UPSTREAM_AND_COMPONENT_LICENSE_REVIEW"}
      ],
      "colors": {"background": "#f5f7fa", "surface": "#ffffff", "text": "#1b2838",
                 "muted": "#425268", "primary": "#126c70",
                 "primary_hover": "#0d5559", "border": "#dbe4ea", "focus": "#15817e"},
      "radius_px": {"card": 16, "button": 10}, "motion_ms": {"fast": 120, "normal": 240},
      "no_auto_install": True, "no_auto_mcp_connection": True,
      "no_provider_keys": True, "no_external_upload": True,
      "no_automatic_spend": True, "no_production_changes": True,
      "private_repo_only": True, "no_main_merge": True,
      "approval": "USER_RELEASE_SIGNOFF_REQUIRED",
    }


def read_policy(path: Path = POLICY) -> dict:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 15000:
        raise ValueError("UNSAFE_DESIGN_POLICY")
    data = json.loads(path.read_text(encoding="utf8"))
    if type(data) is not dict or data != _policy_exact():
        raise ValueError("DESIGN_POLICY_TAMPERED")
    return data


def luminance(value: str) -> float:
    if type(value) is not str or not HEX.fullmatch(value):
        raise ValueError("INVALID_COLOR")
    channels = [int(value[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    rgb = [x / 12.92 if x <= 0.04045 else ((x + 0.055) / 1.055) ** 2.4
           for x in channels]
    return sum(v * w for v, w in zip(rgb, (0.2126, 0.7152, 0.0722)))


def contrast(foreground: str, background: str) -> float:
    a, b = luminance(foreground), luminance(background)
    return (max(a, b) + 0.05) / (min(a, b) + 0.05)


def audit_tokens(tokens: dict) -> dict:
    if type(tokens) is not dict or set(tokens) != set(COLORS):
        raise ValueError("UNKNOWN_TOKEN_SET")
    if any(type(v) is not str or not HEX.fullmatch(v) for v in tokens.values()):
        raise ValueError("INVALID_TOKEN_COLOR")
    measures = {
      "body": contrast(tokens["text"], tokens["surface"]),
      "muted": contrast(tokens["muted"], tokens["surface"]),
      "button": contrast("#ffffff", tokens["primary"]),
      "button_hover": contrast("#ffffff", tokens["primary_hover"]),
      "focus": contrast(tokens["focus"], tokens["surface"]),
    }
    failed = [name for name, val in measures.items()
              if val < (3.0 if name == "focus" else 4.5)]
    return {"status": "PASS" if not failed else "FAIL",
            "ratios": {k: round(v, 2) for k, v in measures.items()},
            "failed": failed, "visual_browser": "NOT_RUN"}


def compile_css() -> str:
    config = read_policy()
    checks = audit_tokens(config["colors"])
    if checks["status"] != "PASS":
        raise ValueError("INSUFFICIENT_DESIGN_CONTRAST")
    variables = "".join(f"--jw-{k.replace('_','-')}:{config['colors'][k]};"
                        for k in COLORS)
    return ":root{" + variables + "}\n" + CSS_TAIL


def intake_21st_component(proposal: dict) -> dict:
    """Review a *structured proposal*, not arbitrary 21st JSX/network output."""
    read_policy()
    if type(proposal) is not dict or set(proposal) != FIELDS:
        raise ValueError("UNSAFE_COMPONENT_FIELDS")
    source = proposal["source_url"]
    if type(source) is not str or len(source) > 500:
        raise ValueError("INVALID_COMPONENT_SOURCE")
    parsed = urlsplit(source)
    if (parsed.scheme != "https" or parsed.hostname not in TRUSTED_HOSTS
            or parsed.username or parsed.password or parsed.port is not None
            or not parsed.path or parsed.fragment):
        raise ValueError("UNTRUSTED_COMPONENT_SOURCE")
    if proposal["framework"] not in ("react", "vanilla"):
        raise ValueError("UNSUPPORTED_FRAMEWORK")
    for field in ("title", "summary", "button"):
        s = proposal[field]
        if type(s) is not str or not 1 <= len(s.strip()) <= 220:
            raise ValueError("INVALID_COMPONENT_TEXT")
        if any(ord(c) < 32 for c in s):
            raise ValueError("CONTROL_CHARACTER_IN_COMPONENT")
    if proposal["framework"] != "vanilla":
        return {"status": "REVIEW_REQUIRED_REACT_TO_VANILLA",
                "preview": None, "provider_calls": 0,
                "external_code_executed": False, "license_review": "PENDING",
                "release": "BLOCKED"}
    title, summary, button = (html.escape(proposal[k], quote=True)
                              for k in ("title", "summary", "button"))
    markup = (
        '<article class="jw-card" data-motion-card>'
        f'<h2>{title}</h2><p>{summary}</p>'
        f'<button class="jw-action" type="button">{button}</button></article>'
    )
    return {"status": "LOCAL_SAFE_PREVIEW", "preview": markup,
            "provider_calls": 0, "external_code_executed": False,
            "license_review": "PENDING", "release": "BLOCKED"}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if not args.check:
        parser.error("only --check is allowed on the CI review route")
    try:
        checks = audit_tokens(read_policy()["colors"])
        if compile_css() != DEMO_CSS.read_text(encoding="utf8"):
            raise ValueError("DESIGN_CSS_DESYNCHRONIZED")
        if checks["status"] != "PASS":
            raise ValueError("CONTRAST_GATE_FAILED")
    except (ValueError, OSError, TypeError):
        print(json.dumps({"status": "BLOCKED", "gate": "DESIGN_SYSTEM_CONTRACT"}))
        return 3
    print(json.dumps({"status": "PASS", "contrast_ratios": checks["ratios"],
                      "21st_mcp_connected": False, "motion_browser": "NOT_RUN",
                      "production_release": "BLOCKED"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
