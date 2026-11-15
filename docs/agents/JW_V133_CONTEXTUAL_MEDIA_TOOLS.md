# J TEAM V13.3 — context-aware, no-duplication tool routing (review only)

## Authority and provenance
- Original scope: owner request to make ViralityAI and delphitools available when appropriate, **not** blanket permission for scraping, paid subscriptions, uploading files or deploying third-party code.
- ViralityAI official site: https://viralityai.net/ ; terms https://viralityai.net/terms-of-service/ (last checked 2026-10-27). Its Terms expressly prohibit automated/non-human use and data mining/scraping and restrict commercial exploitation. Never implement automated page/API access without separate written authorization and legal approval. Manual research only; reported viral scores are vendor claims, not causal forecasts.
- delphitools: https://delphi.tools/ ; official source https://github.com/1612elphi/delphitools ; LICENSE includes 0BSD project-original works, but bundled MuPDF (AGPL-3.0), runtime Pandoc WASM (GPL-2.0-or-later), fonts and assets have independent restrictions. Neither clone/install nor reuse components without a separate legal and security review.
- No vendor account connected or installed during this candidate. No actual production creative export or browser acceptance.

## Selection matrix
| Situation | Preferred | Optional |
|---|---|---|
| YouTube/Instagram viral formats or market research | Existing public-source cross-market research + independent proof | ViralityAI manually in browser (ideas only) |
| Video subtitles or audio transcript | Existing Whisper + FFmpeg | delphitools Auto Subtitle, manual browser fallback |
| Extract frames or prepare storyboards | Existing FFmpeg | delphitools Frame Extractor manually |
| Shorts/Reels 9:16 crop and resize | Existing FFmpeg | delphitools Social Media Cropper manually |
| Background removal | Existing implemented image pipeline, if validated | delphitools Background Remover manually |
| Color contrast/palette | Existing design tokens, browser/accessibility QA | delphitools Contrast Checker/Palette Extractor manually |
| Confidential company/tenant data | Existing local authorized tools only | No external vendor |
| Ordinary Python debugging or unrelated research | Existing J TEAM tools | No vendor recommended |

## Real execution versus recommendation
`scripts/jw_jteam_contextual_tools.py` reads a strict local manifest, evaluates the work-order domain and task keywords, chooses an advisory shortlist, and adds a `contextual_tool_advice` field to the existing V13.0+ work order. It *never opens* a vendor URL, sends credentials, uploads customer data, downloads models, triggers billable resources, publishes, rewrites J1–J6, or claims independent agent execution. `selected[].status` is `NOT_RUN` and `release` remains `BLOCKED`. Manual navigation is at the owner's discretion.

The official open source local-only tools may be used manually by the user. Their privacy claims are not sufficient to authorize use with classified/corporate data without a separate review.

## Verification
Run:
- `python scripts/jw_jteam_contextual_tools.py --check`
- `python -m pytest -q tests/test_jw_jteam_contextual_tools.py tests/test_jw_jteam_universal_work_order.py`
- Existing J TEAM focused/expanded/full offline CI. Treat green CI as **routing-contract correctness**, never as external vendor proof.

Guardrails: project private, no main merge, no production deployment, no user data to external vendors, no new paid subscription; previous V13.0–V13.2 and J1–J6 work preserved.
