# J team V13.0 — owner-only universal one-request operations

## Mission
J team is an owner-only personal work organization, not only a code-review group. Five **roles** operate under existing J1–J6: deputy (research), deputy_manager (experience/content strategy), manager (creation/implementation), director (independent critical review), jarvis_lead (synthesis & approved action). Work domains: software, social_media, business, research, everyday.

**Critical distinction:** role routing in ChatGPT / this repository **does not** launch five independent model sessions, perform one-click end-to-end content creation, connect external accounts or authenticate a publisher. The new `scripts/jw_jteam_universal_work_order.py` is a deterministic, offline, no-spend **planning and safety layer**. `jw_jteam_openai_runner.py` now includes selected domain-role instructions only when its pre-existing restricted Responses API permission gates allow actual execution.

## Universal work order
One user request becomes a private work order with eight steps:
1. Intake / clarify constraints where necessary (including platform, budget, authorized account).
2. Source/market/audience research with date and provenance.
3. Product UX, brand/content concept or workflow design.
4. Original asset, software or commercial deliverable creation.
5. Skeptical check: correctness, copyright/rights, disclosures, platform terms, privacy, accessibility.
6. Human approval for external writes, purchases, API spend or channel scheduling where platform and connector require.
7. Authorized connected tool publishes/updates/deploys **only after consent and permission checks**.
8. Verified real measurements of retention/engagement/conversions/revenue, postmortem, measured A/B improvements.

Stages remain `NOT_RUN` until real tools provide evidence. `PLAN_ONLY` never implies actual independent agents, uploaded social content or business income. External output must have a receipt / destination ID, no fabricated metrics.

## Social business low-cost starting experiment (proposal, not executed)
- One audience/brand serving useful practical AI tools or productivity workflows; the owner selects scope.
- One original short-form content idea adapted for Instagram Reels and YouTube Shorts; start with a small 30-day experiment, not bulk-generated interchangeable videos.
- Unit measurement per published asset: topic, original source and music/media licenses, editorial approval, actual published URL/id, post date, impressions, retention, clicks, follower gains, cost, revenue and gross profit. Never treat views as cash.
- Revenue pathways beyond platform ads: disclosed affiliate links, legitimate sponsorships, original templates, paid micro-services and lawful business assets (subject to actual demand and tax/legal compliance). No promises of monetization.
- Instagram prohibits buying/selling/transferring accounts under its Terms; account flipping must never be advertised as the default Exit strategy. For YouTube review current transfer/Brand Account policies and monetization rules before a transaction.
- YouTube requires genuine, original value. AI may assist; generic mass-produced content and fake engagement risk demonetization, spam enforcement and reputation damage. Realistic altered/synthetic content may require disclosure.
- Connected provider action permissions govern publication. Windsor.ai may publish supported media on a connected eligible Instagram account after individual confirmation. Metricool may schedule within free-tier limits if connected. YouTube account publishing requires an authorized service/plugin or OAuth-based YouTube API. Do not invent or scrape access tokens.

## User-exclusive data/privacy boundaries
- Private GitHub source is never public or uploaded to a third-party code ingestion website.
- Platform accounts linked through official OAuth only. Secrets remain in provider-managed secret stores. No login/password strings through chat, prompts, workflows, logs or CI.
- All outbound posting requires platform permissions and any required per-action confirmation; once authorized scheduling is supported, act only within the explicit account and approved publication scope.
- No purchase of followers/views, follow/unfollow manipulation, spam comments, unauthorized scraping, copyright violations, misleading testimonials, credential-sharing account transfers or unapproved expense.
- No external cloud/LLM spend beyond existing explicit owner budget. Prefer included ChatGPT tools, supported installed connectors, free native scheduling and only approved GitHub Actions time.
- User's existing GitHub J1–J6 acceptance remains the owner of release and recovery evidence. Do not silently modify production app, public Render services, customer databases or schedules.

## Developer commands
```bash
python -m scripts.jw_jteam_universal_work_order --task "인스타그램 릴스 계정 주제 조사와 게시물 준비"
python -m scripts.jw_jteam_universal_work_order --task "프로그램 오류 수정과 테스트" --domain software
python -m pytest -q tests/test_jw_jteam_universal_work_order.py
```

Output intentionally includes `publication_performed: false`, `paid_calls: 0`, `independent_models_run: 0`, and all work stages `NOT_RUN`; request text is not returned, only SHA-256. This is security-aware task routing, **not** autonomous production.

## Next functional acceptance milestones
A. Connect and authenticate one suitable social publishing account; validate current action permissions, posting type, free limits. No budget required.
B. Deliver an original social-media content package end to end (idea, checked claim, script, caption, rights-cleared image/video source) and get publication approval.
C. Publish using the connected app, capture exact post id/URL and confirm actual publication. For recurring schedules, verify platform supports scheduled action; ChatGPT native reminders alone do not perform posting.
D. Read analytics, compute genuine conversion/revenue by source; improve only after actual data.
E. For continuous autonomous multi-model runs, add private secure job queue, tools, model credits or alternative free local model runner and explicit scoped permissions; do not overclaim a UI-only or mock pilot as a real agent farm.

Roll back this V13.0 feature by reverting its new work-order contract/router/test and the domain guidance integration; previous original J team engineering roles remain intact.
