---
name: jt-audio-research
description: Whisper style offline transcript safety validator for evidence based research and recordings with consent.
---

# jt-audio-research — J TEAM optional capability (review only)

Scope: Transcript structure, timing and provenance checks, not speech recognition. J1–J6 and five-role J team authorization remain higher priority. Follow exact SHA evidence, independent verification and the existing 5-Gate harness; never infer an actual external runtime from local code.

1. Confirm `agents/team/jarvis_v1/capability_routing.json` and run `python scripts/jw_jteam_optional_capabilities.py --check` before use.
2. Use `whisper_transcript_gate` only on synthetic or consented local transcript segments; reject credentials and overlapping timestamps; no model downloads or API calls.
3. Return only a content digest and timing structure; actual audio recognition accuracy requires separate consented model input and independent word error rate checks.
4. Mark external connection, independent model results, enterprise tenant-data correctness and deployment `NOT RUN` or `BLOCKED` until separately verified. Candidate fixture tests may be `PASS` only with command output.
5. Do not install upstream packages automatically, transmit private source or customer data, incur a paid API charge, merge `main`, modify an existing J1–J6 contract, or deploy outside an explicitly reviewed and authorized scope.

Approval: jarvis_lead can propose on isolated review branches. A successful local pilot is not a production approval.
