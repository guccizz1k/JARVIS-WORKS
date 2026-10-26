# JARVIS-WORKS V11.6 — four-capability evidence audit

This is a **fail-closed evidence checklist**, not an implementation of actual model-driven code repair.

Targets: V9 checkpoint integration, authenticated AI repair in a disposable checkout, independent regression evaluation, and controlled external skill A/B. Each requires traceable, independently checked execution evidence before PASS.

Run: python3 -m unittest tests.test_jw_learning_four_gate -v

Run audit: python3 scripts/jw_learning_four_gate.py --evidence /path/to/evidence.json

No changes to JARVIS-WORKS main, production, PostgreSQL, secrets, or release gates. Self-reported fields alone cannot establish PASS. JARVIS-CORE's SQLite learning store must not be directly copied into tenant business databases. A/B must use identical pinned cases and evaluator, independently verified outcomes, and no holdout leakage.
