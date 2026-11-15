# J team V12.1 — OpenAI API runner, disabled by default

This is a **review-branch prototype**, not a deployed server. Five isolated Responses API requests are planned in role order; each uses role-specific instructions and receives previous artifacts. The director's independent challenge is **not** equivalent to a separate provider, independent test execution or proof of expertise.

## Safe offline run
`python scripts/jw_jteam_openai_runner.py --task "Review synthetic sample"`
Prints DRY_RUN, model_calls=0, release=BLOCKED. Unit tests: `python -m unittest tests.test_jw_jteam_openai_runner -v`.

## Paid execution prerequisites — NOT MET
- User explicitly approves the specific paid execution and ceiling.
- Operator configures `OPENAI_API_KEY` and an actual supported `JTEAM_MODEL` via private secrets (never Git).
- `JTEAM_PAID_API_APPROVED=YES` and `JTEAM_PROVIDER_BUDGET_ENFORCED=YES` only after independently verifying a real provider-side billing/usage guard. **These flags alone cannot enforce KRW caps**. Before production use add durable usage ledger, exchange-rate/pricing checks and stop-on-threshold enforcement.
- Do not run the execute command before these checks. Even when invoked, this prototype cannot verify true provider budget enforcement and must not be considered production-ready.

No tool-calling, repository write, CI trigger, deployment, live DB access or customer data. Output receipts must be sanitized before sharing. `store:false` requests no server-side response storage but does not replace organizational retention/security review.

## Next implementation
Add durable SQLite task IDs/checkpoints, idempotency, provider pricing/usage metering and independently verifiable budget guards; isolated read-only checkout per agent, actual browser/security test workers and same-SHA evidence. Only then evaluate independent execution and tool A/B in disposable environments. No main merge until explicit approval.
