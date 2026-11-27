# NARUV ONE reconciliation performance decision — 2026-11-27
Draft PR #192, head 29b73bff37576842dc6439f72c3a27a3195196db; Actions run 45988170027, job 140468983589, 15/15 steps success including container cleanup. Pinned source aa8894305dda413127e2994064f456a966d5e3c2, benchmark blob b75fabb99580e66914e3b01fdf18ccd4945a9aeb, candidate blob 07fc6dd4ae72e27ed005b27143e1087437d6adf9. Prior independent functional acceptance PR #190 run 45986616044 remains valid.
Actual ABBA arms, 10 timed samples per metric per arm:
| Arm | bill median ms | ledger median ms |
|---|---:|---:|
| baseline |34.276|693.617|
| candidate |32.390|648.657|
| candidate |32.045|649.532|
| baseline |34.529|695.796|
Median of arm medians: bill 34.4025 -> 32.2175 ms (-6.35%); ledger 694.7065 -> 649.0945 ms (-6.57%). Exact returned JSON equivalence; 40 timed bill and 40 timed ledger samples total across arms, additional warmups excluded. Same seeded local PG17 TLS fixture, function metadata and original body restored, cleanup success.
Decision: retain single-aggregate reconciliation optimization as a validated local review candidate, not deployed/merged; reject blanket FK index adoption per 69c36461a940309a39230dc02b90ce35b5b6b463. No production latency claim, no large-scale/hosted A/B acceptance, no production authorization. Do not repeat same passing benchmark without invalidating changes. Hosted connectivity root cause, release evidence, independent auth revocation boundaries remain outstanding. Actual CI charge not independently verified.
