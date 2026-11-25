# V22.3 composite containment

The original CINEMA guard remains authoritative for the closed V22.2 review.
Run it on a clean, named review branch at
`e22f66dde4ed552a75ce504147875733d4671ab2` using that revision's guard.
The V22.3 composite has separate acceptance and retains the historical legacy
failures as evidence of the scope difference.

## Requirements and scope

- Preserve the 37 approved V22.2 static file contents and modes, including
  the exact approved CSS revision. Preserve the imported legacy guard bytes.
- Account for every changed path from the original containment baseline to
  the verified V22.3 integration. The inventory includes file mode and Git blob
  identity for each path. No glob or prefix grants permission to modify a path.
- Treat the entries labeled legacy-allowed as baseline compatibility
  information. The other 248 entries are reviewed composite scope only.
- Freeze the 30 foreign workflows and 18 new static assets to their identified
  content. Workflow custody covers source bytes and confers no permission to
  run a workflow against external systems.
- Allow exactly the six policy, test, and review paths in the policy commit,
  whose sole parent is the verified integration. Require a clean target
  checkout and an exact match to the independently selected policy commit tree.
  This includes one existing test harness correction. The legacy browser
  collapses the rail using the same width assertion and polls for the resulting
  state with the same five-second bound used for opening the rail.

Each inventory row contains the path, original Git change status, mode, blob ID,
scope, and legacy whitelist verdict. The following scope review explains the
entries admitted by their exact identity.

| Inventory scope | Reason for inclusion |
|---|---|
| Approved V22.2 CSS | Preserve the exact approved rail styling blob. |
| V22.3 review UI assets | Preserve the separately added owner preview and its synthetic review interactions. |
| Legacy CINEMA workflows | Preserve the existing legacy browser, SQL, stage, and backup test wiring as recorded. |
| V22.3 review workflows | Preserve the recorded review, custody, and acceptance workflow source. |
| Inherited single-purpose workflows | Preserve the exact agent, learning, sandbox, and disposable integration workflow files in the verified input. |
| Approval boundary | Retain signature, checkpoint, and adapter code with their tests and runbook. |
| Review SQL | Retain the recorded SQL proposals, synthetic fixtures, assertions, and rollback scripts. |
| Isolated review application | Retain the cutover adapter, owner review, and inherited messaging and OCR review wiring. |
| CINEMA regression | Retain unit, security, HTTP, contract, and SQL regression test coverage. |
| V22.3 and PG17 regression | Retain composite owner review and migration acceptance coverage. |
| Inherited regression | Retain historical installer, agent tooling, and inherited security tests. |
| CINEMA diagnostics and gates | Retain recorded database and backup diagnostics, acceptance scripts, and guards. |
| Local test harness | Retain local browser, fixture restoration, and regression runners. |
| Recorded review evidence | Preserve documented design decisions and historical review results. |
| Review operations runbooks | Preserve backup and synthetic acceptance procedures. |
| Dependency pins | Preserve the reviewed dependency declarations used by those paths. |
| Inherited agent and acceptance tooling | Preserve repository governance, skill metadata, and acceptance scripts present in the verified input. |

## Local verification

Obtain the expected policy commit SHA from the verified bundle and SHA-256
evidence received through the review channel. Use the verifier from that
trusted policy checkout when inspecting a separate candidate worktree. A SHA
from the candidate being inspected is insufficient as a trust anchor.

```bash
python -I /path/to/trusted-policy/scripts/jw_v223_composite_containment.py \
  --root /path/to/clean-candidate --policy-commit "$REVIEWED_POLICY_SHA"
```

The mandatory migration acceptance uses only the existing throw-away Docker
fixture. With the disposable test explicitly authorized and its local image
available, run:

```bash
JW_V36_DISPOSABLE_PG17=1 python -I scripts/jw_v223_pg17_required.py \
  --report /path/outside-candidate/required-pg17.xml
```

The opt-in remains available to ordinary non-PG pytest runs. Mandatory
acceptance requires the explicit opt-in, a successful pytest exit, and exactly
one passing result for the named PG17 migration test. A skip, deselection,
missing report, or failed test fails this gate. For full local regression, use
the same disposable opt-in and retain the full pytest report separately.
The other mandatory SQL and role checks retain their existing disposable
PG17 commands and check counts. Live approval and release remain blocked.
