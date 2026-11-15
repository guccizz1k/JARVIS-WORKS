# PURPOSE
Examine durable job integrity, idempotency and crash-safe recovery boundaries.

# METHOD
- Trace failure before, during and after an external call and local commit.
- Identify uncertain provider outcomes and require reconciliation before retry.
- Define durable task IDs, fencing, checkpoints and bounded retry policy.
- Compare failure injection observations with stated RTO/RPO and budget guard.

# OUTPUT
FAILURE WINDOW | DATA INTEGRITY | RECOVERY ACTION | EVIDENCE | STOP CONDITION.

# HARD GATES
Never retry an uncertain paid operation automatically; never report unmeasured recovery PASS.
