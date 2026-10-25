"""Record only GitHub expression booleans, never receive DSN/secret values."""
from __future__ import annotations

import json
import os
from pathlib import Path

SECRET_NAMES = ("JW_V97_TRADE_DSN", "JW_V97_AUTH_DSN")


def status(env):
    configured = {name: "SET" if env.get(name + "_SET") == "true" else "MISSING"
                  for name in SECRET_NAMES}
    return {"secret_status": configured,
            "ready": all(value == "SET" for value in configured.values()),
            "values_inspected": False}


def main():
    result = status(os.environ)
    Path("jw-v97-secret-status.json").write_text(json.dumps(result, sort_keys=True) + "\n")
    for name, state in result["secret_status"].items():
        print(name + ": " + state)
    if not result["ready"]:
        Path("jw-v97-verdict.json").write_text(json.dumps({
            "decision": "BLOCKED", "reason": "TWO_INDEPENDENT_SECRETS_MISSING",
            "authenticated": False, "read_only": True, "live_attempted": False,
            "production_cutover": False, "production_deployed": False}) + "\n")
        print("BLOCKED: owner must provision both repository Actions secrets in Settings.")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write("ready=" + str(result["ready"]).lower() + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
