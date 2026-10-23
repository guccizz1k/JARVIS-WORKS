#!/usr/bin/env python3
"""Fail-closed optional independent TLS/role/lock primitive drill."""
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.pg_live_dryrun_v88 import live_gate_v88


def main() -> int:
    result = live_gate_v88()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result['result'] == 'PASS' else 2


if __name__ == '__main__':
    sys.exit(main())
