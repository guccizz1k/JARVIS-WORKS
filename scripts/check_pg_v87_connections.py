#!/usr/bin/env python3
"""Standalone safe V8.7 gate. No raw exception, path, token, email or DSN output."""
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.pg_connection_gate_v87 import check_two_connections

def main():
    result=check_two_connections()
    print(json.dumps(result,sort_keys=True))
    return 0 if result['result']=='PASS' else 2

if __name__=='__main__':
    sys.exit(main())
