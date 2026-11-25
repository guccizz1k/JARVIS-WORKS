#!/usr/bin/env python3
"""Post-A/B REAL encrypted backup -> isolated PG17 restore (65 tables only).

Never touches Supabase source. Reads only authenticated encrypted files uploaded
to existing ignored transfer folder. Requires the previously marked localhost
disposable PG17, verifies every restored table/row/security signature, and
retains the older 62-table backup and reports in a separate private directory.
"""
from __future__ import annotations
import sys
from scripts.ci_cinema_pg_w import main as restore_main

if __name__ == "__main__":
    sys.exit(restore_main(profile="postab"))
