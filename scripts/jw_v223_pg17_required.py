"""Run the V22.3 mandatory disposable PostgreSQL migration acceptance."""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from xml.etree import ElementTree

FILE = "tests/test_v36_pg17_engine_e2e.py"
CASE = ("tests.test_v36_pg17_engine_e2e", "test_real_pg17_engine")


def require_pass(report):
    cases = ElementTree.parse(report).getroot().findall(".//testcase")
    if len(cases) != 1:
        raise ValueError("mandatory PG17 acceptance requires exactly one test result")
    case = cases[0]
    if (case.get("classname"), case.get("name")) != CASE or any(
        item.tag in {"skipped", "failure", "error"} for item in case
    ):
        raise ValueError("mandatory PG17 test was missing, skipped, or failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if os.environ.get("JW_V36_DISPOSABLE_PG17") != "1":
        parser.exit(1, "BLOCKED: mandatory PG17 gate requires disposable runtime opt-in\n")
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="jw-v223-required-pg17-") as temporary:
        report = Path(temporary) / "pytest.xml"
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", f"{FILE}::{CASE[1]}", f"--junitxml={report}"],
            cwd=root,
        )
        try:
            if report.is_file():
                args.report.write_bytes(report.read_bytes())
            if result.returncode:
                raise ValueError(f"pytest exited {result.returncode}")
            require_pass(report)
        except (ValueError, OSError, ElementTree.ParseError) as exc:
            parser.exit(1, f"FAIL: {exc}\n")
    print("PASS: mandatory PG17 migration test executed and passed")


if __name__ == "__main__":
    main()
