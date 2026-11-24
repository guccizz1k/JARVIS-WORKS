"""Reject empty, incomplete, skipped or failed JUnit results for the main PR gate.
This is only a focused synthetic regression gate, not a production release proof.
"""
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
from collections import Counter

MINIMUMS = {
    'test_security': 8,
    'test_auth_integrity_v89': 4,
    'test_security_hardening_v17': 6,
    'test_quote_import': 18,
    'test_complex_settlement_v69': 6,
    'test_pg_rls_gate_v79': 14,
    'test_jw_main_ci_receipt': 1,
}


def verify(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 8 * 1024 * 1024:
        raise ValueError('REPORT_SIZE')
    if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
        raise ValueError('XML_DECLARATION_FORBIDDEN')
    root = ET.fromstring(raw)
    if root.tag not in ('testsuites', 'testsuite'):
        raise ValueError('REPORT_ROOT')
    suites = [root] if root.tag == 'testsuite' else list(root)
    counts = Counter()
    seen = set()
    for suite in suites:
        if suite.tag != 'testsuite':
            raise ValueError('SUITE_TAG')
        cases = suite.findall('testcase')
        if not cases or suite.get('tests') != str(len(cases)):
            raise ValueError('SUITE_COUNT')
        for key in ('failures', 'errors', 'skipped'):
            if suite.get(key) != '0':
                raise ValueError('SUITE_NOT_ALL_PASS')
        for case in cases:
            cls, name = case.get('classname'), case.get('name')
            if not cls or not name or (cls, name) in seen:
                raise ValueError('TEST_ID')
            seen.add((cls, name))
            if any(case.find(tag) is not None for tag in ('failure', 'error', 'skipped')):
                raise ValueError('TEST_NOT_ALL_PASS')
            counts[cls.rsplit('.', 1)[-1]] += 1
    if any(counts[module] < minimum for module, minimum in MINIMUMS.items()):
        raise ValueError('REQUIRED_TESTS_MISSING')
    return sum(counts.values())


if __name__ == '__main__':
    try:
        path = Path(sys.argv[1])
        with path.open('rb') as report:
            count = verify(report.read(8 * 1024 * 1024 + 1))
        print(f'PASS_MAIN_FOCUSED_REGRESSION {count} tests; NOT a production release approval')
    except (OSError, ValueError, ET.ParseError, IndexError) as exc:
        print('BLOCKED_MAIN_CI_RECEIPT', type(exc).__name__)
        sys.exit(1)
