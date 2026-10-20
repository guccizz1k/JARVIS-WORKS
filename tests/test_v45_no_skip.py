"""Strict verification of no-skip pytest policy."""
from types import SimpleNamespace
from pathlib import Path
import pytest
from scripts import pytest_no_skip_v45 as plugin

class Reporter:
    def __init__(self, skipped):
        self.stats = {'skipped':[object() for _ in range(skipped)]}
        self.lines=[]
    def write_line(self, msg):self.lines.append(msg)


def call_gate(n, exitstatus=0):
    reporter=Reporter(n)
    session=SimpleNamespace(exitstatus=exitstatus,
        config=SimpleNamespace(pluginmanager=SimpleNamespace(get_plugin=lambda name:reporter)))
    plugin.pytest_sessionfinish(session,exitstatus)
    return session.exitstatus,reporter.lines


def test_zero_skips_preserves_pass():
    assert call_gate(0)==(0,[])


def test_skipped_tests_cannot_pass():
    for n in (1,2,200):
        status,lines=call_gate(n)
        assert status==pytest.ExitCode.TESTS_FAILED and 'skipped' in lines[0]


def test_prior_failure_not_made_pass():
    assert call_gate(0,exitstatus=1)[0]==1
    assert call_gate(1,exitstatus=2)[0]==pytest.ExitCode.TESTS_FAILED


def test_script_enables_only_v45_strict_policy():
    parent=Path(__file__).resolve().parents[1]
    text=(parent/'scripts/check_v45_review.sh').read_text()
    assert "export PYTEST_ADDOPTS='-p scripts.pytest_no_skip_v45'" in text
    assert text.index('export PYTEST_ADDOPTS')<text.index('bash scripts/check_v44_review.sh')
    assert 'scripts.pytest_no_skip_v45' not in (parent/'scripts/run_pg17_codespaces_v45.sh').read_text()
