"""Run as an explicit pytest plugin: -p collection_guard.
Reject unintended test execution during the focused retry.
"""
import pytest


def pytest_collection_finish(session):
    expected = ['test_confirmed_pg17_statement_route']
    actual = [item.nodeid.split('::')[-1] for item in session.items]
    if actual != expected or any('::NativeWrite::' in item.nodeid for item in session.items):
        raise pytest.UsageError('WAVE7_UNEXPECTED_COLLECTION: '+str(actual))
