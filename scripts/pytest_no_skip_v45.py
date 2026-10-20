"""V4.5 strict full-suite gate: a skipped test is not a completed check.

Only activated through check_v45_review.sh, not installed globally.
"""
import pytest


def pytest_sessionfinish(session, exitstatus):
    reporter = session.config.pluginmanager.get_plugin('terminalreporter')
    skipped = reporter.stats.get('skipped', ()) if reporter else ()
    if skipped:
        # Keep the underlying test output / skip reasons visible; never mark
        # a partial suite as completed merely because pytest returned zero.
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
        if reporter:
            reporter.write_line(
                f'FAIL: V4.5 strict regression: {len(skipped)} skipped test(s); '
                'resolve the cause before PostgreSQL integration')
