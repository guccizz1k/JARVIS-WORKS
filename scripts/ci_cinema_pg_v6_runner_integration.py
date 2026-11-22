"""V6 integration shim for the approved B2/B3 runner.

Does not activate the source role or run a backup. The caller must retain
the original SHA/approval gate and revocation/finally semantics.
"""
from __future__ import annotations

def install(runner, psycopg, backup_module):
    """Replace only target preparation and child environment binding.

    The original runner's source authentication, backup command, signature
    evaluation and unconditional role revocation remain unchanged.
    """
    from scripts.ci_cinema_pg_v6_target_binding import checked_target_config
    original_env = runner.backup_env

    def target_stage():
        checked_target_config(psycopg, backup_module)
        return {'restore_target': 'v6_verified_isolated_55433'}

    def child_environment():
        # Retain every source binding and existing backup environment setting.
        # Legacy backup_env() must not be called: it reads and exports 55432.
        import os
        target = checked_target_config(psycopg, backup_module)
        runner.BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        env = dict(os.environ)
        env.update(target)
        env.update({
            'JW_PG_SOURCE_DSN': runner.source_dsn(),
            'JW_PG_REAL_SOURCE': '1',
            'JW_PG_SCHEMA': 'jw_dev',
            'JW_PG_EXPECT_SOURCE_HOST': runner.HOST,
            'JW_PG_EXPECT_SOURCE_PORT': str(runner.PORT),
            'JW_PG_EXPECT_PROJECT_REF': runner.PROJECT_REF,
            'JW_PG_EXPECT_DBNAME': 'postgres',
            'JW_PG_EXPECT_ROLE': runner.ROLE,
            'JW_PG_EXPECT_SCHEMA_FINGERPRINT': (
                os.environ.get('JW_PG_EXPECT_SCHEMA_FINGERPRINT')
                or runner.POSTAB_FINGERPRINT_DEFAULT),
            'TMPDIR': str(runner.BACKUP_DIR),
        })
        return env

    # Preserve original functions for audit/reversal. Never invoke either
    # legacy target stage or legacy backup_env on this isolated target.
    runner._v6_original_stage_target = runner.stage_target
    runner._v6_original_backup_env = original_env
    runner.stage_target = target_stage
    runner.backup_env = child_environment
    return runner
