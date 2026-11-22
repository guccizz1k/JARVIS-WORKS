from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from scripts import ci_cinema_pg_v6_runner_integration as integration

def runner(tmp_path):
    def old_stage(): raise AssertionError('legacy target called')
    def old_env(): raise AssertionError('legacy environment called')
    return SimpleNamespace(
        stage_target=old_stage,backup_env=old_env,
        BACKUP_DIR=tmp_path/'private',source_dsn=lambda:'source-dsn',
        HOST='approved.host',PORT='5432',PROJECT_REF='approved-ref',
        ROLE='jw_backup_ro',POSTAB_FINGERPRINT_DEFAULT='fixed-fingerprint',
    )

def test_stage_uses_v6_not_legacy(tmp_path):
    r=runner(tmp_path)
    with patch('scripts.ci_cinema_pg_v6_target_binding.checked_target_config',
               return_value={'JW_PG_TARGET_ADMIN_DSN':'verified'}):
        integration.install(r,None,None)
        assert r.stage_target()['restore_target']=='v6_verified_isolated_55433'
        assert r._v6_original_stage_target is not r.stage_target

def test_child_env_keeps_source_binding_and_v6_target(tmp_path):
    r=runner(tmp_path)
    with patch('scripts.ci_cinema_pg_v6_target_binding.checked_target_config',
               return_value={'JW_PG_TARGET_ADMIN_DSN':'verified','JW_PG_CI_ALLOW':'ONLY_EPHEMERAL_LOCAL_DATABASE'}):
        integration.install(r,None,None)
        e=r.backup_env()
    assert e['JW_PG_TARGET_ADMIN_DSN']=='verified'
    assert e['JW_PG_SOURCE_DSN']=='source-dsn'
    assert e['JW_PG_EXPECT_SOURCE_HOST']=='approved.host'
    assert e['JW_PG_EXPECT_ROLE']=='jw_backup_ro'
    assert e['TMPDIR']==str(r.BACKUP_DIR)
    assert r.BACKUP_DIR.is_dir()

def test_fail_closed_if_target_proof_fails(tmp_path):
    r=runner(tmp_path)
    with patch('scripts.ci_cinema_pg_v6_target_binding.checked_target_config',
               side_effect=ValueError('target rejected')):
        integration.install(r,None,None)
        import pytest
        with pytest.raises(ValueError):r.stage_target()
        with pytest.raises(ValueError):r.backup_env()
