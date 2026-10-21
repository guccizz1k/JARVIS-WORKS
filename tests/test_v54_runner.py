"""V5.4 wrapper safety/precedence contract tests (no Docker/PG invoked)."""
from pathlib import Path
import subprocess

ROOT=Path(__file__).parents[1]


def test_gate_chains_historical_sha_and_strict_regression():
    s=(ROOT/'scripts/check_v54_review.sh').read_text()
    assert 'sha256sum --check --status V5_4_PG_GATE_SHA256.txt' in s
    assert 'bash scripts/check_v53_review.sh' in s
    assert s.index('sha256sum --check') < s.index('bash scripts/check_v53_review.sh')
    assert 'set -Eeuo pipefail' in s


def test_runner_executes_snapshot_first_and_prior_pg_after():
    s=(ROOT/'scripts/run_pg17_codespaces_v54.sh').read_text()
    assert s.index('python3 -m scripts.test_mutation_snapshot_v54') < s.index('bash scripts/run_pg17_codespaces_v53.sh')
    assert '|| { echo' in s
    assert 'set -Eeuo pipefail' in s
    assert 'NEW PG payload relay NOT IMPLEMENTED' in s


def test_prod_deny_casefold_and_unset():
    s=(ROOT/'scripts/run_pg17_codespaces_v54.sh').read_text()
    guard=s[s.index('JW_ENV_SAFE='):s.index('export JW_PG_OUTBOX_V51')]
    for value,expected in [(None,0),('development',0),('production',2),('PRODUCTION',2),('PrOdUcTiOn',2)]:
        env={}
        if value is not None: env['JW_ENV']=value
        result=subprocess.run(['bash','-c','set -Eeuo pipefail\n'+guard+'\necho REACHED'],
                              env=env,text=True,capture_output=True,timeout=5)
        assert result.returncode==expected
        assert ('REACHED' in result.stdout)==(expected==0)


def test_lab_only_no_migration_or_external_deployment():
    s=(ROOT/'scripts/run_pg17_codespaces_v54.sh').read_text()
    assert 'JW_PG_CI_ALLOW=ONLY_EPHEMERAL_LOCAL_DATABASE' in s
    assert 'JW_PG_LAB_V54=ONLY_DISPOSABLE_LAB' in s
    assert not any(x in s for x in ('kubectl ', 'eas build', 'git push', 'vercel deploy', 'psql -f'))
