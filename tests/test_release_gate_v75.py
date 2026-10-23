from scripts.release_gate_v75 import evaluate


def test_release_remains_blocked_with_known_critical_gaps():
    g=evaluate()
    assert g['decision']=='BLOCKED' and g['deployment_performed'] is False
    assert g['requirements']['operational_pg_rls']=='not_verified'
    assert g['requirements']['physical_ios_safari']=='not_verified'
    assert g['local_tests_are_not_production_evidence'] is True
