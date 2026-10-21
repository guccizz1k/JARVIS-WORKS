import copy
import json
from pathlib import Path
import pytest
from scripts.release_readiness_v53 import evaluate, EvidenceError, GATES, main

@pytest.fixture
def checklist():
    return json.loads((Path(__file__).parents[1]/'docs'/'RELEASE_EVIDENCE_V53.json').read_text())


def test_eight_complete_stage_descriptions(checklist):
    result=evaluate(checklist)
    assert len(result['gates'])==8
    assert result['overall']=='BLOCKED'
    assert result['production_cutover_authorized'] is False
    assert result['release_authorized'] is False
    assert result['full_completion_measured'] is False


def test_missing_gate_denied(checklist):
    del checklist['gates'][GATES[-1][0]]
    with pytest.raises(EvidenceError):evaluate(checklist)


def test_unknown_gate_denied(checklist):
    checklist['gates']['sneaky']={'status':'PASS','evidence':['PASS: fake']}
    with pytest.raises(EvidenceError):evaluate(checklist)

@pytest.mark.parametrize('status',['SKIP','SKIPPED','SUCCESS','PASSING','DONE',1,None])
def test_unapproved_status_denied(checklist,status):
    checklist['gates'][GATES[0][0]]['status']=status
    with pytest.raises((EvidenceError,TypeError)):evaluate(checklist)


def test_empty_pass_proof_denied(checklist):
    checklist['gates'][GATES[0][0]]={'status':'PASS','evidence':[]}
    with pytest.raises(EvidenceError):evaluate(checklist)


def test_pass_claim_still_not_authorization(checklist):
    for item in checklist['gates'].values():
        item['status']='PASS'
        item['evidence']=['PASS: QA claim only']
    r=evaluate(checklist)
    assert not r['release_authorized']
    assert r['overall']=='PARTIAL'


def test_nonpass_cli_is_nonzero(checklist,tmp_path,capsys):
    path=tmp_path/'evidence.json';path.write_text(json.dumps(checklist))
    assert main(['--evidence',str(path)])==2
    assert 'BLOCKED' in capsys.readouterr().out


def test_forged_bad_file_is_failure(tmp_path):
    path=tmp_path/'bad.json';path.write_text('{invalid')
    assert main(['--evidence',str(path)])==1
