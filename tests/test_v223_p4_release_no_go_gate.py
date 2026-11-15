import copy
from scripts.jw_v223_release_no_go_gate import evaluate,SHA,OWNER_UI_SHA,REAL_REQUIREMENTS
def full():
    x={'schema':'JW_V223_RELEASE_EVIDENCE_V1','candidate_sha':SHA,'ui_sha256':OWNER_UI_SHA,
       'independent_audit':{'different_operator':True,'reviewed_same_sha':SHA},'phases':{}}
    for name,required in REAL_REQUIREMENTS.items():
        d={'status':'PASS','candidate_sha':SHA,'synthetic':False,'real_environment':True,
          'evidence_url':'https://qa.example.invalid/e','independent_run_id':'independent-run-'+name,
          'evidence_sha256':'f'*64,'environment_id':'verified-'+name}
        d.update({k:True for k in required});x['phases'][name]=d
    return x
def test_even_complete_json_is_not_release_permission():
    d=evaluate(full());assert d['status']=='STRUCTURALLY_ELIGIBLE_EXTERNAL_QA_REQUIRED' and d['can_release'] is False
def test_missing_p1_blocks():
    d=full();del d['phases']['P1'];assert evaluate(d)['status']=='BLOCKED'
def test_p1_no_key_custody_blocks():
    d=full();d['phases']['P1']['offsite_recovery_key_custody']=False;assert evaluate(d)['status']=='BLOCKED'
def test_pg17_no_restore_blocks():
    d=full();d['phases']['P1']['restored_into_independent_pg17']=False;assert evaluate(d)['status']=='BLOCKED'
def test_synthetic_p3_blocks():
    d=full();d['phases']['P3']['synthetic']=True;assert evaluate(d)['status']=='BLOCKED'
def test_no_17_real_business_routes_blocks():
    d=full();d['phases']['P2']['all_17_business_routes_real']=False;assert evaluate(d)['status']=='BLOCKED'
def test_no_safari_real_device_blocks():
    d=full();d['phases']['P2']['safari_device']=False;assert evaluate(d)['status']=='BLOCKED'
def test_mixed_sha_blocks():
    d=full();d['phases']['P4']['candidate_sha']='a'*40;assert evaluate(d)['status']=='BLOCKED'
def test_bad_approved_ui_sha_blocks():
    d=full();d['ui_sha256']='a'*64;assert evaluate(d)['status']=='BLOCKED'
def test_unsigned_placeholder_blocks():
    d=full();d['phases']['P3']['evidence_sha256']='PASS';assert evaluate(d)['status']=='BLOCKED'
def test_insecure_attestation_url_blocks():
    d=full();d['phases']['P4']['evidence_url']='http://example.invalid';assert evaluate(d)['status']=='BLOCKED'
def test_no_independent_audit_blocks():
    d=full();d['independent_audit']['different_operator']=False;assert evaluate(d)['status']=='BLOCKED'
def test_skipped_gate_blocks():
    d=full();d['phases']['P4']['zero_fail_error_skip']=False;assert evaluate(d)['status']=='BLOCKED'
def test_current_evidence_never_passes():
    from pathlib import Path
    import json
    p=Path(__file__).resolve().parents[1]/'docs/review/jw-v223-current-release-evidence-20261115.json'
    d=json.loads(p.read_text('utf8'))
    assert evaluate(d)['status']=='BLOCKED'
