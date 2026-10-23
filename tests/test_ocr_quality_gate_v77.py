import json
import pytest
from scripts.ocr_quality_gate_v77 import evaluate,from_manifest,EvaluationBlocked


def test_exact_correct_rejection_and_abstention():
    r=evaluate([
      {'expected':{'total_amount':'1000','counterparty':'한빛'},'predicted':{'total_amount':'1000','counterparty':'한빛'}},
      {'expected':{'total_amount':'2000','counterparty':'한빛'},'predicted':{'total_amount':'200O','counterparty':''}},
      {'expected':{'total_amount':'3000'},'predicted':{'total_amount':''}},
    ])
    a=r['fields']['total_amount']
    assert a['samples']==3
    assert a['exact_match_rate']==pytest.approx(1/3,abs=.0001)
    assert a['precision']==.5 and a['recall']==pytest.approx(1/3,abs=.0001)
    assert a['incorrect_nonempty_predictions']==1
    assert a['abstentions']==1
    assert r['production_quality_approved'] is False
    assert '한빛' not in str(r)


def test_blank_expected_and_hallucinated_prediction():
    r=evaluate([{'expected':{'business_number':''},'predicted':{'business_number':'123-45-67890'}}])
    f=r['fields']['business_number']
    assert f['incorrect_nonempty_predictions']==1
    assert f['precision']==0
    assert f['character_error_rate'] is None


def test_unicode_nfkc_and_whitespace():
    r=evaluate([{'expected':{'counterparty':'ＡＢＣ   상사'},'predicted':{'counterparty':'ABC 상사'}}])
    assert r['fields']['counterparty']['exact_match_rate']==1


def test_malformed_or_unbounded_manifest_rejected(tmp_path):
    p=tmp_path/'manifest.json'
    p.write_text(json.dumps({'dataset':'synthetic','rows':[{'expected':{'bad':'1'},'predicted':{}}]}))
    with pytest.raises(EvaluationBlocked,match='Unsupported'):from_manifest(p)
    p.unlink();p.symlink_to(tmp_path/'missing')
    with pytest.raises(EvaluationBlocked,match='Unsafe'):from_manifest(p)


def test_empty_or_long_value_rejected():
    with pytest.raises(EvaluationBlocked):evaluate([])
    with pytest.raises(EvaluationBlocked):evaluate([{'expected':{'counterparty':'a'*501},'predicted':{}}])


def test_abstain_not_counted_as_false_prediction():
    r=evaluate([{'expected':{'total_amount':'1000'},'predicted':{}}])
    assert r['fields']['total_amount']['incorrect_nonempty_predictions']==0
    assert r['fields']['total_amount']['recall']==0
