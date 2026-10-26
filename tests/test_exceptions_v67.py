"""V6.7 auditable exception queue, human-only review and failure cases."""
import sqlite3
import pytest
from app import main
from tests.test_reconciliation_v65 import create_sale, candidates, link


def case(api,rid):
    q=api.get('/evidence/reconciliation/exceptions')
    assert q.status_code==200,q.text
    return next(x for x in q.json()['items'] if x['record_id']==rid)


def review(api,rid,item,status='investigating',note='실제 원본 문서와 차이 재검토 진행'):
    return api.post('/evidence/records/'+rid+'/review-event',{
        'expected_digest':item['expected_digest'],'status':status,
        'original_checked':True,'note':note})


def test_unlinked_exception_and_append_only_history(api,quote_payload):
    before=api.get('/dashboard').json()
    q,rid=create_sale(api,quote_payload)
    x=case(api,rid)
    assert x['case_status']=='unlinked' and x['needs_attention']
    assert x['last_review'] is None
    r=review(api,rid,x)
    assert r.status_code==201,r.text
    assert r.json()['unresolved'] is True
    assert review(api,rid,x).json()['reused'] is True
    r2=review(api,rid,x,'document_checked','원본과 문서번호를 비교했고 차이가 확인됨')
    assert r2.status_code==201
    history=api.get('/evidence/records/'+rid+'/review-history').json()
    assert history['chain_integrity_valid'] is True
    assert [e['status'] for e in history['events']]==['investigating','document_checked']
    assert case(api,rid)['needs_attention'] is True  # document checked != dispute resolved
    after=api.get('/dashboard').json()
    assert after['outstanding']==before['outstanding']
    assert after['collected']==before['collected']
    with main.conn() as c:
        assert c.execute('SELECT count(*) FROM payments').fetchone()[0]==0
        with pytest.raises(sqlite3.IntegrityError):
            c.execute('DELETE FROM reconciliation_reviews_v67 WHERE record_id=?',(rid,))
        with pytest.raises(sqlite3.IntegrityError):
            c.execute("UPDATE reconciliation_reviews_v67 SET note='fake' WHERE record_id=?",(rid,))


def test_stale_digest_after_link_and_change_detection(api,quote_payload):
    q,rid=create_sale(api,quote_payload)
    item=case(api,rid)
    d=next(x for x in candidates(api,rid)['candidates'] if x['source_id']==q['id'])
    assert link(api,rid,d).status_code==201
    assert review(api,rid,item).status_code==409
    x=case(api,rid)
    assert x['case_status']=='linked' and not x['needs_attention']
    with main.transaction() as c:
        c.execute('UPDATE quotes SET status=? WHERE id=?',('sent',q['id']))
    new=case(api,rid)
    assert new['source_changed'] and new['needs_attention']
    assert review(api,rid,new).status_code==201


def test_linked_discrepancies_remain_visible(api,quote_payload):
    q,rid=create_sale(api,quote_payload,amount=121212)
    d=next(x for x in candidates(api,rid)['candidates'] if x['source_id']==q['id'])
    assert link(api,rid,d,reason='업로드 원본에서 금액 불일치 수동으로 확인').status_code==201
    x=case(api,rid)
    assert x['case_status']=='linked_with_issues' and x['needs_attention']
    assert any(i['field']=='gross_amount' for i in x['issues'])
    assert review(api,rid,x,'document_checked','원본을 확인했고 금액 불일치를 별도 정리 예정').status_code==201
    assert case(api,rid)['needs_attention']


def test_input_security_csrf_and_cross_tenant_protection(api,quote_payload):
    q,rid=create_sale(api,quote_payload)
    x=case(api,rid)
    assert api.post('/evidence/records/'+rid+'/review-event',{
        'expected_digest':x['expected_digest'],'status':'investigating',
        'original_checked':False,'note':'금액과 문서번호를 재검토하는 중'}).status_code==422
    assert api.post('/evidence/records/'+rid+'/review-event',{
        'expected_digest':x['expected_digest'],'status':'resolved',
        'original_checked':True,'note':'금액과 문서번호를 재검토하는 중'}).status_code==422
    assert api.c.post('/api/evidence/records/'+rid+'/review-event',headers={'Cookie':api.auth['Cookie']},
        json={'expected_digest':x['expected_digest'],'status':'investigating',
              'original_checked':True,'note':'금액과 문서번호를 재검토하는 중'}).status_code==403
    assert api.login('demo@bada.example').status_code==200
    assert api.get('/evidence/reconciliation/exceptions').json()['items']==[]
    assert api.get('/evidence/records/'+rid+'/review-history').status_code==404
    assert review(api,rid,x).status_code==404


def test_empty_queue_and_bad_event_digest(api,quote_payload):
    assert api.get('/evidence/reconciliation/exceptions').json()['total']==0
    q,rid=create_sale(api,quote_payload)
    x=case(api,rid)
    bad={**x,'expected_digest':'a'*64}
    assert review(api,rid,bad).status_code==409
    assert api.get('/evidence/records/'+rid+'/review-history').json()['events']==[]
