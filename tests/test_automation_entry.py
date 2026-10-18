"""V1.5 automation entrypoint, review queue and tenant privacy safeguards."""
from pathlib import Path
from tests.test_smart_import import make_xlsx, post_file, approve
from app import main as backend

ROOT=Path(__file__).resolve().parents[1]

def test_global_entrypoint_highest_priority():
    html=(ROOT/'app/static/index.html').read_text()
    assert html.index('data-page="imports"')<html.index('data-page="dashboard"')
    assert html.index('data-page="dashboard"')<html.index('data-page="customers"')
    assert '문서 업로드 · 자동 처리' in html
    script=(ROOT/'app/static/app.js').read_text()
    assert "await navigate('imports')" in script
    assert '후속 자동화 개발 대상' in script
    assert '발주서 · 수주서 · 주문서' in script

def test_queue_starts_empty(api):
    q=api.get('/imports/queue')
    assert q.status_code==200
    assert q.json()['pending_count']==0
    assert q.json()['confirmed_count']==0
    assert q.json()['source_bytes_stored'] is False

def test_preview_queue_before_confirmation(api):
    p=post_file(api,make_xlsx()).json()
    q=api.get('/imports/queue').json()
    assert q['pending_count']==1 and q['confirmed_count']==0
    assert q['pending'][0]['filename']=='purchase.xlsx'
    assert q['pending'][0]['document_kind']=='발주서'
    assert q['pending'][0]['order_id'] is None
    assert not api.get('/orders').json()
    assert approve(api,p).status_code==201
    q=api.get('/imports/queue').json()
    assert q['pending_count']==0 and q['confirmed_count']==1
    assert q['confirmed'][0]['order_id']

def test_queue_no_raw_file_contents_or_private_payment_details(api):
    post_file(api,make_xlsx())
    q=api.get('/imports/queue').json()
    assert 'normalized_json' not in q['pending'][0]
    assert 'items' not in q['pending'][0]
    assert 'file_sha256' not in q['pending'][0]

def test_queue_separation_across_organizations(api,client):
    p=post_file(api,make_xlsx()).json()
    other=client.post('/api/login',json={'email':'demo@bada.example','password':'Demo!2026secure'})
    assert other.status_code==200
    q=client.get('/api/imports/queue')
    assert q.status_code==200 and not q.json()['pending']
    assert client.get('/api/imports/'+p['id']).status_code==404

def test_unrecognized_document_kind_fails_no_persistence(api):
    original_orders=len(api.get('/orders').json())
    for kind in ['견적서','납품서','청구서','입금확인서']:
        r=post_file(api,make_xlsx({'문서종류':kind}),filename='document.xlsx')
        assert r.status_code==422
    assert len(api.get('/orders').json())==original_orders
    assert api.get('/imports/queue').json()['pending_count']==0
