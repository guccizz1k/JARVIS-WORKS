"""Actual FastAPI B2B messenger write-path integration; isolated disposable DB."""
import uuid
import pytest

from fastapi.testclient import TestClient
import app.main as website
from app.pg_transition_outbox_v51 import OUTBOX, LAB, ALLOW


def test_default_web_messenger_has_no_outbox(client):
    with website.conn() as c:
        assert c.execute("SELECT name FROM sqlite_master WHERE name=?", (OUTBOX,)).fetchone() is None


def test_real_http_send_generates_same_transaction_outbox(tmp_path, monkeypatch):
    monkeypatch.setenv('JW_PG_OUTBOX_V51', LAB)
    monkeypatch.setenv('JW_PG_CI_ALLOW', ALLOW)
    monkeypatch.setenv('DEMO_SEED', '1')
    monkeypatch.delenv('BOOTSTRAP_EMAIL', raising=False)
    monkeypatch.delenv('JW_ENV', raising=False)
    monkeypatch.setattr(website, 'DB_PATH', tmp_path / 'web-lab.db')
    with TestClient(website.app, base_url='https://testserver') as client:
        login = client.post('/api/login', json={
            'email': 'demo@hanbit.example', 'password': 'Demo!2026secure'})
        assert login.status_code == 200, login.text
        cookie = login.cookies.get(website.SESSION_COOKIE)
        headers = {'Cookie': website.SESSION_COOKIE+'='+cookie,
                   'X-CSRF-Token': login.json()['csrf_token']}
        directory = client.get('/api/messenger/directory/search', headers=headers)
        assert directory.status_code == 200, directory.text
        peers = directory.json()['items']
        assert peers, 'Synthetic peer company missing'
        thread = client.post('/api/messenger/threads',
                             json={'recipient_org_id': peers[0]['org_id']},
                             headers=headers)
        assert thread.status_code in (200, 201), thread.text
        tid = thread.json()['id']
        request_id = uuid.uuid4().hex
        text = 'synthetic v51 content, never replicated'
        posted = client.post(f'/api/messenger/threads/{tid}/messages',
                             json={'content': text, 'request_id': request_id},
                             headers=headers)
        assert posted.status_code in (200, 201), posted.text
        mid = posted.json()['id']
        with website.conn() as c:
            assert c.execute('SELECT count(*) FROM messenger_messages WHERE id=?',(mid,)).fetchone()[0] == 1
            logs = c.execute(f'SELECT event_type,entity_ref FROM {OUTBOX} ORDER BY seq').fetchall()
            assert [(r[0],r[1]) for r in logs] == [('message.insert',mid)]
            assert text not in str(logs)
        replayed = client.post(f'/api/messenger/threads/{tid}/messages',
                               json={'content': text, 'request_id': request_id},
                               headers=headers)
        assert replayed.status_code in (200, 201), replayed.text
        with website.conn() as c:
            assert c.execute(f'SELECT count(*) FROM {OUTBOX}').fetchone()[0] == 1


def test_web_outbox_rejected_in_production_without_side_effects(tmp_path, monkeypatch):
    monkeypatch.setenv('JW_PG_OUTBOX_V51', LAB)
    monkeypatch.setenv('JW_PG_CI_ALLOW', ALLOW)
    monkeypatch.setenv('JW_ENV', 'production')
    monkeypatch.setattr(website, 'DB_PATH', tmp_path / 'would-be-prod.db')
    from app.pg_transition_outbox_v51 import OutboxRefused
    with pytest.raises(OutboxRefused):
        website.init_db()
    with website.conn() as c:
        assert c.execute("SELECT name FROM sqlite_master WHERE name=?",(OUTBOX,)).fetchone() is None
