"""Public Render QA auth isolation; no real external app or credentials."""
import base64
import pytest
from fastapi.testclient import TestClient

from app import main
from app.owner_review_app_v223 import app
from app.owner_review_public_qa_guard_v223 import (
    PublicQAGateError,authorized_basic,check_public_qa_runtime,public_qa_enabled
)


def public_env(tmp_path):
    return {
        'JW_PUBLIC_QA_MODE':'1',
        'JW_ENV':'review',
        'JW_ROOT_UI':'owner-visual-review',
        'JW_APPROVED_UI_REVIEW':'ISOLATED_REVIEW_ONLY',
        'JW_NO_EXTERNAL_DATABASE':'1',
        'DEMO_SEED':'1',
        'JARVIS_DB_PATH':str(tmp_path/'jw-v223-qa-regression.sqlite3'),
        'JW_REVIEW_BASIC_USER':'review_qa',
        'JW_REVIEW_BASIC_PASSWORD':'A-random-test-only-long-REDACTED-unsafe-to-use',
    }


def basic(user='review_qa', password='A-random-test-only-long-REDACTED-unsafe-to-use'):
    value=base64.b64encode((user+':'+password).encode()).decode()
    return {'Authorization':'Basic '+value}


@pytest.mark.parametrize('name,wrong',[
    ('JW_ENV','production'),
    ('JW_ROOT_UI','v222'),
    ('JW_APPROVED_UI_REVIEW',''),
    ('JW_NO_EXTERNAL_DATABASE','0'),
    ('DEMO_SEED','0'),
    ('JARVIS_DB_PATH','/opt/render/project/src/data/works.db'),
    ('JARVIS_DB_PATH','/tmp/not-dummy.db'),
    ('DATABASE_URL','postgresql://secret@remote/postgres'),
    ('JW_PG_STAGE_DSN','postgresql://secret@remote/postgres'),
    ('JW_PG_SOURCE_DSN','postgresql://secret@remote/postgres'),
    ('JW_PG_BACKUP_KEY','FAKE_32_BYTE_KEY'),
    ('SUPABASE_SERVICE_ROLE_KEY','secret'),
    ('JW_REVIEW_BASIC_USER','!'),
    ('JW_REVIEW_BASIC_PASSWORD','Demo!2026secure'),
    ('JW_REVIEW_BASIC_PASSWORD','short'),
])
def test_public_mode_fail_closed_on_unsafe_settings(tmp_path,name,wrong):
    env=public_env(tmp_path)
    env[name]=wrong
    with pytest.raises(PublicQAGateError,match='BLOCKED_PUBLIC_QA_'):
        check_public_qa_runtime(env)


def test_invalid_mode_is_not_silent_opt_out():
    with pytest.raises(PublicQAGateError,match='UNRECOGNIZED_MODE'):
        public_qa_enabled({'JW_PUBLIC_QA_MODE':'true'})
    assert public_qa_enabled({'JW_PUBLIC_QA_MODE':'1'})
    assert not public_qa_enabled({})


def test_valid_explicit_review_is_isolated(tmp_path):
    assert check_public_qa_runtime(public_env(tmp_path)) is True
    assert check_public_qa_runtime({}) is False


@pytest.mark.parametrize('value',[
    'Bearer token','Basic','Basic *','Basic !!!',
    'Basic '+base64.b64encode(b'nocolon').decode(),
    'Basic '+base64.b64encode(b'bad:bad').decode(),
    'Basic '+('A'*800),
])
def test_invalid_header_never_authorizes(value):
    assert not authorized_basic(value,'review_qa','A-random-test-only-long-REDACTED-unsafe-to-use')


def test_exact_basic_header_only():
    pw='A-random-test-only-long-REDACTED-unsafe-to-use'
    auth=basic()['Authorization']
    assert authorized_basic(auth,'review_qa',pw)
    assert not authorized_basic(auth,'review_qb',pw)
    assert not authorized_basic(auth,'review_qa','wrong-but-even-longer-password')


def test_isolated_public_review_middleware_protects_all_mounted_routes(tmp_path,monkeypatch):
    settings=public_env(tmp_path)
    for k,v in settings.items():
        monkeypatch.setenv(k,v)
    monkeypatch.setattr(main,'DB_PATH',tmp_path/'jw-v223-qa-regression.sqlite3')
    with TestClient(app,base_url='https://testserver') as client:
        health=client.get('/api/health')
        assert health.status_code==200
        for path in ('/','/api/config','/api/customers','/api/me',
                     '/api/review/orders/'+'a'*32+'/edit-context'):
            denied=client.get(path)
            assert denied.status_code==401,(path,denied.text)
            assert denied.headers['Cache-Control']=='no-store'
            assert denied.headers['WWW-Authenticate'].startswith('Basic ')
            assert denied.headers['Vary']=='Authorization'
        bad=client.post('/api/login',json={'email':'demo@hanbit.example',
                                            'password':'Demo!2026secure'})
        assert bad.status_code==401
        correct=client.get('/api/config',headers=basic())
        assert correct.status_code==200,correct.text
        assert correct.json()['demo_mode'] is True
        origin=client.post('/api/login',headers=basic(),json={
            'email':'demo@hanbit.example','password':'Demo!2026secure'})
        assert origin.status_code==200,origin.text
        assert client.get('/api/customers',headers=basic()).status_code==200


def test_invalid_public_mode_fails_before_seeding_database(tmp_path,monkeypatch):
    settings=public_env(tmp_path)
    settings['DATABASE_URL']='postgresql://real.invalid/live'
    for k,v in settings.items():
        monkeypatch.setenv(k,v)
    db_path=tmp_path/'jw-v223-qa-regression.sqlite3'
    monkeypatch.setattr(main,'DB_PATH',db_path)
    with pytest.raises(PublicQAGateError,match='EXTERNAL_CREDENTIALS'):
        with TestClient(app,base_url='https://testserver'):
            pass
    assert not db_path.exists()
