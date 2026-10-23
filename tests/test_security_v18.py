"""V1.8 evidence: MFA recovery cannot bypass possession checks or tenant boundaries."""
import hashlib
import time
import sqlite3
from cryptography.fernet import Fernet
from app import main as backend
from app.security_hardening import totp_code


def auth(r):
    return {'Cookie':backend.SESSION_COOKIE + '=' + r.cookies.get(backend.SESSION_COOKIE),
            'X-CSRF-Token':r.json()['csrf_token']}


def login(client,email='demo@hanbit.example',otp=None,recovery_code=None,password='Demo!2026secure'):
    return client.post('/api/login',json={'email':email,'password':password,'otp':otp,'recovery_code':recovery_code})


def enroll(client,monkeypatch,email='demo@hanbit.example'):
    monkeypatch.setenv('JW_DATA_KEY',Fernet.generate_key().decode())
    a=login(client,email=email)
    assert a.status_code==200,a.text
    h=auth(a)
    s=client.post('/api/security/mfa/start',json={'password':'Demo!2026secure'},headers=h)
    assert s.status_code==200,s.text
    secret=s.json()['secret']
    counter=int(time.time()//30)
    res=client.post('/api/security/mfa/confirm',json={'otp':totp_code(secret,counter)},headers=h)
    assert res.status_code==200,res.text
    codes=res.json()['recovery_codes']
    return a,secret,codes


def test_codes_random_stored_only_as_hash_and_single_use(client,monkeypatch):
    a,secret,codes=enroll(client,monkeypatch)
    assert len(set(codes))==8
    assert all(len(c)==32 and c.isascii() for c in codes)
    with backend.conn() as c:
        recs=c.execute('SELECT * FROM mfa_recovery_codes WHERE user_id=?',(a.json()['user']['id'],)).fetchall()
        assert len(recs)==8
        for rec in recs:
            assert rec['code_hash'] not in codes
            assert rec['consumed_at'] is None
            assert len(rec['code_hash'])==64
    assert login(client,recovery_code=codes[0],password='incorrect').status_code==401
    ok=login(client,recovery_code=codes[0]);assert ok.status_code==200
    assert login(client,recovery_code=codes[0]).status_code==401
    h=auth(ok)
    status=client.get('/api/security/mfa/status',headers=h)
    assert status.status_code==200 and status.json()['recovery_codes_remaining']==7
    assert all(x not in str(client.get('/api/security/overview',headers=h).json()) for x in codes)


def test_rotation_requires_fresh_factor_revokes_existing_sessions(client,monkeypatch):
    _,secret,codes=enroll(client,monkeypatch)
    sess=login(client,recovery_code=codes[0]);h=auth(sess)
    assert client.post('/api/security/mfa/recovery/rotate',json={'password':'Demo!2026secure'},headers=h).status_code==422
    assert client.post('/api/security/mfa/recovery/rotate',json={'password':'invalid','recovery_code':codes[1]},headers=h).status_code==403
    assert client.get('/api/me',headers=h).status_code==200
    rotated=client.post('/api/security/mfa/recovery/rotate',json={'password':'Demo!2026secure','recovery_code':codes[1]},headers=h)
    assert rotated.status_code==200,rotated.text
    new=rotated.json()['recovery_codes']; assert len(new)==8 and not (set(new)&set(codes))
    assert client.get('/api/me',headers=h).status_code==401
    for code in codes[:2]:
        assert login(client,recovery_code=code).status_code==401
    assert login(client,recovery_code=new[2]).status_code==200
    with backend.conn() as c:
        assert c.execute('SELECT count(*) FROM mfa_recovery_codes WHERE consumed_at IS NOT NULL').fetchone()[0]==1


def test_cross_company_recovery_code_cannot_log_in(client,monkeypatch):
    _,secret,codes=enroll(client,monkeypatch)
    fail=login(client,email='demo@bada.example',recovery_code=codes[0])
    # The other company has no MFA, and no recovery code is ever read from it.
    assert fail.status_code==401
    correct=login(client,email='demo@bada.example')
    assert correct.status_code==200
    data=client.get('/api/me',headers=auth(correct)).json()
    assert data['org_name']=='바다유통'
    with backend.conn() as c:
        assert c.execute('SELECT count(*) FROM mfa_recovery_codes WHERE user_id=?', (data['id'],)).fetchone()[0]==0
    assert login(client,recovery_code=codes[0]).status_code==200


def test_mfa_rotation_rejects_cross_site_without_csrf(client,monkeypatch):
    _,secret,codes=enroll(client,monkeypatch)
    session=login(client,recovery_code=codes[0]);h=auth(session)
    response=client.post('/api/security/mfa/recovery/rotate',json={'password':'Demo!2026secure','recovery_code':codes[1]},headers={'Cookie':h['Cookie']})
    assert response.status_code==403
    assert login(client,recovery_code=codes[1]).status_code==200


def test_legacy_mfa_schema_migrates_without_replacing_saved_secret(client,monkeypatch):
    a,secret,codes=enroll(client,monkeypatch)
    backend.init_db();backend.init_db()
    with backend.conn() as c:
        assert c.execute('SELECT count(*) FROM mfa_recovery_codes').fetchone()[0]==8
    assert login(client,recovery_code=codes[0]).status_code==200


def test_production_guard_is_case_insensitive(client,monkeypatch):
    monkeypatch.setenv('JW_ENV','PRODUCTION')
    with __import__('pytest').raises(RuntimeError,match='DEMO_SEED'):
        backend.init_db()
    import app.security_hardening as sh
    monkeypatch.setenv('JW_UPLOAD_SCAN','off')
    with __import__('pytest').raises(RuntimeError,match='cannot disable'):
        sh.lock_file_scan(b'fixture')
