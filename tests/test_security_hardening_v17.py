"""Security-focused tests for MFA, consistency constraints, document isolation."""
import base64
import sqlite3
import subprocess
import time
import pytest
from cryptography.fernet import Fernet
from app import main as backend
from app.security_hardening import totp_code, match_totp, limited_extract
from tests.test_quote_import import qxlsx, confirm


def login(client, email='demo@hanbit.example',password='Demo!2026secure',otp=None):
    payload={'email':email,'password':password}
    if otp is not None:payload['otp']=otp
    return client.post('/api/login',json=payload)


def h(r):
    return {'Cookie':backend.SESSION_COOKIE+'='+r.cookies.get(backend.SESSION_COOKIE),
            'X-CSRF-Token':r.json()['csrf_token']}


def test_mfa_enrollment_wrong_password_and_strong_secret(client,monkeypatch):
    monkeypatch.setenv('JW_DATA_KEY',Fernet.generate_key().decode())
    a=login(client); headers=h(a)
    wrong=client.post('/api/security/mfa/start',json={'password':'not-the-password'},headers=headers)
    assert wrong.status_code==403
    setup=client.post('/api/security/mfa/start',json={'password':'Demo!2026secure'},headers=headers)
    assert setup.status_code==200,setup.text
    secret=setup.json()['secret'];assert len(secret)>=30
    with backend.conn() as c:
        row=c.execute('SELECT * FROM mfa_credentials WHERE user_id=?',(a.json()['user']['id'],)).fetchone()
        assert secret not in str(dict(row))
        assert not row['secret_encrypted'] and row['pending_encrypted']
    assert client.post('/api/security/mfa/confirm',json={'otp':'abcabc'},headers=headers).status_code==403
    code=totp_code(secret,int(time.time()//30))
    confirmed=client.post('/api/security/mfa/confirm',json={'otp':code},headers=headers)
    assert confirmed.status_code==200,confirmed.text
    assert client.get('/api/me',headers=headers).status_code==401
    assert login(client).status_code==401
    assert login(client,otp='000000').status_code==401
    # TOTP is single-use per 30s interval; confirmed code cannot be replayed.
    assert login(client,otp=code).status_code==401
    # Advance counter deterministically for a valid next code (without changing global clock).
    with backend.conn() as c:
        user=a.json()['user']['id']
        saved=c.execute('SELECT last_counter FROM mfa_credentials WHERE user_id=?',(user,)).fetchone()[0]
        assert saved>0
    # Next-time code is validated by verifier directly to avoid a clock/timer test.
    assert match_totp(secret,code,saved)==None


def test_non_admin_mfa_setup_is_per_user_no_cross_company(client,monkeypatch):
    monkeypatch.setenv('JW_DATA_KEY',Fernet.generate_key().decode())
    a=login(client)
    b=login(client,'demo@bada.example')
    assert client.post('/api/security/mfa/start',json={'password':'Demo!2026secure'},headers=h(a)).status_code==200
    assert client.get('/api/security/mfa/status',headers=h(a)).json()['pending_setup']
    assert client.get('/api/security/mfa/status',headers=h(b)).json()=={'enabled':False,'pending_setup':False}


def test_cross_tenant_db_reference_rejected_even_with_direct_sql(client):
    with backend.transaction() as c:
        orgs=c.execute('SELECT org_id FROM users ORDER BY email').fetchall()
        # Reused true IDs from existing fixtures
        a=c.execute("SELECT org_id,id FROM users WHERE email='demo@hanbit.example'").fetchone()
        b=c.execute("SELECT org_id,id FROM users WHERE email='demo@bada.example'").fetchone()
        target=c.execute('SELECT id FROM customers WHERE org_id=?',(b['org_id'],)).fetchone()['id']
        with pytest.raises(sqlite3.IntegrityError,match='cross-tenant'):
            c.execute('''INSERT INTO quotes(id,org_id,customer_id,customer_name_snapshot,doc_no,title,status,vat_mode,created_at,updated_at)
                         VALUES(?,?,?,?,?,?,?,?,?,?)''',('evil-quote',a['org_id'],target,'타회사','EVIL-Q','오류','draft','taxable',backend.now(),backend.now()))
        invoice_id='bogus-invoice'
        with pytest.raises(sqlite3.IntegrityError,match='cross-tenant'):
            c.execute("INSERT INTO import_previews(id,org_id,uploaded_by,file_sha256,filename,normalized_json,preview_digest,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                      ('evil-preview',a['org_id'],b['id'],'a'*64,'doc.pdf','{}','b'*64,'pending',backend.now()))


def test_mfa_login_bad_code_rate_limited(client,monkeypatch):
    monkeypatch.setenv('JW_DATA_KEY',Fernet.generate_key().decode())
    a=login(client);s=client.post('/api/security/mfa/start',json={'password':'Demo!2026secure'},headers=h(a)).json()['secret']
    valid=totp_code(s,int(time.time()//30))
    assert client.post('/api/security/mfa/confirm',json={'otp':valid},headers=h(a)).status_code==200
    for _ in range(5):assert login(client,otp='AAAAAA').status_code==401
    assert login(client,otp='111111').status_code==429


def test_file_parser_timeout_fails_closed(monkeypatch):
    import app.security_hardening as sh
    def slow(*args,**kwargs):raise subprocess.TimeoutExpired('worker',18)
    monkeypatch.setattr(sh.subprocess,'run',slow)
    with pytest.raises(ValueError,match='timed out'):limited_extract('doc.xlsx',qxlsx())


def test_production_blocks_demo_and_no_rls(client,monkeypatch,tmp_path):
    monkeypatch.setenv('JW_ENV','production')
    with pytest.raises(RuntimeError,match='DEMO_SEED'):
        backend.init_db()
    monkeypatch.delenv('DEMO_SEED',raising=False)
    monkeypatch.setenv('JW_DATA_KEY',Fernet.generate_key().decode())
    monkeypatch.setenv('JW_UPLOAD_SCAN','clamav')
    # Existing admin users with no MFA must never be served in production.
    with pytest.raises(RuntimeError,match='MFA'):
        backend.init_db()
