"""Authentication regressions: exact password bytes and secure cookie removal."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app import pg_auth_v85 as auth
from tests.test_pg_auth_v85 import prepared, make_hash


@pytest.mark.parametrize('password', [' testpass', 'testpass ', '\ttestpass\n', ' 비밀번호 '])
def test_password_whitespace_is_preserved(password):
    payload = auth.LoginPayload(email=' valid@EXAMPLE.com ', password=password)
    assert payload.password == password
    assert payload.email == 'valid@EXAMPLE.com'


def test_spaced_password_hash_can_authenticate(prepared):
    row = list(prepared.cur.candidate)
    row[2] = make_hash(' testpass ')
    prepared.cur.candidate = tuple(row)
    token, _, _ = auth.login_session(auth.LoginPayload(email='valid@example.com', password=' testpass '))
    assert token


def test_password_with_added_spaces_is_not_same_secret(prepared):
    with pytest.raises(Exception) as exc:
        auth.login_session(auth.LoginPayload(email='valid@example.com', password=' testpass '))
    assert exc.value.status_code == 401


def test_logout_deletion_obeys_host_cookie_contract(prepared):
    app = FastAPI()
    auth.register_v85_auth(app)
    client = TestClient(app, base_url='https://testserver')
    login = client.post(auth.AUTH_PREFIX + '/login', json={'email':'valid@example.com','password':'testpass'})
    assert login.status_code == 200
    result = client.post(auth.AUTH_PREFIX + '/logout', headers={'X-CSRF-Token':login.json()['csrf_token']})
    assert result.status_code == 200
    cookie = result.headers['set-cookie']
    assert 'Max-Age=0' in cookie and 'Path=/' in cookie
    assert 'Secure' in cookie and 'HttpOnly' in cookie and 'SameSite=strict' in cookie
    assert 'Domain=' not in cookie
