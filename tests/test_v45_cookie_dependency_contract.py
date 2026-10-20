"""Regression for V4.5's real FastAPI synthetic cookie dependency.

Before the repair, Request was imported only inside run().  With
``from __future__ import annotations`` the FastAPI dependency compiler treated
``req: Request`` as an untyped query parameter; an unauthenticated request
returned HTTP 422 rather than the required HTTP 401.

This test extracts the actual (not duplicated) dependency definition from the
review gate, using the review gate's module-global annotation namespace.
It calls a real FastAPI TestClient; no PostgreSQL or customer data is used.
"""
from __future__ import annotations

import __future__
import ast
import importlib.util
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient


SOURCE = Path(__file__).resolve().parents[1] / 'scripts' / 'test_postgres_evidence_shadow_v45.py'


def _auth_from_real_runner():
    spec = importlib.util.spec_from_file_location('jw_v45_cookie_contract', SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.Request is Request, 'Request must resolve from the dependency module globals'
    run = next(n for n in ast.parse(SOURCE.read_text()).body
               if isinstance(n, ast.FunctionDef) and n.name == 'run')
    actual = next(n for n in ast.walk(run)
                  if isinstance(n, ast.FunctionDef) and n.name == 'website_cookie')
    # One AST node is the exact reviewed implementation.  ``cookie`` and
    # HTTPException normally come from run()'s closure; provide them as
    # synthetic fixtures in the extracted callable's globals.
    code = compile(ast.Module(body=[actual], type_ignores=[]), str(SOURCE), 'exec',
                   flags=__future__.annotations.compiler_flag, dont_inherit=True)
    token = 'synthetic-cookie-opaque-value-not-production'
    namespace = dict(vars(module), cookie=token, HTTPException=HTTPException)
    exec(code, namespace)
    auth = namespace['website_cookie']
    assert auth.__annotations__['req'] == 'Request'
    return auth, token


def _http_client():
    auth, token = _auth_from_real_runner()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get('/lab45/threads/{thread}/evidence')
    def evidence(thread: str, user=Depends(auth)):
        return {'org_id': user['org_id'], 'actor': user['id']}

    return TestClient(app, base_url='https://testserver'), token


def test_no_cookie_must_respond_401_not_422():
    client, _ = _http_client()
    with client:
        response = client.get('/lab45/threads/' + 'a' * 32 + '/evidence')
    assert response.status_code == 401, response.text
    assert 'cookie' in response.json()['detail'].lower()


def test_forged_auth_header_and_invalid_cookie_rejected():
    client, token = _http_client()
    path = '/lab45/threads/' + 'a' * 32 + '/evidence'
    with client:
        assert client.get(path, headers={'X-JW-Lab-Session': token}).status_code == 401
        client.cookies.set('jw_v45_synthetic_cookie', token + '-forged')
        assert client.get(path).status_code == 401


def test_verified_synthetic_cookie_allows_only_fixture_identity():
    client, token = _http_client()
    path = '/lab45/threads/' + 'a' * 32 + '/evidence'
    with client:
        client.cookies.set('jw_v45_synthetic_cookie', token)
        response = client.get(path)
        assert response.status_code == 200, response.text
        assert response.json() == {'org_id': 'tenant_a', 'actor': 'ua'}
        assert token not in response.text
        client.cookies.clear()
        assert client.get(path).status_code == 401


def test_no_public_web_routes_or_prod_storage_reconfigured():
    source = SOURCE.read_text()
    assert 'from fastapi import Request' in source.split('def run()', 1)[0]
    assert 'from fastapi import HTTPException, Request' not in source
    assert 'with TestClient(isolated,base_url=' in source
    assert "req.cookies.get('jw_v45_synthetic_cookie')!=cookie" in source
    assert 'from app.main import' not in source
