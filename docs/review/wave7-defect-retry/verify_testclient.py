"""Proposed CI-only compatibility gate; needs the exact remote dependencies."""
import importlib.metadata as md
import warnings
from starlette.exceptions import StarletteDeprecationWarning


def verify():
    if md.version('starlette') != '1.10.0' or md.version('httpx2') != '2.16.2':
        raise RuntimeError('WAVE7_TESTCLIENT_VERSION_MISMATCH')
    with warnings.catch_warnings():
        warnings.simplefilter('error', StarletteDeprecationWarning)
        from fastapi import FastAPI, Request
        from fastapi.testclient import TestClient
        import starlette.testclient as transport
        if transport.httpx.__name__ != 'httpx2':
            raise RuntimeError('WAVE7_TESTCLIENT_BACKEND_MISMATCH')
        app=FastAPI()
        @app.post('/fixture')
        def read(request:Request):
            return {'https':request.url.scheme=='https', 'cookie':request.cookies.get('__Host-jw_session')=='fixture', 'origin':request.headers.get('origin')=='https://testserver'}
        with TestClient(app,base_url='https://testserver') as c:
            c.cookies.set('__Host-jw_session','fixture')
            result=c.post('/fixture',headers={'origin':'https://testserver'})
            if result.status_code!=200 or result.json()!={'https':True,'cookie':True,'origin':True}:
                raise RuntimeError('WAVE7_TESTCLIENT_SMOKE_FAILED')
    print('WAVE7_TESTCLIENT_HTTPX2_WARNING_FREE_SMOKE_PASS')

if __name__=='__main__':verify()
