"""Generate a non-sensitive synthetic PG cutover gap inventory; never load customer data."""
from __future__ import annotations
import json
import os
from pathlib import Path
import tempfile
from fastapi.testclient import TestClient
from app import main
from app.ops_cutover_v71 import schema_inventory


def run():
    if os.environ.get('JW_ENV','').lower() in ('production','prod'):
        raise RuntimeError('Production cutover inspection via synthetic CLI forbidden')
    saved=main.DB_PATH;oldseed=os.environ.get('DEMO_SEED')
    with tempfile.TemporaryDirectory(prefix='jw-v71-compat-') as td:
        main.DB_PATH=Path(td)/'synthetic.db';os.environ['DEMO_SEED']='1'
        try:
            with TestClient(main.app):
                with main.conn() as c:
                    ref=(Path(__file__).resolve().parents[1]/'security/pg_rls_test_fixture.sql').read_text()
                    return schema_inventory(c,ref)
        finally:
            main.DB_PATH=saved
            if oldseed is None:os.environ.pop('DEMO_SEED',None)
            else:os.environ['DEMO_SEED']=oldseed

if __name__=='__main__':print(json.dumps(run(),ensure_ascii=False,indent=2))
