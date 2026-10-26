"""Offline sample-only SQLite entire schema snapshot gate; aggregate-only output."""
from __future__ import annotations
import json
import os
from pathlib import Path
import tempfile
from fastapi.testclient import TestClient
from app import main
from app.pg_full_shadow_v76 import capture,summary


def run():
    if os.environ.get('JW_ENV','').lower() in ('production','prod'):
        raise RuntimeError('Synthetic snapshot forbidden in production')
    original=main.DB_PATH
    prior_seed=os.environ.get('DEMO_SEED')
    try:
        with tempfile.TemporaryDirectory(prefix='jw-v76-shadow-synthetic-') as td:
            main.DB_PATH=Path(td)/'synthetic.db'
            os.environ['DEMO_SEED']='1'
            with TestClient(main.app):
                with main.conn() as c:
                    return {**summary(capture(c)), 'data_source':'synthetic_demo_only'}
    finally:
        main.DB_PATH=original
        if prior_seed is None:os.environ.pop('DEMO_SEED',None)
        else:os.environ['DEMO_SEED']=prior_seed


if __name__=='__main__':
    print(json.dumps(run(),ensure_ascii=False,indent=2))
