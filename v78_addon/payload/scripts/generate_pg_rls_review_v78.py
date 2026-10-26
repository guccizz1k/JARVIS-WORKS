"""Generate 35-table synthetic-only PostgreSQL RLS draft for offline audit.

Never connects to or modifies a PostgreSQL database. No live database path used.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import json
import os
import tempfile
from fastapi.testclient import TestClient
from app import main
from app.pg_rls_full_review_v78 import generate_lab_sql, schema_contract


def run() -> tuple[str, dict]:
    if os.environ.get('JW_ENV','').strip().lower() in {'prod','production'}:
        raise RuntimeError('Production RLS review generation prohibited')
    prior = main.DB_PATH
    seed = os.environ.get('DEMO_SEED')
    try:
        with tempfile.TemporaryDirectory(prefix='jw-v78-rls-draft-') as td:
            main.DB_PATH=Path(td)/'synthetic.db'
            os.environ['DEMO_SEED']='0'
            with TestClient(main.app):
                with main.conn() as c:
                    return generate_lab_sql(c), schema_contract(c)
    finally:
        main.DB_PATH=prior
        if seed is None:
            os.environ.pop('DEMO_SEED',None)
        else:
            os.environ['DEMO_SEED']=seed


if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Offline SQL review only; never execute on production')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    sql, stats=run()
    if args.output.is_symlink():
        raise RuntimeError('Refusing to overwrite symlink')
    args.output.write_text(sql,encoding='utf-8')
    print(json.dumps(stats,ensure_ascii=False,indent=2))
