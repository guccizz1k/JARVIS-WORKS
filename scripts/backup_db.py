"""Create a consistent SQLite backup. The destination must be managed securely."""
from __future__ import annotations
import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT=Path(__file__).resolve().parents[1]
source=Path(os.environ.get('JARVIS_DB_PATH', ROOT/'data'/'works.db'))
target_dir=Path(os.environ.get('JARVIS_BACKUP_DIR', ROOT/'backups'))

def backup():
    if not source.is_file():
        raise FileNotFoundError(f'데이터베이스 파일이 없습니다: {source}')
    target_dir.mkdir(parents=True,exist_ok=True)
    timestamp=datetime.now(ZoneInfo('Asia/Seoul')).strftime('%Y%m%d_%H%M%S_%f')
    target=target_dir/f'works_{timestamp}.sqlite3'
    fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    os.close(fd)
    try:
        with sqlite3.connect(f'file:{source}?mode=ro',uri=True) as src, sqlite3.connect(target) as dest:
            src.backup(dest)
            if dest.execute('PRAGMA integrity_check').fetchone()[0]!='ok':
                raise ValueError('백업 데이터 무결성 검사 실패')
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return target

if __name__=='__main__':
    try: print(backup())
    except Exception as ex: print(f'백업 실패: {ex}',file=sys.stderr);raise SystemExit(1)
