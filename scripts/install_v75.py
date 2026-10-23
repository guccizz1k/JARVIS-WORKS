"""Incremental review-only V7.0->V7.5 overlay; no remote/network operations.

No production, symlink, unknown baseline, or modified target is allowed.
Preflight is all-files before writing; rollback on caught write failures.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

BASE_SHA='06dcb206a49e3d728ddff3a7154cc7c37ac36bcf867a73d4539ea172cdbca210'
BASE_QUALITY_SHA='fcd94ae85a7fdc7ab3b7e6decfa8e90299f235a867a152fd6498619b827a7920'


def sha(data):return hashlib.sha256(data).hexdigest()


def run(root:Path,bundle:Path,*,apply:bool=False,inject_failure_after:int|None=None):
    if os.environ.get('JW_ENV','').strip().lower() in ('production','prod'):
        raise RuntimeError('BLOCKED: production apply/check forbidden')
    if not root.exists() or root.is_symlink() or not root.is_dir():
        raise RuntimeError('BLOCKED: invalid root')
    root=root.resolve(strict=True)
    bundle=bundle.resolve(strict=True)
    expected=json.loads((bundle/'PAYLOAD_SHA256.json').read_text())
    # This is an incremental patch; the complete V7.0 baseline must be present.
    baseline=root/'app/evidence_quality_v70.py'
    if baseline.is_symlink() or not baseline.is_file() or sha(baseline.read_bytes())!=BASE_QUALITY_SHA:
        raise RuntimeError('BLOCKED: not verified V7.0 baseline')
    staged=[]
    for rel,digest in expected.items():
        if Path(rel).is_absolute() or '..' in Path(rel).parts:
            raise RuntimeError('BLOCKED: unsafe patch path')
        source=bundle/'payload'/rel
        if not source.is_file() or source.is_symlink():raise RuntimeError('BLOCKED: payload missing/symlink '+rel)
        content=source.read_bytes()
        if sha(content)!=digest:raise RuntimeError('BLOCKED: payload SHA256 mismatch '+rel)
        dest=root/rel
        if not dest.parent.is_dir():raise RuntimeError('BLOCKED: missing destination directory '+rel)
        parent=dest.parent
        while parent!=root:
            if parent.is_symlink():raise RuntimeError('BLOCKED: symlink parent '+rel)
            parent=parent.parent
        if dest.is_symlink():raise RuntimeError('BLOCKED: symlink target '+rel)
        old=dest.read_bytes() if dest.is_file() else None
        if old==content:continue
        if rel=='app/main.py':
            if old is None or sha(old)!=BASE_SHA:raise RuntimeError('BLOCKED: main.py is not V7.0 original')
        elif old is not None:
            raise RuntimeError('BLOCKED: unrecognized existing add-on '+rel)
        mode=(dest.stat().st_mode & 0o777) if old is not None else 0o644
        staged.append((dest,content,old,mode))
    if not apply:return {'status':'CHECK_OK','planned_files':len(staged)}
    if inject_failure_after is not None and (
        os.environ.get('JW_INSTALL_TEST_MODE')!='ONLY_SYNTHETIC' or inject_failure_after<1):
        raise RuntimeError('BLOCKED: fault injection not authorized')
    temporary=[];done=[]
    try:
        for dest,content,old,mode in staged:
            fd,tmp=tempfile.mkstemp(dir=str(dest.parent),prefix='.jw-v75-',suffix='.tmp')
            os.fchmod(fd,mode)
            temporary.append(Path(tmp))
            with os.fdopen(fd,'wb') as f:
                f.write(content);f.flush();os.fsync(f.fileno())
        for i,(dest,content,old,mode) in enumerate(staged,1):
            os.replace(temporary[i-1],dest)
            done.append((dest,old,mode))
            if inject_failure_after==i:raise RuntimeError('INJECTED_FAILURE')
        return {'status':'APPLIED','changed_files':len(staged)}
    except BaseException:
        for dest,old,mode in reversed(done):
            if old is None:dest.unlink(missing_ok=True)
            else:
                fd,tmp=tempfile.mkstemp(dir=str(dest.parent),prefix='.jw-rollback-',suffix='.tmp')
                os.fchmod(fd,mode)
                with os.fdopen(fd,'wb') as f:
                    f.write(old);f.flush();os.fsync(f.fileno())
                os.replace(tmp,dest)
        raise
    finally:
        for file in temporary:file.unlink(missing_ok=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description='V7.5 local engineering review patch, not production')
    parser.add_argument('--root',required=True,type=Path)
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--check',action='store_true');modes.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    try:
        print(json.dumps(run(args.root,Path(__file__).resolve().parent,apply=args.apply)))
    except Exception as exc:
        print('FAIL:',exc)
        raise SystemExit(1)
