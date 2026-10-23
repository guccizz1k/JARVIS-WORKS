"""Install *additive* V7.9 lab review tools onto a verified V7.8 DEV copy.

No existing project files are replaced. Not intended for production rollout.
The hash manifest detects accidental corruption, not a malicious resigning adversary.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile


class InstallBlocked(RuntimeError):
    pass


def sha(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        while data:=f.read(1024*1024): h.update(data)
    return h.hexdigest()


def safe_path(root: Path, relative: str, exists=True) -> Path:
    p=Path(relative)
    if p.is_absolute() or not p.parts or any(s in ('..','.') for s in p.parts) or '\\' in relative:
        raise InstallBlocked('Unsafe relative path')
    target=root/p
    for parent in (root,*[root.joinpath(*p.parts[:i]) for i in range(1,len(p.parts)+1)]):
        if parent.is_symlink():raise InstallBlocked('Symlink in target path')
    if exists and (not target.is_file() or not target.exists()):
        raise InstallBlocked('Required baseline file missing: '+relative)
    return target


def plan(root:Path,bundle:Path):
    if os.environ.get('JW_ENV','').strip().lower() in ('production','prod'):
        raise InstallBlocked('Deployment forbidden in production')
    if not root.is_dir() or root.is_symlink() or not bundle.is_dir() or bundle.is_symlink():
        raise InstallBlocked('Development root and overlay must be real directories')
    base=json.loads((bundle/'BASE_SHA256.json').read_text('utf-8'))
    payload=json.loads((bundle/'PAYLOAD_SHA256.json').read_text('utf-8'))
    if not isinstance(base,dict) or not isinstance(payload,dict) or len(base)<4 or len(payload)!=4:
        raise InstallBlocked('Unexpected overlay manifest')
    for name,want in base.items():
        file=safe_path(root,name)
        if sha(file)!=want:raise InstallBlocked('V7.8 baseline hash mismatch: '+name)
    actions=[]
    for name,want in payload.items():
        source=safe_path(bundle/'payload',name)
        if sha(source)!=want:raise InstallBlocked('Overlay payload hash mismatch: '+name)
        target=safe_path(root,name,exists=False)
        if target.exists():
            if not target.is_file() or sha(target)!=want:
                raise InstallBlocked('Refusing to overwrite existing file: '+name)
        else:
            actions.append((name,source,target))
    return actions


def install(root:Path,bundle:Path,apply=False):
    root,bundle=Path(root),Path(bundle)
    actions=plan(root,bundle)
    if not apply:return {'status':'CHECK','changes':len(actions)}
    created=[]
    try:
        with tempfile.TemporaryDirectory(prefix='.jw-v79-',dir=root) as td:
            tmp=Path(td)
            for index,(name,source,target) in enumerate(actions):
                staged=tmp/str(index)
                shutil.copyfile(source,staged)
                if sha(staged)!=sha(source):raise InstallBlocked('Staged file changed')
            for index,(name,source,target) in enumerate(actions):
                # Re-validate to fail closed if another process changed the root.
                if target.exists() or target.is_symlink():raise InstallBlocked('Concurrent change detected')
                target.parent.mkdir(parents=True,exist_ok=True)
                if target.parent.is_symlink():raise InstallBlocked('Unsafe new parent directory')
                os.replace(tmp/str(index),target)
                created.append(target)
        return {'status':'APPLIED','changes':len(created)}
    except Exception:
        for path in reversed(created):
            try:path.unlink(missing_ok=True)
            except OSError:pass
        raise


def main():
    p=argparse.ArgumentParser(description='V7.9 additive review overlay, DEV only')
    p.add_argument('--root',type=Path,required=True)
    p.add_argument('--bundle',type=Path,required=True)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--check',action='store_true')
    group.add_argument('--apply',action='store_true')
    args=p.parse_args()
    print(json.dumps(install(args.root,args.bundle,apply=args.apply),ensure_ascii=False))

if __name__=='__main__':main()
