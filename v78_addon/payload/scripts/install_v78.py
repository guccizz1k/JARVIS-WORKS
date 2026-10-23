"""V7.7->V7.8 offline, guarded review overlay. NEVER a production installer.

Explicit SHA-256 allowlist; fails closed on unexpected changes; synthetic
failure injection checks best-effort rollback. Power-loss atomicity is NOT
promised. Remote repos, live services and customer data are never accessed.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile

class InstallBlocked(RuntimeError):
    pass


def _hash(path:Path):
    return sha256(path.read_bytes()).hexdigest()


def _target(root:Path, name:str):
    parts=Path(name).parts
    if not parts or Path(name).is_absolute() or any(x in ('..','.') for x in parts):
        raise InstallBlocked('Unsafe relative path')
    path=root
    for part in parts:
        path=path/part
        if path.is_symlink():
            raise InstallBlocked('Symlink target forbidden')
    if not path.parent.is_dir():
        raise InstallBlocked('Missing target directory')
    return path


def _read_manifest(path:Path):
    if not path.is_file() or path.is_symlink():
        raise InstallBlocked('Manifest missing or symlink')
    try:
        mapping=json.loads(path.read_text('utf8'))
    except (ValueError,UnicodeError) as exc:
        raise InstallBlocked('Malformed manifest') from exc
    if not isinstance(mapping,dict) or not mapping or any(
            not isinstance(key,str) or not isinstance(value,str) or len(value)!=64 or
            any(ch not in '0123456789abcdef' for ch in value)
            for key,value in mapping.items()):
        raise InstallBlocked('Invalid file manifest')
    return mapping


def inspect(root:Path,bundle:Path):
    if os.environ.get('JW_ENV','').strip().lower() in ('prod','production'):
        raise InstallBlocked('Production modification prohibited')
    if root.is_symlink() or not root.is_dir() or bundle.is_symlink() or not bundle.is_dir():
        raise InstallBlocked('Invalid review root or package')
    root=root.resolve(strict=True)
    bundle=bundle.resolve(strict=True)
    baseline=_read_manifest(bundle/'BASE_SHA256.json')
    payload=_read_manifest(bundle/'PAYLOAD_SHA256.json')
    installed=[]
    planned=[]
    for name,hashval in baseline.items():
        dest=_target(root,name)
        if not dest.is_file():
            raise InstallBlocked('Missing V7.7 source: '+name)
        if _hash(dest)!=hashval and not (name in payload and _hash(dest)==payload[name]):
            raise InstallBlocked('V7.7 baseline differs: '+name)
    for name,digest in payload.items():
        src=_target(bundle/'payload',name)
        if not src.is_file() or src.stat().st_size>2_000_000 or _hash(src)!=digest:
            raise InstallBlocked('Payload integrity failure: '+name)
        dest=_target(root,name)
        if dest.exists():
            if not dest.is_file():raise InstallBlocked('Target is not a file: '+name)
            found=_hash(dest)
            if found==digest:
                installed.append(name)
                continue
            if name not in baseline or found!=baseline[name]:
                raise InstallBlocked('Unexpected existing target: '+name)
        planned.append(name)
    return {'planned':planned,'installed':installed}


def apply(root:Path,bundle:Path,*,inject_failure_after:int|None=None):
    state=inspect(root,bundle)
    if inject_failure_after is not None and (
        os.environ.get('JW_INSTALL_TEST_MODE')!='SYNTHETIC_V78_ONLY' or
        not 1<=inject_failure_after<=len(state['planned'])):
        raise InstallBlocked('Failure injection requires isolated synthetic test')
    inserted=[]
    temporaries=[]
    try:
        for index,name in enumerate(state['planned'],1):
            dest=_target(root,name)
            original=dest.read_bytes() if dest.is_file() else None
            mode=dest.stat().st_mode & 0o777 if original is not None else 0o600
            body=(bundle/'payload'/name).read_bytes()
            fd,filename=tempfile.mkstemp(prefix='.jw-v78-',suffix='.tmp',dir=dest.parent)
            temporaries.append(Path(filename))
            with os.fdopen(fd,'wb') as file:
                os.fchmod(file.fileno(),mode)
                file.write(body);file.flush();os.fsync(file.fileno())
            # Reconfirm the old state immediately before replacement; cannot
            # promise multi-process atomicity without a higher-level lock.
            actual=dest.read_bytes() if dest.is_file() else None
            if actual!=original:
                raise InstallBlocked('Concurrent target change detected')
            os.replace(filename,dest)
            inserted.append((dest,original,mode))
            if inject_failure_after==index:
                raise InstallBlocked('INJECTED_FAILURE')
        if inspect(root,bundle)['planned']:
            raise InstallBlocked('Verification failed after patch')
        return {'changed':len(inserted),'unchanged':len(state['installed'])}
    except BaseException:
        for dest,original,mode in reversed(inserted):
            if original is None:
                dest.unlink(missing_ok=True)
            else:
                fd,tmp=tempfile.mkstemp(prefix='.jw-restore-',dir=dest.parent)
                with os.fdopen(fd,'wb') as f:
                    os.fchmod(f.fileno(),mode)
                    f.write(original);f.flush();os.fsync(f.fileno())
                os.replace(tmp,dest)
        raise
    finally:
        for tmp in temporaries:
            tmp.unlink(missing_ok=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description='V7.8 offline review, not production')
    p.add_argument('--root',required=True,type=Path)
    p.add_argument('--bundle',type=Path,default=Path(__file__).resolve().parent.parent/'v78_addon')
    action=p.add_mutually_exclusive_group(required=True)
    action.add_argument('--check',action='store_true')
    action.add_argument('--apply',action='store_true')
    opt=p.parse_args()
    try:
        print(json.dumps(inspect(opt.root,opt.bundle) if opt.check else apply(opt.root,opt.bundle),ensure_ascii=False))
    except (InstallBlocked,OSError) as exc:
        print('BLOCKED: '+str(exc))
        raise SystemExit(2)
