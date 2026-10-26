"""Fail-closed installer for JARVIS WORKS V6.0 review candidate.

Usage (from repo root, after copying bundle files):
  python scripts/install_v60.py --check
  python scripts/install_v60.py --apply
Writes only app/main.py; no remote git operations, migrations run at app startup.
"""
from __future__ import annotations
import argparse
import ast
import os
import tempfile
from pathlib import Path

IMPORT = 'from .automation_v60 import install_schema as install_automation_schema, register_routes as register_automation_routes'
LIFESPAN_ANCHOR = 'async def lifespan(_app: FastAPI):\n    init_db()\n'
LIFESPAN_NEW = LIFESPAN_ANCHOR + '    install_automation_schema(conn)\n'
ROUTES = """\nregister_automation_routes(app, conn=conn, transaction=transaction,\n    current_user=current_user, get_row=get_row, retrieve_items=retrieve_items,\n    money=money, audit=audit, ident=ident, now=now, fail=fail)\n"""


def proposed(source: str) -> str:
    if IMPORT in source or 'register_automation_routes(app' in source:
        if IMPORT in source and 'register_automation_routes(app' in source and 'install_automation_schema(conn)' in source:
            return source
        raise RuntimeError('Inconsistent partial installation; refuse to overwrite')
    import_anchor = 'from .security_hardening import '
    if source.count(import_anchor) != 1:
        raise RuntimeError('Expected security import not found exactly once')
    index = source.index('\n', source.index(import_anchor))
    source = source[:index+1] + IMPORT + '\n' + source[index+1:]
    if source.count(LIFESPAN_ANCHOR) != 1:
        raise RuntimeError('Expected lifespan anchor missing or ambiguous')
    source = source.replace(LIFESPAN_ANCHOR, LIFESPAN_NEW, 1)
    reg = 'register_messenger_routes(app, '
    route_anchor = "\n\n@app.get('/')"
    if source.count(reg) != 1 or source.count(route_anchor) != 1:
        raise RuntimeError('Expected route registration anchor missing or ambiguous')
    source = source.replace(route_anchor, '\n' + ROUTES + route_anchor, 1)
    ast.parse(source, filename='app/main.py')
    return source


def run(root: Path, *, apply: bool) -> str:
    file = root / 'app' / 'main.py'
    module = root / 'app' / 'automation_v60.py'
    if not file.is_file() or not module.is_file():
        raise RuntimeError('Expected app/main.py and app/automation_v60.py')
    orig = file.read_text(encoding='utf-8')
    new = proposed(orig)
    ast.parse(module.read_text(encoding='utf-8'), filename=str(module))
    if new == orig:
        return 'ALREADY_INSTALLED'
    if not apply:
        return 'PATCH_READY_NOT_APPLIED'
    fd, name = tempfile.mkstemp(prefix='.main-v60-',dir=file.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as out:
            out.write(new)
        os.chmod(name,file.stat().st_mode)
        os.replace(name,file)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    return 'PATCH_INSTALLED_LOCAL_ONLY'


if __name__ == '__main__':
    p=argparse.ArgumentParser()
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check',action='store_true')
    mode.add_argument('--apply',action='store_true')
    p.add_argument('--root',type=Path,default=Path.cwd())
    args=p.parse_args()
    try:
        print(run(args.root, apply=args.apply))
    except (RuntimeError, OSError, SyntaxError) as e:
        p.exit(2, f'BLOCKED: {e}\n')
