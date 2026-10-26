from pathlib import Path
import pytest
from scripts.install_v60 import proposed,run

GOOD='''from .security_hardening import data_cipher\nfrom fastapi import FastAPI\nasync def lifespan(_app: FastAPI):\n    init_db()\n    yield\nregister_messenger_routes(app, current_user=current_user)\n\n@app.get('/')\ndef index():\n    pass\n'''


def test_check_then_apply_is_idempotent(tmp_path):
    root=tmp_path;(root/'app').mkdir()
    (root/'app/main.py').write_text(GOOD)
    (root/'app/automation_v60.py').write_text('def placeholder(): pass\n')
    assert run(root,apply=False)=='PATCH_READY_NOT_APPLIED'
    assert (root/'app/main.py').read_text()==GOOD
    assert run(root,apply=True)=='PATCH_INSTALLED_LOCAL_ONLY'
    after=(root/'app/main.py').read_text()
    assert 'register_automation_routes(app' in after
    assert 'install_automation_schema(conn)' in after
    assert run(root,apply=True)=='ALREADY_INSTALLED'
    assert after==(root/'app/main.py').read_text()


def test_fails_closed_on_unexpected_source(tmp_path):
    root=tmp_path;(root/'app').mkdir()
    (root/'app/main.py').write_text('other code\n')
    (root/'app/automation_v60.py').write_text('ok=True')
    with pytest.raises(RuntimeError):run(root,apply=True)
    assert (root/'app/main.py').read_text()=='other code\n'


def test_partial_patch_refused():
    with pytest.raises(RuntimeError): proposed(GOOD+'\nfrom .automation_v60 import install_schema as install_automation_schema, register_routes as register_automation_routes\n')
