import json
from pathlib import Path
from cryptography.fernet import Fernet
from app import main as backend
from tests.test_quote_import import qxlsx
from app.security_hardening import unseal_json


def test_import_evidence_encrypted_and_readable_with_key(api,monkeypatch):
    monkeypatch.setenv('JW_DATA_KEY',Fernet.generate_key().decode())
    doc=qxlsx()
    r=api.c.post('/api/imports/preview',files={'file':('quote.xlsx',doc)},headers=api.auth)
    assert r.status_code==201,r.text
    p=r.json()
    with backend.conn() as c:
        stored=c.execute('SELECT normalized_json FROM import_previews WHERE id=?',(p['id'],)).fetchone()[0]
        assert stored.startswith('ENC1:') and '신규견적사' not in stored
        assert unseal_json(stored)['company']=='신규견적사'
    result=api.post('/imports/'+p['id']+'/confirm',{
        'preview_digest':p['digest'],'confirmed_customer':p['document']['company'],
        'confirmed_quote_date':p['document']['quote_date'],
        'confirmed_total':p['document']['money']['total'],'approve':True})
    assert result.status_code==201,result.text
    with backend.conn() as c:
        info=c.execute('SELECT source_document_meta FROM quotes WHERE source_import_id=?',(p['id'],)).fetchone()[0]
        assert info.startswith('ENC1:')
        assert unseal_json(info)['company']=='신규견적사'
    # Distinct file bytes but same original document must not duplicate.
    r2=api.c.post('/api/imports/preview',files={'file':('quote.xlsx',doc)},headers=api.auth)
    assert r2.status_code==409


def test_explicit_migration_with_backup(api,monkeypatch,tmp_path):
    from scripts.migrate_evidence_encryption import migrate
    import sqlite3
    p=api.c.post('/api/imports/preview',files={'file':('q.xlsx',qxlsx())},headers=api.auth).json()
    monkeypatch.setenv('JW_DATA_KEY',Fernet.generate_key().decode())
    db=backend.DB_PATH
    bak=tmp_path/'before.db'
    count=migrate(db,bak)
    assert count>=1 and bak.exists()
    with sqlite3.connect(bak) as c:
        assert c.execute('SELECT normalized_json FROM import_previews WHERE id=?',(p['id'],)).fetchone()[0].startswith('{')
    with backend.conn() as c:
        enc=c.execute('SELECT normalized_json FROM import_previews WHERE id=?',(p['id'],)).fetchone()[0]
        assert enc.startswith('ENC1:')
    assert api.get('/imports/'+p['id']).status_code==200
    assert migrate_evidence_only_recheck(db,monkeypatch) == 0


def migrate_evidence_only_recheck(db,monkeypatch):
    from app.security_hardening import migrate_evidence_encryption
    with backend.transaction() as c:
        return migrate_evidence_encryption(c)
