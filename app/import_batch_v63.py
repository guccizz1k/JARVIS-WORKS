"""V6.3: atomic, explicit-review multi-file preview for *supported* business documents.

Every untrusted file is parsed by the pre-existing restricted subprocess parser.
Never store the original bytes or promote a document to a business record on upload.
Actual photo OCR, unstructured documents, and legal invoices are NOT supported.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated

from fastapi import Depends, File, UploadFile
from .import_engine import DocumentError, MAX_FILE_SIZE
from .security_hardening import limited_extract, sealed_json, unseal_json

MAX_BATCH_FILES = 8
MAX_BATCH_BYTES = 20 * 1024 * 1024


def _facts(doc):
    return {k: v for k, v in doc.items() if k not in
            ('filename', 'format', 'user_filled_fields', 'missing_fields')}


def register_routes(app, *, current_user, transaction, ident, now, audit,
                    fail, match_import_customer, import_preview_response):
    @app.post('/api/imports/batch/preview', status_code=201)
    async def preview_batch(files: Annotated[list[UploadFile], File()], user=Depends(current_user)):
        # All-or-nothing: parse every file before writing, then save in one transaction.
        if not 1 <= len(files) <= MAX_BATCH_FILES:
            fail(f'한 번에 1~{MAX_BATCH_FILES}개 파일만 처리할 수 있습니다', 422)
        accepted = []
        total = 0
        for index, file in enumerate(files, 1):
            filename = Path(file.filename or '').name
            suffix = Path(filename).suffix.lower()
            if suffix not in ('.pdf', '.xlsx'):
                fail(f'{index}번 파일: 현재는 정형 PDF·XLSX만 지원합니다. 사진 OCR은 개발 중입니다', 422)
            try:
                raw = await file.read(MAX_FILE_SIZE + 1)
            finally:
                await file.close()
            total += len(raw)
            if not raw or len(raw) > MAX_FILE_SIZE or total > MAX_BATCH_BYTES:
                fail(f'{index}번 파일: 파일당 5MB, 묶음당 20MB 제한을 초과했습니다', 413)
            checksum = hashlib.sha256(raw).hexdigest()
            if any(previous['checksum'] == checksum for previous in accepted):
                fail(f'{index}번 파일: 동일 파일이 묶음에 중복 포함되어 있습니다', 409)
            try:
                doc = limited_extract(filename, raw)
            except (DocumentError, ValueError) as exc:
                fail(f'{index}번 파일 분석 실패: {exc}', 422)
            except RuntimeError:
                fail(f'{index}번 파일의 보안 검사를 완료하지 못했습니다', 503)
            if any(_facts(previous['doc']) == _facts(doc) for previous in accepted):
                fail(f'{index}번 파일: 동일 거래 내용이 묶음에 중복 포함되어 있습니다', 409)
            digest = hashlib.sha256(json.dumps(doc, ensure_ascii=False, sort_keys=True,
                                                separators=(',', ':')).encode('utf-8')).hexdigest()
            accepted.append({'checksum': checksum, 'doc': doc, 'digest': digest})
        batch_id = ident()
        with transaction() as c:
            # The database enforces a second per-tenant uniqueness check at approval.
            # Staged records remain pending; no transaction/order/quote is created here.
            confirmed = [unseal_json(row['normalized_json']) for row in c.execute(
                "SELECT normalized_json FROM import_previews WHERE org_id=? AND status='confirmed'",
                (user['org_id'],)).fetchall()]
            results = []
            for index, item in enumerate(accepted, 1):
                doc = item['doc']
                if c.execute('''SELECT 1 FROM import_previews WHERE org_id=?
                                AND file_sha256=? AND status='confirmed' LIMIT 1''',
                             (user['org_id'], item['checksum'])).fetchone():
                    fail(f'{index}번 파일: 이미 승인된 동일 파일입니다', 409)
                if any(_facts(prev) == _facts(doc) for prev in confirmed):
                    fail(f'{index}번 파일: 이미 승인된 동일 거래 내용입니다', 409)
                existing = match_import_customer(c, user['org_id'], doc)
                preview_id = ident()
                c.execute('''INSERT INTO import_previews
                    (id,org_id,uploaded_by,file_sha256,filename,normalized_json,
                     preview_digest,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)''',
                    (preview_id, user['org_id'], user['id'], item['checksum'],
                     doc['filename'], sealed_json(doc), item['digest'], 'pending', now()))
                audit(c, user, 'document_import', preview_id, 'batch_preview',
                      {'batch_id': batch_id, 'index': index, 'record_type': doc['record_type'],
                       'file_format': doc['format'], 'items': doc['item_count']})
                results.append(import_preview_response(doc, preview_id, item['digest'], existing))
        return {'batch_id': batch_id, 'staged_count': len(results),
                'previews': results, 'confirmation_required': True,
                'transaction_records_created': 0, 'original_files_saved': False}
