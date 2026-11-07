#!/usr/bin/env python3
"""Report only the label of the last real isolated-restore mismatch.

Reads existing private evidence WITHOUT opening secret keys, decrypting backup,
running pg_restore, or connecting to any database. Never declares DR PASS.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import ci_cinema_pg_w as w
from scripts.pg_backup_v223 import BackupError

LABEL_PATTERN = re.compile(r"[A-Za-z0-9_:.?/-]{1,120}\\Z")

def read_report() -> dict:
    if os.environ.get("CODESPACES") != "true" or Path.cwd().resolve()!=w.ROOT.resolve():
        raise BackupError("BLOCKED_APPROVED_CODESPACE_REQUIRED")
    private=w.PRIVATE
    if not private.is_dir() or private.is_symlink():
        raise BackupError("BLOCKED_PRIVATE_BACKUP_DIRECTORY_MISSING")
    st=private.stat()
    if st.st_uid!=os.getuid() or st.st_mode&0o077:
        raise BackupError("BLOCKED_PRIVATE_BACKUP_DIRECTORY_UNSAFE")
    paths=[p for p in private.glob("*.restore-report.json")
           if p.is_file() and not p.is_symlink()]
    if len(paths)!=1:
        raise BackupError("BLOCKED_EXPECT_ONE_LOCAL_EVIDENCE_REPORT")
    p=paths[0]
    st=p.stat()
    if st.st_uid!=os.getuid() or st.st_mode&0o077 or st.st_size>16384:
        raise BackupError("BLOCKED_PRIVATE_EVIDENCE_PERMISSIONS_OR_SIZE")
    try:
        data=json.loads(p.read_text(encoding="utf-8"))
    except (OSError,ValueError,TypeError):
        raise BackupError("BLOCKED_PRIVATE_EVIDENCE_PARSE") from None
    if (not isinstance(data,dict) or data.get("source_real") is not True
        or data.get("verified_disposable_pg17") is not True
        or data.get("schema_fingerprint")!=w.FINGERPRINT
        or data.get("verdict")!="FAIL"
        or data.get("table_count")!=62
        or data.get("row_count")!=22
        or data.get("mismatch_count")!=1):
        raise BackupError("BLOCKED_EVIDENCE_UNEXPECTED_STATE")
    # The evidence must be bound to the exact encrypted archive saved privately.
    base=p.name.removesuffix(".restore-report.json")
    archive=private/(base+".jwpgbk")
    if not archive.is_file() or archive.is_symlink():
        raise BackupError("BLOCKED_BACKUP_ARCHIVE_MISSING")
    if w.sha256(archive)!=data.get("encrypted_archive_sha256"):
        raise BackupError("BLOCKED_EVIDENCE_ARCHIVE_DIGEST")
    labels=data.get("mismatch_labels")
    if (not isinstance(labels,list) or len(labels)!=1
        or not isinstance(labels[0],str) or not LABEL_PATTERN.fullmatch(labels[0])):
        raise BackupError("BLOCKED_MISMATCH_LABEL_NOT_SAFE")
    return {"mismatch":labels[0],"verdict":data["verdict"]}

def main()->int:
    try:
        report=read_report()
        print("REAL_RESTORE_VERDICT="+report["verdict"])
        print("ONE_MISMATCH_LABEL="+report["mismatch"])
        print("NO_SOURCE_CONNECTION_OR_RESTORE_ATTEMPTED=PASS")
        return 0
    except Exception as exc:
        code=str(exc) if isinstance(exc,BackupError) else "BLOCKED_"+type(exc).__name__
        if not code.startswith("BLOCKED_"):
            code="BLOCKED_EVIDENCE_REVIEW"
        print("RESTORE_REPORT_REVIEW="+code)
        return 2

if __name__=="__main__":
    sys.exit(main())
