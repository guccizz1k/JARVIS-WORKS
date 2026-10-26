"""Compatibility entry point for the secure backup routine.

V1.8 SECURITY CHANGE: plaintext *.sqlite3 backups are no longer produced by
this script. Set a separate JW_BACKUP_KEY to create an authenticated, encrypted
*.jwbackup file. For restore, use scripts/secure_backup.py directly.
"""
try:
    from scripts.secure_backup import make_backup
except ModuleNotFoundError:
    from secure_backup import make_backup


def backup():
    return make_backup()


if __name__=='__main__':
    import sys
    try:
        print(backup())
    except Exception as exc:
        print('Encrypted backup failed: '+str(exc),file=sys.stderr)
        raise SystemExit(1)
