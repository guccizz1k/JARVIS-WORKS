"""Authenticated, tenant-scoped profile and review UI preferences (V22.3).

Additive SQLite reference-backend tables. No changes to business ledger, roles,
existing users columns or production authorization policy. Review-only feature.
"""
from __future__ import annotations

import unicodedata
from fastapi import Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator


class StrictPayload(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)


class ProfileNameUpdate(StrictPayload):
    version: int = Field(ge=0, strict=True)
    name: str = Field(min_length=1, max_length=80)

    @field_validator('name')
    @classmethod
    def validate_name(cls, name):
        cleaned = unicodedata.normalize('NFC', name.strip())
        if not cleaned or len(cleaned) > 80 or any(unicodedata.category(ch) in ('Cc', 'Cf') for ch in cleaned):
            raise ValueError('Display name must be visible text (1–80 characters)')
        return cleaned


class PreferenceUpdate(StrictPayload):
    version: int = Field(ge=0, strict=True)
    compact_view: StrictBool
    messenger_auto_refresh: StrictBool


def install_schema(conn):
    with conn() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS jw_owner_profile_versions_v223 (
            user_id TEXT PRIMARY KEY REFERENCES users(id),
            org_id TEXT NOT NULL REFERENCES organizations(id),
            version INTEGER NOT NULL CHECK(version>=1),
            updated_at TEXT NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS jw_owner_preferences_v223 (
            user_id TEXT PRIMARY KEY REFERENCES users(id),
            org_id TEXT NOT NULL REFERENCES organizations(id),
            compact_view INTEGER NOT NULL CHECK(compact_view IN (0,1)),
            messenger_auto_refresh INTEGER NOT NULL CHECK(messenger_auto_refresh IN (0,1)),
            version INTEGER NOT NULL CHECK(version>=1),
            updated_at TEXT NOT NULL
        )""")


def register_routes(app, *, current_user, conn, transaction, now, audit, fail):
    def profile_row(db, user):
        row = db.execute("""SELECT u.id,u.org_id,u.email,u.name,u.role,o.name AS org_name,
            COALESCE(p.version,0) AS version FROM users u
            JOIN organizations o ON o.id=u.org_id
            LEFT JOIN jw_owner_profile_versions_v223 p
              ON p.user_id=u.id AND p.org_id=u.org_id
            WHERE u.id=? AND u.org_id=?""",(user['id'],user['org_id'])).fetchone()
        if row is None:
            fail('프로필을 찾을 수 없습니다',404)
        return dict(row)

    def preference_row(db, user):
        row = db.execute("""SELECT compact_view,messenger_auto_refresh,version FROM
            jw_owner_preferences_v223 WHERE user_id=? AND org_id=?""",
            (user['id'],user['org_id'])).fetchone()
        return {
            'user_id': user['id'], 'org_id': user['org_id'],
            'compact_view': bool(row['compact_view']) if row else False,
            'messenger_auto_refresh': bool(row['messenger_auto_refresh']) if row else True,
            'version': row['version'] if row else 0
        }

    @app.get('/api/account/profile')
    def get_profile(user=Depends(current_user)):
        with conn() as db:
            return profile_row(db,user)

    @app.post('/api/account/profile')
    def update_profile(body: ProfileNameUpdate, user=Depends(current_user)):
        with transaction() as db:
            old = profile_row(db,user)
            if old['version'] != body.version:
                fail('프로필이 변경되었습니다. 다시 조회하세요',409)
            if old['name'] != body.name:
                changed = db.execute('UPDATE users SET name=? WHERE id=? AND org_id=?',
                                     (body.name,user['id'],user['org_id'])).rowcount
                if changed != 1:
                    fail('프로필을 찾을 수 없습니다',404)
                version = old['version'] + 1
                db.execute("""INSERT INTO jw_owner_profile_versions_v223
                    (user_id,org_id,version,updated_at) VALUES(?,?,?,?)
                    ON CONFLICT(user_id) DO UPDATE SET
                    version=excluded.version,updated_at=excluded.updated_at
                    WHERE jw_owner_profile_versions_v223.org_id=excluded.org_id""",
                    (user['id'],user['org_id'],version,now()))
                audit(db,user,'profile',user['id'],'display_name_changed',{'version':version})
            return profile_row(db,user)

    @app.get('/api/account/preferences')
    def get_preferences(user=Depends(current_user)):
        with conn() as db:
            return preference_row(db,user)

    @app.post('/api/account/preferences')
    def update_preferences(body: PreferenceUpdate, user=Depends(current_user)):
        with transaction() as db:
            old = preference_row(db,user)
            if old['version'] != body.version:
                fail('설정이 변경되었습니다. 다시 조회하세요',409)
            if (old['compact_view'] != body.compact_view or
                    old['messenger_auto_refresh'] != body.messenger_auto_refresh):
                version = old['version'] + 1
                db.execute("""INSERT INTO jw_owner_preferences_v223
                    (user_id,org_id,compact_view,messenger_auto_refresh,version,updated_at)
                    VALUES(?,?,?,?,?,?)
                    ON CONFLICT(user_id) DO UPDATE SET
                    compact_view=excluded.compact_view,
                    messenger_auto_refresh=excluded.messenger_auto_refresh,
                    version=excluded.version,updated_at=excluded.updated_at
                    WHERE jw_owner_preferences_v223.org_id=excluded.org_id""",
                    (user['id'],user['org_id'],int(body.compact_view),
                     int(body.messenger_auto_refresh),version,now()))
                audit(db,user,'preferences',user['id'],'preferences_changed',{'version':version})
            return preference_row(db,user)
