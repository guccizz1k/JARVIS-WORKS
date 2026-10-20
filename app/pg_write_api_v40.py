"""TestClient-only V4.0 write endpoint. Never included in production routes."""
from __future__ import annotations

import re

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.pg_messenger_review import PostgreSQLUnverified
from app.pg_write_replay_v40 import LabWriterV40, ReplayConflict


class SendText(BaseModel):
    model_config = ConfigDict(extra='forbid')
    content: str = Field(min_length=1, max_length=2000)
    request_id: str = Field(pattern=r'^[a-f0-9]{32}$')


def create_lab_app(dsn: str, *, writer=None) -> FastAPI:
    # The constructor rejects production hosts/DBs even before any request.
    writer = writer or LabWriterV40(dsn)
    app = FastAPI(title='JARVIS WORKS V4.0 private PG17 write test',
                  docs_url=None, redoc_url=None, openapi_url=None)

    @app.post('/lab40/threads/{thread}/messages')
    def send(thread: str, payload: SendText,
             x_jw_lab_session: str | None = Header(default=None)):
        if re.fullmatch(r'[a-zA-Z0-9_-]{1,100}', thread) is None:
            raise HTTPException(422, 'Invalid thread identifier')
        if not isinstance(x_jw_lab_session, str) or not 40 <= len(x_jw_lab_session) <= 512:
            raise HTTPException(401, 'Verified synthetic session required')
        try:
            result = writer.send_text(token=x_jw_lab_session, thread=thread,
                                      content=payload.content, request_id=payload.request_id)
            return JSONResponse(status_code=200 if result['replayed'] else 201, content=result,
                                headers={'Cache-Control': 'no-store'})
        except ReplayConflict:
            raise HTTPException(409, 'Idempotency key conflicts with original request') from None
        except (ValueError, PostgreSQLUnverified):
            raise HTTPException(403, 'Synthetic request denied') from None
        except Exception:
            # No tenant IDs, SQL, token, DSN, or customer evidence in errors.
            raise HTTPException(503, 'Isolated test database request failed') from None
    return app
