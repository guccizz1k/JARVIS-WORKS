"""JARVIS WORKS v1 – tenant isolated quotation-to-cash reference implementation.

All monetary amounts are integer KRW. The application is a locally runnable MVP,
not an externally audited production finance/accounting system.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import uuid
from contextlib import contextmanager, asynccontextmanager
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, HTTPException, Request, Response, UploadFile, File, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from .import_engine import extract, DocumentError, MAX_FILE_SIZE, supplement_review

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get('JARVIS_DB_PATH', str(ROOT.parent / 'data' / 'works.db')))
KST = ZoneInfo('Asia/Seoul')
MAX_ITEMS = 40
MAX_QTY = 100_000
MAX_PRICE = 1_000_000_000
SESSION_HOURS = 12
SESSION_COOKIE = '__Host-jw_session'
# HTTPS is required by default. Local HTTP mode is only for isolated demo/dev.
ALLOW_INSECURE_DEV = os.environ.get('JW_INSECURE_LOCAL_DEV') == '1'
if ALLOW_INSECURE_DEV:
    if os.environ.get('JW_ENV', '').lower() == 'production':
        raise RuntimeError('Insecure local dev cookies cannot be enabled in production')
    SESSION_COOKIE = 'jw_local_dev_session'
LOGIN_FAILURE_LIMIT = 5
LOGIN_WINDOW_MINUTES = 15


def now() -> str:
    return datetime.now(KST).isoformat(timespec='seconds')


def today() -> str:
    return datetime.now(KST).date().isoformat()


def ident() -> str:
    return uuid.uuid4().hex


def fail(message: str, code: int = 400):
    raise HTTPException(status_code=code, detail=message)


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), 260_000)
    return f'pbkdf2_sha256$260000${salt}${dk.hex()}'


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds, salt, digest = stored.split('$')
        if algo != 'pbkdf2_sha256':
            return False
        test = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(test, bytes.fromhex(digest))
    except (ValueError, TypeError):
        return False


@contextmanager
def conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys = ON')
    c.execute('PRAGMA busy_timeout = 10000')
    try:
        yield c
    finally:
        c.close()


@contextmanager
def transaction():
    with conn() as c:
        c.execute('BEGIN IMMEDIATE')
        try:
            yield c
            c.execute('COMMIT')
        except BaseException:
            c.execute('ROLLBACK')
            raise


SCHEMA = '''
CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id),
  email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','member')),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_failures (
  email TEXT PRIMARY KEY, attempts INTEGER NOT NULL, first_failed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
  expires_at TEXT NOT NULL, csrf_token TEXT NOT NULL DEFAULT '',
  id TEXT UNIQUE, created_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS customers (
  id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id),
  name TEXT NOT NULL, business_number TEXT NOT NULL DEFAULT '',
  contact_name TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '',
  phone TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
  UNIQUE(org_id, name)
);
CREATE INDEX IF NOT EXISTS idx_customers_org ON customers(org_id);
CREATE TABLE IF NOT EXISTS quotes (
  id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id),
  customer_id TEXT NOT NULL REFERENCES customers(id),
  customer_name_snapshot TEXT NOT NULL,
  doc_no TEXT NOT NULL, title TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('draft','sent','accepted','rejected')),
  vat_mode TEXT NOT NULL CHECK(vat_mode IN ('taxable','exempt')),
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE(org_id,doc_no)
);
CREATE TABLE IF NOT EXISTS quote_items (
  id TEXT PRIMARY KEY, quote_id TEXT NOT NULL REFERENCES quotes(id),
  name TEXT NOT NULL, quantity INTEGER NOT NULL CHECK(quantity > 0 AND quantity <= 100000),
  unit_price INTEGER NOT NULL CHECK(unit_price >= 0 AND unit_price <= 1000000000),
  position INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id),
  customer_id TEXT NOT NULL REFERENCES customers(id),
  quote_id TEXT NOT NULL UNIQUE REFERENCES quotes(id),
  customer_name_snapshot TEXT NOT NULL,
  doc_no TEXT NOT NULL, title TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('received','processing','fulfilled','cancelled')),
  review_state TEXT NOT NULL CHECK(review_state IN ('clean','pending','acknowledged')),
  vat_mode TEXT NOT NULL CHECK(vat_mode IN ('taxable','exempt')),
  due_date TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE(org_id,doc_no)
);
CREATE TABLE IF NOT EXISTS order_items (
  id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id),
  source_quote_item_id TEXT REFERENCES quote_items(id),
  name TEXT NOT NULL, quantity INTEGER NOT NULL CHECK(quantity > 0 AND quantity <= 100000),
  unit_price INTEGER NOT NULL CHECK(unit_price >= 0 AND unit_price <= 1000000000),
  position INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS invoices (
  id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id),
  order_id TEXT NOT NULL UNIQUE REFERENCES orders(id),
  customer_id TEXT NOT NULL REFERENCES customers(id),
  customer_name_snapshot TEXT NOT NULL,
  doc_no TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('issued')),
  vat_mode TEXT NOT NULL CHECK(vat_mode IN ('taxable','exempt')),
  due_date TEXT NOT NULL, created_at TEXT NOT NULL,
  UNIQUE(org_id,doc_no)
);
CREATE TABLE IF NOT EXISTS invoice_items (
  id TEXT PRIMARY KEY, invoice_id TEXT NOT NULL REFERENCES invoices(id),
  source_order_item_id TEXT REFERENCES order_items(id),
  name TEXT NOT NULL, quantity INTEGER NOT NULL CHECK(quantity > 0 AND quantity <= 100000),
  unit_price INTEGER NOT NULL CHECK(unit_price >= 0 AND unit_price <= 1000000000),
  position INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id),
  invoice_id TEXT NOT NULL REFERENCES invoices(id),
  amount INTEGER NOT NULL CHECK(amount > 0),
  paid_at TEXT NOT NULL, note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL, reference TEXT NOT NULL,
  reversed_at TEXT, reversed_by TEXT REFERENCES users(id),
  UNIQUE(org_id,invoice_id,reference)
);
CREATE INDEX IF NOT EXISTS idx_payments_invoice ON payments(invoice_id);
CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id),
  actor_id TEXT NOT NULL REFERENCES users(id), entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL, action TEXT NOT NULL,
  detail TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(org_id,created_at);
CREATE TABLE IF NOT EXISTS security_events (
  id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id),
  actor_id TEXT REFERENCES users(id), event_type TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_security_events_org ON security_events(org_id,created_at);
CREATE TABLE IF NOT EXISTS import_previews (
  id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id),
  uploaded_by TEXT NOT NULL REFERENCES users(id),
  file_sha256 TEXT NOT NULL, filename TEXT NOT NULL,
  normalized_json TEXT NOT NULL, preview_digest TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','confirmed')),
  created_at TEXT NOT NULL, confirmed_at TEXT,
  order_id TEXT UNIQUE REFERENCES orders(id)
);
CREATE INDEX IF NOT EXISTS idx_import_previews_org ON import_previews(org_id,created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_imports_single_confirmed_file
  ON import_previews(org_id,file_sha256) WHERE status='confirmed';

'''


def init_db():
    with conn() as c:
        c.executescript(SCHEMA)
        # Forward-only session migration: old bearer tokens are invalidated on upgrade.
        session_cols={r['name'] for r in c.execute('PRAGMA table_info(sessions)')}
        if 'csrf_token' not in session_cols:
            c.execute("ALTER TABLE sessions ADD COLUMN csrf_token TEXT NOT NULL DEFAULT ''")
            c.execute('DELETE FROM sessions')
        session_cols={r['name'] for r in c.execute('PRAGMA table_info(sessions)')}
        if 'id' not in session_cols:
            c.execute('ALTER TABLE sessions ADD COLUMN id TEXT')
            c.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_id ON sessions(id)')
        if 'created_at' not in session_cols:
            c.execute("ALTER TABLE sessions ADD COLUMN created_at TEXT NOT NULL DEFAULT ''")
        for session in c.execute('SELECT token_hash FROM sessions WHERE id IS NULL').fetchall():
            c.execute('UPDATE sessions SET id=? WHERE token_hash=?', (ident(), session['token_hash']))
        # Forward-only additive migration preserves existing user invoices and receipts.
        cols={r['name'] for r in c.execute('PRAGMA table_info(payments)')}
        if 'reversed_at' not in cols: c.execute('ALTER TABLE payments ADD COLUMN reversed_at TEXT')
        if 'reversed_by' not in cols: c.execute('ALTER TABLE payments ADD COLUMN reversed_by TEXT REFERENCES users(id)')
        order_cols={r['name'] for r in c.execute('PRAGMA table_info(orders)')}
        if 'order_date' not in order_cols:
            c.execute("ALTER TABLE orders ADD COLUMN order_date TEXT NOT NULL DEFAULT ''")
        if 'source_import_id' not in order_cols:
            c.execute('ALTER TABLE orders ADD COLUMN source_import_id TEXT')
        c.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_source_import ON orders(source_import_id)')
        if 'source_document_meta' not in order_cols:
            c.execute("ALTER TABLE orders ADD COLUMN source_document_meta TEXT NOT NULL DEFAULT '{}'")
        for table in ('quotes','orders','invoices'):
            old_cols={r['name'] for r in c.execute(f'PRAGMA table_info({table})')}
            if 'customer_name_snapshot' not in old_cols:
                c.execute(f"ALTER TABLE {table} ADD COLUMN customer_name_snapshot TEXT NOT NULL DEFAULT ''")
                # Pre-snapshot databases only retain the current customer name. Do not
                # pretend it is proof of the historical name on older documents.
                c.execute(f'''UPDATE {table} SET customer_name_snapshot=(
                    SELECT name FROM customers WHERE customers.id={table}.customer_id
                ) WHERE customer_name_snapshot='' ''')
    if os.environ.get('DEMO_SEED') == '1':
        if os.environ.get('JW_ENV', '').lower() == 'production':
            raise RuntimeError('DEMO_SEED must never be used with JW_ENV=production')
        seed_demo()
    elif all(os.environ.get(k) for k in ('BOOTSTRAP_EMAIL', 'BOOTSTRAP_PASSWORD', 'BOOTSTRAP_ORG')):
        pw = os.environ['BOOTSTRAP_PASSWORD']
        if len(pw) < 12:
            raise RuntimeError('BOOTSTRAP_PASSWORD must contain at least 12 characters')
        with transaction() as c:
            if c.execute('SELECT count(*) FROM users').fetchone()[0] == 0:
                org = ident()
                c.execute('INSERT INTO organizations VALUES(?,?,?)',(org,os.environ['BOOTSTRAP_ORG'],now()))
                c.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
                          (ident(),org,os.environ['BOOTSTRAP_EMAIL'].lower(),hash_password(pw),'관리자','admin',now()))


def seed_demo():
    with transaction() as c:
        if c.execute("SELECT 1 FROM users WHERE email = 'demo@hanbit.example'").fetchone():
            return
        for org_name, mail, customer_name in [
            ('한빛테크','demo@hanbit.example','미래부품'),
            ('바다유통','demo@bada.example','대명산업')
        ]:
            org, user, customer = ident(), ident(), ident()
            c.execute('INSERT INTO organizations VALUES(?,?,?)',(org,org_name,now()))
            c.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
                      (user,org,mail,hash_password('Demo!2026secure'),f'{org_name} 관리자','admin',now()))
            c.execute('INSERT INTO customers VALUES(?,?,?,?,?,?,?,?)',
                      (customer,org,customer_name,'','','','',now()))
            quote=ident()
            c.execute('INSERT INTO quotes VALUES(?,?,?,?,?,?,?,?,?,?)',
                      (quote,org,customer,customer_name,f'Q-{uuid.uuid4().hex[:8].upper()}','10월 샘플 견적','draft','taxable',now(),now()))
            c.execute('INSERT INTO quote_items VALUES(?,?,?,?,?,?)',
                      (ident(),quote,'산업용 부품 A',12,125000,0))


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)


class LoginBody(Strict):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=1000)


class CustomerBody(Strict):
    name: str = Field(min_length=1,max_length=120)
    business_number: str = Field(default='',max_length=20)
    contact_name: str = Field(default='',max_length=100)
    email: str = Field(default='',max_length=255)
    phone: str = Field(default='',max_length=30)

    @field_validator('email')
    @classmethod
    def validate_mail(cls, v):
        if v and not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',v):
            raise ValueError('올바른 이메일 주소가 아닙니다')
        return v


class LineBody(Strict):
    name: str = Field(min_length=1,max_length=150)
    quantity: int = Field(ge=1,le=MAX_QTY,strict=True)
    unit_price: int = Field(ge=0,le=MAX_PRICE,strict=True)


class OrderLineBody(LineBody):
    source_quote_item_id: str | None = None


class QuoteBody(Strict):
    customer_id: str
    title: str = Field(min_length=1,max_length=150)
    vat_mode: Literal['taxable','exempt'] = 'taxable'
    items: list[LineBody] = Field(min_length=1,max_length=MAX_ITEMS)


class QuoteStatus(Strict):
    status: Literal['sent','accepted','rejected']


class OrderFromQuote(Strict):
    quote_id: str
    due_date: date


class OrderChange(Strict):
    items: list[OrderLineBody] = Field(min_length=1,max_length=MAX_ITEMS)
    change_reason: str = Field(min_length=5,max_length=500)
    due_date: date


class OrderStatus(Strict):
    status: Literal['processing','fulfilled','cancelled']


class InvoiceFromOrder(Strict):
    order_id: str
    due_date: date


class PaymentBody(Strict):
    reference: str = Field(min_length=8,max_length=100)
    amount: int = Field(gt=0,le=10**16,strict=True)
    paid_at: date
    note: str = Field(default='',max_length=300)


def rowdict(row):
    return dict(row) if row is not None else None


def get_row(c, table: str, row_id: str, org_id: str):
    # Table name is chosen by internal constants only, never user input.
    r=c.execute(f'SELECT * FROM {table} WHERE id=? AND org_id=?',(row_id,org_id)).fetchone()
    if not r:
        fail('대상을 찾을 수 없습니다',404)
    return dict(r)


def customer_exists(c, org, id):
    if not c.execute('SELECT 1 FROM customers WHERE id=? AND org_id=?',(id,org)).fetchone():
        fail('거래처를 찾을 수 없습니다',404)


def money(items, vat_mode):
    subtotal = sum(int(x['quantity'])*int(x['unit_price']) for x in items)
    vat = (subtotal + 5) // 10 if vat_mode == 'taxable' else 0  # ROUND_HALF_UP, one invoice subtotal
    return {'subtotal':subtotal,'vat':vat,'total':subtotal+vat}


def retrieve_items(c, kind, parent_id):
    # Three hardcoded safe tables.
    tab={'quote':'quote_items','order':'order_items','invoice':'invoice_items'}[kind]
    key={'quote':'quote_id','order':'order_id','invoice':'invoice_id'}[kind]
    return [dict(r) for r in c.execute(f'SELECT * FROM {tab} WHERE {key}=? ORDER BY position',(parent_id,)).fetchall()]


def detail_doc(c, kind, doc):
    items=retrieve_items(c,kind,doc['id'])
    result={**doc, 'items':items, 'money':money(items,doc['vat_mode'])}
    if kind=='order' and doc.get('source_import_id'):
        try:
            source_doc=json.loads(doc.get('source_document_meta') or '{}')
        except (TypeError, ValueError):
            source_doc={}
        result['import_source']={
            'filename':source_doc.get('filename'),
            'document_kind':source_doc.get('document_kind'),
            'reference_number':source_doc.get('additional_fields',{}).get('reference_number'),
            'additional_fields':source_doc.get('additional_fields',{}),
            'source_items':source_doc.get('items',[]),
            'quantity_by_unit':source_doc.get('quantity_by_unit',{}),
        }
    if kind=='invoice':
        result['paid']=c.execute('SELECT COALESCE(SUM(amount),0) FROM payments WHERE invoice_id=? AND reversed_at IS NULL',(doc['id'],)).fetchone()[0]
        result['payments']=[dict(r) for r in c.execute('''SELECT id,amount,paid_at,note,created_at,reference,reversed_at
            FROM payments WHERE invoice_id=? ORDER BY paid_at DESC,created_at DESC,id DESC''',(doc['id'],))]
        result['balance']=result['money']['total']-result['paid']
        result['payment_status']='paid' if result['balance']==0 else ('overdue' if doc['due_date']<today() else 'unpaid')
    return result


def doc_list(c,kind,org):
    tab={'quote':'quotes','order':'orders','invoice':'invoices'}[kind]
    records=c.execute(f'SELECT d.*,d.customer_name_snapshot AS customer_name FROM {tab} d WHERE d.org_id=? ORDER BY d.created_at DESC,d.id DESC',(org,)).fetchall()
    return [detail_doc(c,kind,dict(r)) for r in records]


def audit(c, user,entity_type,entity_id,action,detail):
    c.execute('INSERT INTO audit_logs VALUES(?,?,?,?,?,?,?,?)',
              (ident(),user['org_id'],user['id'],entity_type,entity_id,action,
               json.dumps(detail,ensure_ascii=False,sort_keys=True),now()))


def diff_lines(src, target, linkkey):
    matched={x.get(linkkey):x for x in target if x.get(linkkey)}
    differences=[]
    for x in src:
        y=matched.get(x['id'])
        if not y:
            differences.append({'item':x['name'],'field':'missing','expected':x['name'],'actual':'누락'})
            continue
        for field in ['name','quantity','unit_price']:
            if x[field]!=y[field]:
                differences.append({'item':x['name'],'field':field,'expected':x[field],'actual':y[field]})
    for x in target:
        if not x.get(linkkey) or not any(s['id']==x[linkkey] for s in src):
            differences.append({'item':x['name'],'field':'extra','expected':'없음','actual':x['name']})
    return differences


def order_diff(c,order):
    src=retrieve_items(c,'quote',order['quote_id'])
    target=retrieve_items(c,'order',order['id'])
    q=c.execute('SELECT vat_mode FROM quotes WHERE id=?',(order['quote_id'],)).fetchone()
    diffs=diff_lines(src,target,'source_quote_item_id')
    if q['vat_mode']!=order['vat_mode']:
        diffs.append({'item':'부가세','field':'vat_mode','expected':q['vat_mode'],'actual':order['vat_mode']})
    return diffs


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app=FastAPI(title='JARVIS WORKS v1', version='1.3.0', docs_url='/docs' if os.getenv('ENABLE_API_DOCS')=='1' else None,
            redoc_url=None, lifespan=lifespan)


@app.middleware('http')
async def response_security_headers(request: Request, call_next):
    if request.url.path.startswith('/api/') and request.method not in ('GET', 'HEAD', 'OPTIONS'):
        if request.headers.get('Sec-Fetch-Site') == 'cross-site':
            return JSONResponse(status_code=403,content={'detail':'외부 사이트의 요청은 허용되지 않습니다'})
        origin=request.headers.get('Origin')
        if origin and origin != str(request.base_url).rstrip('/'):
            return JSONResponse(status_code=403,content={'detail':'요청 출처가 일치하지 않습니다'})
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    if request.url.scheme == 'https':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    if request.url.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'
    return response


@app.get('/api/config')
def config():
    return {'demo_mode':os.environ.get('DEMO_SEED')=='1'}


@app.get('/api/health')
def health():
    return {'status':'ok','version':'1.3.0'}


@app.post('/api/login')
def login(body:LoginBody,response:Response):
    with transaction() as c:
        email = body.email.casefold()
        current = datetime.now(KST)
        record = c.execute('SELECT * FROM login_failures WHERE email=?', (email,)).fetchone()
        if record and datetime.fromisoformat(record['first_failed_at']) + timedelta(minutes=LOGIN_WINDOW_MINUTES) <= current:
            c.execute('DELETE FROM login_failures WHERE email=?', (email,))
            record = None
        if record and record['attempts'] >= LOGIN_FAILURE_LIMIT:
            fail('로그인 시도가 많습니다. 15분 후 다시 시도하세요', 429)
        user=c.execute('SELECT u.*,o.name as org_name FROM users u JOIN organizations o ON o.id=u.org_id WHERE lower(u.email)=?',(email,)).fetchone()
        if not user or not verify_password(body.password,user['password_hash']):
            if record:
                c.execute('UPDATE login_failures SET attempts=attempts+1 WHERE email=?', (email,))
            else:
                c.execute('INSERT INTO login_failures VALUES(?,?,?)', (email, 1, current.isoformat(timespec='seconds')))
            # Do not store unknown identifiers, IPs, passwords or attempted secrets.
            if user:
                c.execute('INSERT INTO security_events VALUES(?,?,?,?,?)',
                          (ident(),user['org_id'],user['id'],'login_failed',now()))
            # Return after transaction commits so failed attempts are actually persisted.
            failed = True
        else:
            failed = False
            c.execute('DELETE FROM login_failures WHERE email=?', (email,))
        if failed:
            result = None
        else:
            token=secrets.token_urlsafe(36)
            exp=(current+timedelta(hours=SESSION_HOURS)).isoformat(timespec='seconds')
            csrf=secrets.token_urlsafe(32)
            c.execute('INSERT INTO sessions(token_hash,user_id,expires_at,csrf_token,id,created_at) VALUES(?,?,?,?,?,?)',
                      (hashlib.sha256(token.encode()).hexdigest(),user['id'],exp,csrf,ident(),now()))
            c.execute('INSERT INTO security_events VALUES(?,?,?,?,?)',
                      (ident(),user['org_id'],user['id'],'login_success',now()))
            result = {'csrf_token':csrf,'expires_at':exp,'user':{'id':user['id'],'org_id':user['org_id'],'org_name':user['org_name'],'email':user['email'],'name':user['name'],'role':user['role']}}
    if failed:
        fail('이메일 또는 비밀번호가 올바르지 않습니다',401)
    response.set_cookie(SESSION_COOKIE,token,secure=not ALLOW_INSECURE_DEV,httponly=True,
                        samesite='strict',path='/')
    response.headers['Cache-Control']='no-store'
    return result


def current_user(request:Request):
    token=request.cookies.get(SESSION_COOKIE,'')
    if len(token)<30:
        fail('로그인이 필요합니다',401)
    with conn() as c:
        result=c.execute('''SELECT u.id,u.org_id,u.email,u.name,u.role,o.name AS org_name,
               s.expires_at,s.csrf_token
            FROM sessions s JOIN users u ON u.id=s.user_id JOIN organizations o ON o.id=u.org_id
            WHERE s.token_hash=?''',(hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if not result or datetime.fromisoformat(result['expires_at'])<=datetime.now(KST):
            fail('세션이 만료되었거나 유효하지 않습니다',401)
        if request.method not in ('GET','HEAD','OPTIONS'):
            submitted=request.headers.get('X-CSRF-Token','')
            expected=result['csrf_token']
            if not expected or not hmac.compare_digest(submitted,expected):
                fail('보안 토큰이 없거나 잘못되었습니다',403)
        return dict(result)


def need_admin(user):
    if user['role']!='admin':
        fail('관리자 권한이 필요합니다',403)


@app.get('/api/me')
def me(user=Depends(current_user)):
    return {k:user[k] for k in ['id','org_id','email','name','role','org_name','csrf_token']}


@app.post('/api/logout')
def logout(request:Request,response:Response,user=Depends(current_user)):
    with transaction() as c:
        token=request.cookies.get(SESSION_COOKIE,'')
        c.execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),))
        c.execute('INSERT INTO security_events VALUES(?,?,?,?,?)',
                  (ident(),user['org_id'],user['id'],'logout',now()))
    response.delete_cookie(SESSION_COOKIE,path='/')
    response.headers['Cache-Control']='no-store'
    return {'ok':True}


@app.get('/api/security/overview')
def security_overview(request: Request, user=Depends(current_user)):
    # Security information must never leak between organizations or to non-admin staff.
    need_admin(user)
    token_hash=hashlib.sha256(request.cookies.get(SESSION_COOKIE,'').encode()).hexdigest()
    with conn() as c:
        users=[dict(r) for r in c.execute('''SELECT id,name,role FROM users WHERE org_id=?
                                               ORDER BY created_at,id''',(user['org_id'],))]
        sessions=[dict(r) for r in c.execute('''SELECT s.id,s.user_id,u.name AS user_name,s.created_at,s.expires_at
                 FROM sessions s JOIN users u ON s.user_id=u.id
                 WHERE u.org_id=? AND s.expires_at>? ORDER BY s.expires_at DESC''',
                 (user['org_id'],now()))]
        current=c.execute('SELECT id FROM sessions WHERE token_hash=? AND user_id=?',
                          (token_hash,user['id'])).fetchone()
        events=[dict(r) for r in c.execute('''SELECT e.id,e.event_type,e.created_at,u.name AS actor_name
                FROM security_events e LEFT JOIN users u ON u.id=e.actor_id
                WHERE e.org_id=? ORDER BY e.created_at DESC,e.rowid DESC LIMIT 50''',(user['org_id'],))]
        failures=c.execute('''SELECT count(*) FROM security_events WHERE org_id=? AND event_type='login_failed'
               AND created_at>=?''',(user['org_id'],(datetime.now(KST)-timedelta(hours=24)).isoformat(timespec='seconds'))).fetchone()[0]
        return {'users':users,'sessions':[{**s,'is_current':s['id']==(current['id'] if current else None)} for s in sessions],
                'events':events,'failed_logins_24h':failures,'mfa_enabled':False,
                'db_row_level_security_enabled':False,'security_monitoring_automated':False}


@app.post('/api/security/sessions/{session_id}/revoke')
def revoke_session(session_id: str, request: Request, user=Depends(current_user)):
    need_admin(user)
    with transaction() as c:
        match=c.execute('''SELECT s.id,s.user_id FROM sessions s JOIN users u ON u.id=s.user_id
                           WHERE s.id=? AND u.org_id=?''',(session_id,user['org_id'])).fetchone()
        if not match:
            fail('세션을 찾을 수 없습니다',404)
        live_hash=hashlib.sha256(request.cookies.get(SESSION_COOKIE,'').encode()).hexdigest()
        current=c.execute('SELECT id FROM sessions WHERE token_hash=?',(live_hash,)).fetchone()
        if current and match['id']==current['id']:
            fail('현재 사용 중인 세션은 로그아웃에서 종료하세요',400)
        c.execute('DELETE FROM sessions WHERE id=?',(session_id,))
        c.execute('INSERT INTO security_events VALUES(?,?,?,?,?)',
                  (ident(),user['org_id'],user['id'],'session_revoked',now()))
    return {'ok':True}


@app.get('/api/customers')
def customers(user=Depends(current_user)):
    with conn() as c:
        return [dict(r) for r in c.execute('SELECT * FROM customers WHERE org_id=? ORDER BY created_at DESC,name',(user['org_id'],))]


@app.post('/api/customers',status_code=201)
def create_customer(body:CustomerBody,user=Depends(current_user)):
    with transaction() as c:
        key=ident()
        try:
            c.execute('INSERT INTO customers VALUES(?,?,?,?,?,?,?,?)',
                     (key,user['org_id'],body.name,body.business_number,body.contact_name,body.email,body.phone,now()))
        except sqlite3.IntegrityError:
            fail('같은 이름의 거래처가 이미 등록되어 있습니다',409)
        audit(c,user,'customer',key,'create',{'fields':list(body.model_fields_set),'privacy':'contact values omitted'})
        return get_row(c,'customers',key,user['org_id'])


@app.put('/api/customers/{customer_id}')
def update_customer(customer_id: str, body: CustomerBody, user=Depends(current_user)):
    with transaction() as c:
        before = get_row(c, 'customers', customer_id, user['org_id'])
        try:
            c.execute('''UPDATE customers SET name=?,business_number=?,contact_name=?,email=?,phone=?
                      WHERE id=? AND org_id=?''',
                      (body.name,body.business_number,body.contact_name,body.email,body.phone,customer_id,user['org_id']))
        except sqlite3.IntegrityError:
            fail('같은 이름의 거래처가 이미 등록되어 있습니다',409)
        after = get_row(c, 'customers', customer_id, user['org_id'])
        changed=[k for k in ('name','business_number','contact_name','email','phone') if before[k]!=after[k]]
        audit(c,user,'customer',customer_id,'edit',{'changed_fields':changed,'privacy':'contact values omitted'})
        return after


@app.get('/api/quotes')
def quotes(user=Depends(current_user)):
    with conn() as c:
        return doc_list(c,'quote',user['org_id'])


@app.post('/api/quotes',status_code=201)
def create_quote(body:QuoteBody,user=Depends(current_user)):
    with transaction() as c:
        customer_exists(c,user['org_id'],body.customer_id)
        customer_name=get_row(c,'customers',body.customer_id,user['org_id'])['name']
        key=ident()
        doc=f'Q-{datetime.now(KST):%Y%m%d}-{key[:10].upper()}'
        c.execute('INSERT INTO quotes VALUES(?,?,?,?,?,?,?,?,?,?)',
                  (key,user['org_id'],body.customer_id,customer_name,doc,body.title,'draft',body.vat_mode,now(),now()))
        for i,it in enumerate(body.items):
            c.execute('INSERT INTO quote_items VALUES(?,?,?,?,?,?)',(ident(),key,it.name,it.quantity,it.unit_price,i))
        audit(c,user,'quote',key,'create',{'number':doc,'money':money([x.model_dump() for x in body.items],body.vat_mode)})
        return detail_doc(c,'quote',get_row(c,'quotes',key,user['org_id']))


@app.get('/api/quotes/{quote_id}')
def get_quote(quote_id:str,user=Depends(current_user)):
    with conn() as c:
        return detail_doc(c,'quote',get_row(c,'quotes',quote_id,user['org_id']))


@app.put('/api/quotes/{quote_id}')
def update_quote(quote_id:str,body:QuoteBody,user=Depends(current_user)):
    with transaction() as c:
        orig=get_row(c,'quotes',quote_id,user['org_id'])
        if orig['status']!='draft': fail('초안 견적서만 수정할 수 있습니다',409)
        customer_exists(c,user['org_id'],body.customer_id)
        before=detail_doc(c,'quote',orig)
        c.execute('UPDATE quotes SET customer_id=?,customer_name_snapshot=?,title=?,vat_mode=?,updated_at=? WHERE id=? AND org_id=?',
                  (body.customer_id,get_row(c,'customers',body.customer_id,user['org_id'])['name'],body.title,body.vat_mode,now(),quote_id,user['org_id']))
        c.execute('DELETE FROM quote_items WHERE quote_id=?',(quote_id,))
        for i,it in enumerate(body.items):
            c.execute('INSERT INTO quote_items VALUES(?,?,?,?,?,?)',(ident(),quote_id,it.name,it.quantity,it.unit_price,i))
        after=detail_doc(c,'quote',get_row(c,'quotes',quote_id,user['org_id']))
        audit(c,user,'quote',quote_id,'edit',{'before':{'title':before['title'],'customer':before['customer_name_snapshot'],'items':before['items'],'money':before['money']},'after':{'title':after['title'],'customer':after['customer_name_snapshot'],'items':after['items'],'money':after['money']}})
        return after


@app.post('/api/quotes/{quote_id}/status')
def change_quote_status(quote_id:str,body:QuoteStatus,user=Depends(current_user)):
    paths={'draft':['sent'],'sent':['accepted','rejected'],'accepted':[],'rejected':[]}
    with transaction() as c:
        orig=get_row(c,'quotes',quote_id,user['org_id'])
        if body.status not in paths[orig['status']]: fail('허용되지 않는 견적 상태 변경입니다',409)
        c.execute('UPDATE quotes SET status=?,updated_at=? WHERE id=?',(body.status,now(),quote_id))
        audit(c,user,'quote',quote_id,'status',{'before':orig['status'],'after':body.status})
        return detail_doc(c,'quote',get_row(c,'quotes',quote_id,user['org_id']))


class ImportSupplement(Strict):
    preview_digest: str = Field(min_length=64,max_length=64)
    fields: dict[Literal['company','ordered_at','due_date'], str] = Field(min_length=1,max_length=3)


class ImportConfirmation(Strict):
    preview_digest: str = Field(min_length=64, max_length=64)
    confirmed_customer: str = Field(min_length=1,max_length=120)
    confirmed_order_date: date
    confirmed_total: int = Field(ge=0,strict=True)
    approve: Literal[True]


def import_preview_response(doc, preview_id, digest, existing):
    return {'id':preview_id,'digest':digest,'status':'pending','document':doc,
            'customer_status':'existing' if existing else 'new',
            'existing_customer_id':existing['id'] if existing else None,
            'confirmation_required':True,'ready_to_confirm':not bool(doc.get('missing_fields'))}


def match_import_customer(c, org, doc):
    name=doc['company']
    if not name:return None
    business=doc['business_number']
    same_name=c.execute('SELECT * FROM customers WHERE org_id=? AND name=?',(org,name)).fetchone()
    if business:
        by_number=c.execute('SELECT * FROM customers WHERE org_id=? AND business_number=? AND business_number!=\'\'',(org,business)).fetchall()
        if len(by_number)>1:fail('같은 사업자번호에 여러 거래처가 존재하여 자동 등록할 수 없습니다',409)
        if by_number and by_number[0]['name']!=name:fail('사업자번호는 같지만 상호가 다릅니다. 거래처를 먼저 확인하세요',409)
        if same_name and same_name['business_number'] != business:fail('상호는 같지만 사업자번호가 불일치하거나 기존에 누락되어 있습니다. 거래처를 먼저 확인하세요',409)
    return same_name


@app.post('/api/imports/preview',status_code=201)
async def upload_order_preview(file:UploadFile=File(...),user=Depends(current_user)):
    # Do not persist file bytes; reject oversized uploads while streaming a bounded amount.
    raw=await file.read(MAX_FILE_SIZE+1)
    await file.close()
    try:document=extract(file.filename or '',raw,allow_missing=True)
    except DocumentError as exc:fail(str(exc),422)
    digest=hashlib.sha256(json.dumps(document,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    checksum=hashlib.sha256(raw).hexdigest()
    with transaction() as c:
        if c.execute("SELECT 1 FROM import_previews WHERE org_id=? AND file_sha256=? AND status='confirmed'",(user['org_id'],checksum)).fetchone():
            fail('이미 승인·등록된 동일 문서입니다',409)
        existing=match_import_customer(c,user['org_id'],document)
        ident_new=ident()
        c.execute('''INSERT INTO import_previews
          (id,org_id,uploaded_by,file_sha256,filename,normalized_json,preview_digest,status,created_at)
          VALUES(?,?,?,?,?,?,?,?,?)''',
          (ident_new,user['org_id'],user['id'],checksum,document['filename'],json.dumps(document,ensure_ascii=False,sort_keys=True),digest,'pending',now()))
        audit(c,user,'document_import',ident_new,'preview',{'format':document['format'],'items':document['item_count']})
        return import_preview_response(document,ident_new,digest,existing)


@app.get('/api/imports/{preview_id}')
def read_order_preview(preview_id:str,user=Depends(current_user)):
    with conn() as c:
        row=get_row(c,'import_previews',preview_id,user['org_id'])
        if row['uploaded_by']!=user['id'] and user['role']!='admin':fail('업로드한 사용자만 검토할 수 있습니다',403)
        doc=json.loads(row['normalized_json'])
        existing=match_import_customer(c,user['org_id'],doc)
        return {**import_preview_response(doc,row['id'],row['preview_digest'],existing),'status':row['status'],'order_id':row['order_id']}


@app.patch('/api/imports/{preview_id}/supplement')
def supplement_order_import(preview_id: str, body: ImportSupplement, user=Depends(current_user)):
    """Only user-supplied missing metadata; a new digest invalidates earlier approvals."""
    with transaction() as c:
        row=get_row(c,'import_previews',preview_id,user['org_id'])
        if row['uploaded_by']!=user['id'] and user['role']!='admin':
            fail('업로드한 사용자만 보완할 수 있습니다',403)
        if row['status']!='pending':fail('이미 완료된 문서는 보완할 수 없습니다',409)
        if (datetime.now(KST)-datetime.fromisoformat(row['created_at'])).total_seconds()>24*3600:
            fail('검토 기간이 지났습니다. 문서를 다시 업로드하세요',409)
        if body.preview_digest!=row['preview_digest']:
            fail('검토 중 다른 변경이 발생했습니다. 최신 내용을 다시 확인하세요',409)
        doc=json.loads(row['normalized_json'])
        try:changed=supplement_review(doc,body.fields)
        except DocumentError as exc:fail(str(exc),422)
        digest=hashlib.sha256(json.dumps(changed,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        existing=match_import_customer(c,user['org_id'],changed)
        c.execute('UPDATE import_previews SET normalized_json=?,preview_digest=? WHERE id=? AND org_id=?',
                  (json.dumps(changed,ensure_ascii=False,sort_keys=True),digest,preview_id,user['org_id']))
        audit(c,user,'document_import',preview_id,'supplement',
              {'supplied_fields':sorted(body.fields),'remaining_missing':changed['missing_fields'],
               'source_values_preserved':True})
        return import_preview_response(changed,preview_id,digest,existing)


@app.post('/api/imports/{preview_id}/confirm',status_code=201)
def confirm_order_import(preview_id:str,body:ImportConfirmation,user=Depends(current_user)):
    with transaction() as c:
        row=get_row(c,'import_previews',preview_id,user['org_id'])
        if row['uploaded_by']!=user['id'] and user['role']!='admin':fail('업로드한 사용자만 승인할 수 있습니다',403)
        if row['status']!='pending':fail('이미 승인 처리된 문서입니다',409)
        if (datetime.now(KST)-datetime.fromisoformat(row['created_at'])).total_seconds()>24*3600:
            fail('검토 기간 24시간이 지났습니다. 문서를 다시 업로드하세요',409)
        doc=json.loads(row['normalized_json'])
        if doc.get('missing_fields') or any(not doc.get(f) for f in ('company','ordered_at','due_date')):
            fail('필수 누락 항목을 모두 보완해야 발주 생성이 가능합니다',409)
        if (body.preview_digest!=row['preview_digest'] or
            body.confirmed_customer!=doc['company'] or
            body.confirmed_order_date.isoformat()!=doc['ordered_at'] or
            body.confirmed_total!=doc['money']['total']):
            fail('확인한 문서 정보가 검토 자료와 일치하지 않습니다. 다시 검토하세요',409)
        if c.execute("SELECT 1 FROM import_previews WHERE org_id=? AND file_sha256=? AND status='confirmed'",(user['org_id'],row['file_sha256'])).fetchone():
            fail('이미 승인·등록된 동일 파일입니다',409)
        cust=match_import_customer(c,user['org_id'],doc)
        # An external purchase-order number is a business identifier, even if file bytes differ.
        # Reject duplicate confirmations for the same tenant/customer/PO inside this transaction.
        reference=(doc.get('additional_fields') or {}).get('reference_number')
        if reference:
            duplicate=c.execute('''SELECT o.id FROM orders o WHERE o.org_id=?
             AND o.customer_name_snapshot=? AND
             json_extract(o.source_document_meta,'$.additional_fields.reference_number')=?
             LIMIT 1''',(user['org_id'],doc['company'],reference)).fetchone()
            if duplicate:
                fail('이미 동일 거래처·발주번호로 등록된 문서입니다. 원본을 확인하세요',409)
        if not cust:
            customer_id=ident()
            c.execute('INSERT INTO customers VALUES(?,?,?,?,?,?,?,?)',
                      (customer_id,user['org_id'],doc['company'],doc['business_number'],'','','',now()))
            audit(c,user,'customer',customer_id,'create',{'source':'confirmed_import','privacy':'contact values omitted'})
        else:customer_id=cust['id']
        # This quote is an internal imported-source record, not a claim of external quote acceptance.
        quote_id=ident(); order_id=ident()
        qnum=f'Q-{datetime.now(KST):%Y%m%d}-{quote_id[:10].upper()}'
        onum=f'O-{datetime.now(KST):%Y%m%d}-{order_id[:10].upper()}'
        c.execute('INSERT INTO quotes VALUES(?,?,?,?,?,?,?,?,?,?)',
                  (quote_id,user['org_id'],customer_id,doc['company'],qnum,'[내부 연결용·외부 승인 아님] '+doc['title'][:110],
                   'accepted',doc['vat_mode'],now(),now()))
        c.execute('''INSERT INTO orders
          (id,org_id,customer_id,quote_id,customer_name_snapshot,doc_no,title,status,
           review_state,vat_mode,due_date,created_at,updated_at,order_date,source_import_id,source_document_meta)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
          (order_id,user['org_id'],customer_id,quote_id,doc['company'],onum,doc['title'],
           'received','clean',doc['vat_mode'],doc['due_date'],now(),now(),doc['ordered_at'],preview_id,
           json.dumps(doc,ensure_ascii=False,sort_keys=True)))
        for i,x in enumerate(doc['items']):
            itemid=ident()
            c.execute('INSERT INTO quote_items VALUES(?,?,?,?,?,?)',(itemid,quote_id,x['name'],x['quantity'],x['unit_price'],i))
            c.execute('INSERT INTO order_items VALUES(?,?,?,?,?,?,?)',
                      (ident(),order_id,itemid,x['name'],x['quantity'],x['unit_price'],i))
        c.execute('UPDATE import_previews SET status=?,confirmed_at=?,order_id=? WHERE id=? AND org_id=?',
                  ('confirmed',now(),order_id,preview_id,user['org_id']))
        audit(c,user,'document_import',preview_id,'confirm',{'order_id':order_id,'quote_id':quote_id,
              'ordered_at':doc['ordered_at'],'amount':doc['money']['total'],'quantity':doc['ordered_quantity']})
        audit(c,user,'order',order_id,'create',{'quote_id':quote_id,'number':onum,'source':'explicitly_confirmed_file_import'})
        return {'order':detail_doc(c,'order',get_row(c,'orders',order_id,user['org_id'])),
                'quote_id':quote_id,'import_id':preview_id}


@app.get('/api/order-analytics')
def order_analytics(start_date:date|None=None,end_date:date|None=None,user=Depends(current_user)):
    if start_date and end_date and start_date>end_date:fail('시작일은 종료일보다 이전이어야 합니다')
    with conn() as c:
        rows=c.execute('''SELECT o.*,COALESCE(NULLIF(o.order_date,''),substr(o.created_at,1,10)) AS recorded_order_date
          FROM orders o WHERE o.org_id=? ORDER BY recorded_order_date DESC,o.id DESC''',(user['org_id'],)).fetchall()
        summary={};by_date={};by_item={};by_unit={};warnings=[]
        totals={'order_count':0,'ordered_quantity':0,'subtotal':0,'vat':0,'total':0}
        for o in rows:
            day=o['recorded_order_date']
            if (start_date and day<start_date.isoformat()) or (end_date and day>end_date.isoformat()):continue
            if o['status']=='cancelled':continue
            items=retrieve_items(c,'order',o['id']);m=money(items,o['vat_mode']);qty=sum(x['quantity'] for x in items)
            entry=summary.setdefault(o['customer_name_snapshot'],{'company':o['customer_name_snapshot'],
                    'order_count':0,'ordered_quantity':0,'subtotal':0,'vat':0,'total':0})
            daily=by_date.setdefault(day,{'date':day,'order_count':0,'ordered_quantity':0,'subtotal':0,'vat':0,'total':0})
            source_items=[]
            if o['source_import_id']:
                try:source_items=json.loads(o['source_document_meta'] or '{}').get('items',[])
                except (ValueError,TypeError):source_items=[]
            same_items=(len(source_items)==len(items) and all(
                source_items[i][f]==item[f] for i,item in enumerate(items) for f in ('name','quantity','unit_price')))
            if o['source_import_id'] and not same_items:
                warnings.append({'order_id':o['id'],'reason':'원본 파일과 발주 품목이 변경되어 단위를 재확인해야 합니다'})
            for i,item in enumerate(items):
                unit=(source_items[i].get('unit') or '단위 미기재') if same_items else '단위 확인 필요'
                src=source_items[i] if same_items else {}
                sku=src.get('sku','')
                spec=src.get('spec','')
                key=(sku,item['name'],spec,unit)
                prod=by_item.setdefault(key,{'item':item['name'],'sku':sku,'spec':spec,
                    'unit':unit,'ordered_quantity':0,'subtotal':0})
                prod['ordered_quantity']+=item['quantity']
                prod['subtotal']+=item['quantity']*item['unit_price']
                by_unit[unit]=by_unit.get(unit,0)+item['quantity']
            for target in (entry,daily,totals):
                target['order_count']+=1;target['ordered_quantity']+=qty
                for k in ('subtotal','vat','total'):target[k]+=m[k]
        return {'period':{'start_date':str(start_date) if start_date else None,'end_date':str(end_date) if end_date else None},
                'totals':totals,'companies':sorted(summary.values(),key=lambda x:(-x['total'],x['company'])),
                'by_date':sorted(by_date.values(),key=lambda x:x['date'],reverse=True),
                'by_item':sorted(by_item.values(),key=lambda x:(-x['subtotal'],x['item'],x['unit'])),
                'quantity_by_unit':by_unit,'mixed_units':len(by_unit)>1,'warnings':warnings}


@app.get('/api/orders')
def orders(user=Depends(current_user)):
    with conn() as c:
        return doc_list(c,'order',user['org_id'])


@app.post('/api/orders/from-quote',status_code=201)
def create_order(body:OrderFromQuote,user=Depends(current_user)):
    with transaction() as c:
        q=get_row(c,'quotes',body.quote_id,user['org_id'])
        if q['status']!='accepted': fail('승인된 견적서에서만 발주를 생성할 수 있습니다',409)
        if c.execute('SELECT 1 FROM orders WHERE quote_id=?',(q['id'],)).fetchone():
            fail('이미 발주로 전환된 견적서입니다',409)
        if body.due_date.isoformat()<today(): fail('납기일은 오늘 이후여야 합니다')
        key=ident();doc=f'O-{datetime.now(KST):%Y%m%d}-{key[:10].upper()}'
        c.execute('''INSERT INTO orders (id,org_id,customer_id,quote_id,customer_name_snapshot,doc_no,title,status,review_state,vat_mode,due_date,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                  (key,user['org_id'],q['customer_id'],q['id'],q['customer_name_snapshot'],doc,q['title'],'received','clean',q['vat_mode'],body.due_date.isoformat(),now(),now()))
        for i,x in enumerate(retrieve_items(c,'quote',q['id'])):
            c.execute('INSERT INTO order_items VALUES(?,?,?,?,?,?,?)',
                      (ident(),key,x['id'],x['name'],x['quantity'],x['unit_price'],i))
        c.execute('UPDATE orders SET order_date=? WHERE id=?',(today(),key))
        audit(c,user,'order',key,'create',{'quote_id':q['id'],'number':doc})
        return detail_doc(c,'order',get_row(c,'orders',key,user['org_id']))


@app.get('/api/orders/{order_id}')
def get_order(order_id:str,user=Depends(current_user)):
    with conn() as c:
        return detail_doc(c,'order',get_row(c,'orders',order_id,user['org_id']))


@app.put('/api/orders/{order_id}')
def update_order(order_id:str,body:OrderChange,user=Depends(current_user)):
    with transaction() as c:
        original=get_row(c,'orders',order_id,user['org_id'])
        if original['status'] not in ('received','processing'):
            fail('진행 중인 발주만 수정할 수 있습니다',409)
        if c.execute('SELECT 1 FROM invoices WHERE order_id=?',(order_id,)).fetchone():
            fail('청구서 발행 후 발주 금액은 수정할 수 없습니다',409)
        valid_ids={x['id'] for x in retrieve_items(c,'quote',original['quote_id'])}
        seen=[]
        for x in body.items:
            if x.source_quote_item_id is not None:
                if x.source_quote_item_id not in valid_ids: fail('원본 견적 품목이 유효하지 않습니다')
                seen.append(x.source_quote_item_id)
        if len(seen)!=len(set(seen)): fail('원본 견적 품목은 중복으로 참조할 수 없습니다')
        before=detail_doc(c,'order',original)
        c.execute('UPDATE orders SET due_date=?,updated_at=? WHERE id=?',(body.due_date.isoformat(),now(),order_id))
        c.execute('DELETE FROM order_items WHERE order_id=?',(order_id,))
        for i,x in enumerate(body.items):
            c.execute('INSERT INTO order_items VALUES(?,?,?,?,?,?,?)',
                      (ident(),order_id,x.source_quote_item_id,x.name,x.quantity,x.unit_price,i))
        changed=bool(order_diff(c,original))
        c.execute('UPDATE orders SET review_state=? WHERE id=?',('pending' if changed else 'clean',order_id))
        after=detail_doc(c,'order',get_row(c,'orders',order_id,user['org_id']))
        audit(c,user,'order',order_id,'edit',{'reason':body.change_reason,'before':{'items':before['items'],'money':before['money'],'due_date':before['due_date']},
              'after':{'items':after['items'],'money':after['money'],'due_date':after['due_date']},'requires_review':changed})
        return after


@app.post('/api/orders/{order_id}/acknowledge')
def acknowledge_order(order_id:str,user=Depends(current_user)):
    need_admin(user)
    with transaction() as c:
        order=get_row(c,'orders',order_id,user['org_id'])
        if order['review_state']!='pending' or not order_diff(c,order):
            fail('확인이 필요한 변경 사항이 없습니다',409)
        c.execute('UPDATE orders SET review_state=?,updated_at=? WHERE id=?',('acknowledged',now(),order_id))
        audit(c,user,'order',order_id,'acknowledge',{'differences':order_diff(c,order)})
        return detail_doc(c,'order',get_row(c,'orders',order_id,user['org_id']))


@app.post('/api/orders/{order_id}/status')
def change_order_status(order_id:str,body:OrderStatus,user=Depends(current_user)):
    paths={'received':['processing','cancelled'],'processing':['fulfilled','cancelled'],'fulfilled':[],'cancelled':[]}
    with transaction() as c:
        order=get_row(c,'orders',order_id,user['org_id'])
        if body.status not in paths[order['status']]:fail('허용되지 않는 발주 상태 변경입니다',409)
        if body.status=='cancelled' and c.execute('SELECT 1 FROM invoices WHERE order_id=?',(order_id,)).fetchone():
            fail('청구된 발주를 취소할 수 없습니다',409)
        if body.status=='fulfilled' and order['review_state']=='pending':
            fail('변경 사항을 확인한 후 납품 완료 처리할 수 있습니다',409)
        c.execute('UPDATE orders SET status=?,updated_at=? WHERE id=?',(body.status,now(),order_id))
        audit(c,user,'order',order_id,'status',{'before':order['status'],'after':body.status})
        return detail_doc(c,'order',get_row(c,'orders',order_id,user['org_id']))


@app.get('/api/invoices')
def invoices(user=Depends(current_user)):
    with conn() as c:
        return doc_list(c,'invoice',user['org_id'])


@app.post('/api/invoices/from-order',status_code=201)
def create_invoice(body:InvoiceFromOrder,user=Depends(current_user)):
    with transaction() as c:
        order=get_row(c,'orders',body.order_id,user['org_id'])
        if order['status']!='fulfilled': fail('납품 완료된 발주만 청구할 수 있습니다',409)
        if order['review_state']=='pending':fail('변경 내역 검증이 필요합니다',409)
        if c.execute('SELECT 1 FROM invoices WHERE order_id=?',(order['id'],)).fetchone():
            fail('해당 발주에는 이미 청구서가 있습니다',409)
        if body.due_date.isoformat()<today(): fail('입금기한은 오늘 이후여야 합니다')
        key=ident();doc=f'I-{datetime.now(KST):%Y%m%d}-{key[:10].upper()}'
        c.execute('INSERT INTO invoices VALUES(?,?,?,?,?,?,?,?,?,?)',
                  (key,user['org_id'],order['id'],order['customer_id'],order['customer_name_snapshot'],doc,'issued',order['vat_mode'],body.due_date.isoformat(),now()))
        for i,x in enumerate(retrieve_items(c,'order',order['id'])):
            c.execute('INSERT INTO invoice_items VALUES(?,?,?,?,?,?,?)',
                      (ident(),key,x['id'],x['name'],x['quantity'],x['unit_price'],i))
        audit(c,user,'invoice',key,'create',{'order_id':order['id'],'number':doc})
        return detail_doc(c,'invoice',get_row(c,'invoices',key,user['org_id']))


@app.get('/api/invoices/{invoice_id}')
def get_invoice(invoice_id:str,user=Depends(current_user)):
    with conn() as c:
        return detail_doc(c,'invoice',get_row(c,'invoices',invoice_id,user['org_id']))


@app.get('/api/invoices/{invoice_id}/payments')
def payment_history(invoice_id:str,user=Depends(current_user)):
    with conn() as c:
        get_row(c,'invoices',invoice_id,user['org_id'])
        return [dict(r) for r in c.execute('SELECT id,amount,paid_at,note,created_at,reversed_at FROM payments WHERE invoice_id=? AND org_id=? ORDER BY paid_at DESC,created_at DESC,id DESC',
               (invoice_id,user['org_id']))]


@app.post('/api/invoices/{invoice_id}/payments',status_code=201)
def record_payment(invoice_id:str,body:PaymentBody,user=Depends(current_user)):
    with transaction() as c:
        inv=get_row(c,'invoices',invoice_id,user['org_id'])
        existing=c.execute('SELECT * FROM payments WHERE org_id=? AND invoice_id=? AND reference=?',
                           (user['org_id'],invoice_id,body.reference)).fetchone()
        if existing:
            if existing['reversed_at'] is not None:
                fail('이미 취소된 입금 요청 ID는 다시 사용할 수 없습니다',409)
            if (existing['amount'],existing['paid_at'],existing['note'])!=(body.amount,body.paid_at.isoformat(),body.note):
                fail('동일한 요청 ID에 서로 다른 입금 정보가 입력되었습니다',409)
            return detail_doc(c,'invoice',inv)
        detail=detail_doc(c,'invoice',inv)
        if body.amount>detail['balance']: fail('입금액은 잔액을 초과할 수 없습니다',409)
        if body.paid_at.isoformat()>today():fail('미래 날짜의 입금은 확정 처리할 수 없습니다')
        key=ident()
        c.execute('INSERT INTO payments(id,org_id,invoice_id,amount,paid_at,note,created_at,reference) VALUES(?,?,?,?,?,?,?,?)',
                  (key,user['org_id'],invoice_id,body.amount,body.paid_at.isoformat(),body.note,now(),body.reference))
        audit(c,user,'payment',key,'create',{'invoice_id':invoice_id,'amount':body.amount,'paid_at':body.paid_at.isoformat()})
        return detail_doc(c,'invoice',inv)


@app.post('/api/invoices/{invoice_id}/payments/{payment_id}/reverse')
def reverse_payment(invoice_id: str, payment_id: str, user=Depends(current_user)):
    need_admin(user)
    with transaction() as c:
        invoice = get_row(c,'invoices',invoice_id,user['org_id'])
        record = c.execute('''SELECT * FROM payments WHERE id=? AND invoice_id=? AND org_id=?''',
                           (payment_id,invoice_id,user['org_id'])).fetchone()
        if not record: fail('입금 내역을 찾을 수 없습니다',404)
        if record['reversed_at'] is not None: fail('이미 취소한 입금 내역입니다',409)
        c.execute('UPDATE payments SET reversed_at=?,reversed_by=? WHERE id=?',
                  (now(),user['id'],payment_id))
        audit(c,user,'payment',payment_id,'reverse',{'invoice_id':invoice_id,'amount':record['amount'],
                                                      'reference':record['reference']})
        return detail_doc(c,'invoice',invoice)


@app.get('/api/reconciliation/{order_id}')
def reconciliation(order_id:str,user=Depends(current_user)):
    with conn() as c:
        order=get_row(c,'orders',order_id,user['org_id'])
        quote=get_row(c,'quotes',order['quote_id'],user['org_id'])
        d1=order_diff(c,order)
        invoice=c.execute('SELECT * FROM invoices WHERE order_id=? AND org_id=?',(order_id,user['org_id'])).fetchone()
        d2=[]
        if invoice:
            d2=diff_lines(retrieve_items(c,'order',order_id),retrieve_items(c,'invoice',invoice['id']),'source_order_item_id')
        return {'quote_money':money(retrieve_items(c,'quote',quote['id']),quote['vat_mode']),
                'order_money':money(retrieve_items(c,'order',order_id),order['vat_mode']),
                'invoice_money':money(retrieve_items(c,'invoice',invoice['id']),invoice['vat_mode']) if invoice else None,
                'quote_to_order':d1,'order_to_invoice':d2,'review_state':order['review_state'],
                'has_invoice':bool(invoice),'safe_to_bill':order['review_state']!='pending' and order['status']=='fulfilled' and not invoice}


@app.get('/api/dashboard')
def dashboard(user=Depends(current_user)):
    with conn() as c:
        org=user['org_id']
        q=doc_list(c,'quote',org)
        orders=doc_list(c,'order',org)
        invs=doc_list(c,'invoice',org)
        issues=[]
        for x in orders:
            if x['review_state']=='pending':issues.append({'kind':'review','title':'발주 변경 확인 필요','doc_no':x['doc_no'],'id':x['id']})
            if x['due_date']<today() and x['status'] not in ('fulfilled','cancelled'):
                issues.append({'kind':'overdue_order','title':'납기일 경과','doc_no':x['doc_no'],'id':x['id']})
        for x in invs:
            if x['balance']>0 and x['due_date']<today():
                issues.append({'kind':'overdue_invoice','title':'입금기한 경과','doc_no':x['doc_no'],'id':x['id']})
        count=c.execute('SELECT count(*) FROM customers WHERE org_id=?',(org,)).fetchone()[0]
        return {'customers':count,'quotes':len(q),'orders':len(orders),'invoices':len(invs),
                'outstanding':sum(x['balance'] for x in invs),'collected':sum(x['paid'] for x in invs),
                'quote_total':sum(x['money']['total'] for x in q),
                'issues':issues,'recent_quotes':q[:5],'recent_orders':orders[:5], 'recent_invoices':invs[:5]}


@app.get('/api/audit')
def audit_list(user=Depends(current_user)):
    with conn() as c:
        return [dict(r) for r in c.execute('''SELECT a.*,u.name AS actor_name FROM audit_logs a JOIN users u ON u.id=a.actor_id
              WHERE a.org_id=? ORDER BY a.created_at DESC,a.rowid DESC LIMIT 30''',(user['org_id'],))]


@app.get('/')
def index():
    return FileResponse(ROOT/'static'/'index.html',headers={'Cache-Control':'no-store'})


app.mount('/static',StaticFiles(directory=ROOT/'static'),name='static')
