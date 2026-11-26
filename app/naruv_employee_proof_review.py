"""Synthetic-only server verification handoff. No provider calls, enrolment,
real identity proofing or production delivery. Only trusted server records;
browser-supplied success, DI or claims are never admissible.
"""
from dataclasses import dataclass
import hashlib,hmac,os,re,secrets
from app import naruv_employee_session_store_review as store
from app.naruv_employee_access_review import need,ident,digest,AccessDenied

PROVIDER="SYNTHETIC_PROVIDER_ONLY"
DDL="""CREATE TABLE naruv_employee_ci.proof_enrollment(
 tenant text NOT NULL,principal text NOT NULL,worker text NOT NULL,
 subject_tag text NOT NULL CHECK(subject_tag ~ '^[0-9a-f]{64}$'),
 active boolean NOT NULL,PRIMARY KEY(tenant,principal), UNIQUE(tenant,subject_tag),
 FOREIGN KEY(tenant,principal,worker) REFERENCES naruv_employee_ci.identities(tenant,principal,worker));
CREATE TABLE naruv_employee_ci.proof_challenges(
 id text PRIMARY KEY CHECK(id ~ '^[A-Za-z0-9_-]{43}$'),
 tenant text NOT NULL,principal text NOT NULL,worker text NOT NULL,receipt text NOT NULL,
 auth_epoch bigint NOT NULL, subject_tag text NOT NULL CHECK(subject_tag ~ '^[0-9a-f]{64}$'),
 issued_at bigint NOT NULL,expires_at bigint NOT NULL CHECK(expires_at>issued_at AND expires_at-issued_at<=300),
 consumed boolean NOT NULL DEFAULT false,
 FOREIGN KEY(tenant,principal,worker) REFERENCES naruv_employee_ci.identities(tenant,principal,worker),
 FOREIGN KEY(tenant,worker,receipt) REFERENCES naruv_employee_ci.entitlements(tenant,worker,receipt));
REVOKE ALL ON naruv_employee_ci.proof_enrollment,naruv_employee_ci.proof_challenges FROM PUBLIC;
"""

@dataclass(frozen=True)
class SyntheticServerResult:
    challenge_id:str
    status:str
    subject_tag:str
    provider:str=PROVIDER

def _guard(conn):
    store._guard(conn)
    need(os.environ.get("GITHUB_ACTIONS")=="true" and os.environ.get("GITHUB_REPOSITORY")=="guccizz1k/JARVIS-WORKS")
    need(conn.execute("SELECT current_user,session_user").fetchone()==("postgres","postgres"))

def synthetic_tag(pepper,tenant,subject):
    need(type(pepper) is bytes and len(pepper)==32 and ident(tenant)
         and type(subject) is str and re.fullmatch(r"fixture-[A-Za-z0-9_-]{1,80}",subject) is not None)
    return hmac.new(pepper,("NARUV_SYNTHETIC_DI_V1\0"+tenant+"\0"+subject).encode("ascii"),hashlib.sha256).hexdigest()

def _binding(conn,tenant,principal,receipt):
    i,e=store._live(conn,tenant,principal,receipt)
    need(i.active is True and e.active is True)
    row=conn.execute("SELECT worker,subject_tag,active FROM naruv_employee_ci.proof_enrollment WHERE tenant=%s AND principal=%s FOR SHARE",(tenant,principal)).fetchone()
    need(row is not None and row[0]==i.worker and digest(row[1]) and row[2] is True)
    return i,e,row[1]

def begin(conn,*,tenant,principal,receipt):
    _guard(conn)
    i,e,tag=_binding(conn,tenant,principal,receipt)
    now=store._now(conn)
    challenge=secrets.token_urlsafe(32)
    conn.execute("INSERT INTO naruv_employee_ci.proof_challenges (id,tenant,principal,worker,receipt,auth_epoch,subject_tag,issued_at,expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                 (challenge,tenant,principal,i.worker,receipt,i.auth_epoch,tag,now,now+300))
    return challenge

def finish(conn,*,tenant,principal,receipt,challenge,result):
    """Atomic synthetic consume + session issue; caller must commit before use.
    No HTTP/provider result ingestion. A server-owned verified mapping is required.
    """
    _guard(conn)
    need(type(result) is SyntheticServerResult and result.provider==PROVIDER
         and result.status=="VERIFIED" and digest(result.subject_tag)
         and type(challenge) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}",challenge)
         and result.challenge_id==challenge)
    with conn.transaction():
        i,e,tag=_binding(conn,tenant,principal,receipt)
        need(hmac.compare_digest(tag,result.subject_tag))
        now=store._now(conn)
        row=conn.execute("""UPDATE naruv_employee_ci.proof_challenges SET consumed=true
             WHERE id=%s AND tenant=%s AND principal=%s AND worker=%s AND receipt=%s
             AND auth_epoch=%s AND subject_tag=%s AND NOT consumed AND issued_at<=%s AND expires_at>%s
             RETURNING id""",(challenge,tenant,principal,i.worker,receipt,i.auth_epoch,tag,now,now)).fetchone()
        need(row==(challenge,))
        token=store.issue(conn,trusted_tenant=tenant,trusted_principal=principal,receipt=receipt)
    return token,{"synthetic_proof_binding_verified":True,"provider_identity_verified":False,
                  "delivery_authorized":False,"production_authorized":False}
