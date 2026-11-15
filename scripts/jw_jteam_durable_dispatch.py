"""J team durable dispatcher: offline by default; no paid API or production writes.
Use injected callable for deterministic tests; real provider integration is not enabled.
"""
import argparse
import hashlib
import json
import sqlite3
import time
from pathlib import Path

ROLES=("deputy","deputy_manager","manager","director","jarvis_lead")
def setup(db):
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,task_hash TEXT NOT NULL,state TEXT NOT NULL,updated INTEGER NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS steps(job_id TEXT NOT NULL,role TEXT NOT NULL,ordinal INTEGER NOT NULL,status TEXT NOT NULL,receipt TEXT,PRIMARY KEY(job_id,role),FOREIGN KEY(job_id) REFERENCES jobs(id))")
    db.execute("CREATE TABLE IF NOT EXISTS usage_events(id INTEGER PRIMARY KEY AUTOINCREMENT,job_id TEXT NOT NULL,role TEXT NOT NULL,input_tokens INTEGER NOT NULL,output_tokens INTEGER NOT NULL,estimated_krw INTEGER,provider_receipt TEXT,FOREIGN KEY(job_id) REFERENCES jobs(id))")
    db.commit()
def dispatch(db,job_id,task,worker=None,fail_after=None):
    """Fail-closed role claims and receipts; injected worker is never implicitly authorized.

    BEGIN IMMEDIATE prevents two local writers from claiming the same role
    concurrently. A crash after a provider request leaves RUNNING and requires
    manual reconciliation, never an automatic retry.
    """
    if worker is None:
        raise PermissionError("NO_AUTHORIZED_MODEL_WORKER")
    if type(job_id) is not str or not 1 <= len(job_id) <= 128:
        raise ValueError("INVALID_JOB_ID")
    if type(task) is not str or not 1 <= len(task) <= 8000:
        raise ValueError("INVALID_TASK")
    digest=hashlib.sha256(task.encode("utf-8")).hexdigest()
    now=int(time.time())
    with db:
        row=db.execute("SELECT task_hash,state FROM jobs WHERE id=?",(job_id,)).fetchone()
        if row and row[0]!=digest:
            raise ValueError("JOB_ID_TASK_MISMATCH")
        if row and row[1]=="BLOCKED":
            raise PermissionError("BLOCKED_JOB_RECONCILIATION_REQUIRED")
        if not row:
            db.execute("INSERT INTO jobs VALUES(?,?,?,?)",(job_id,digest,"RUNNING",now))
    for index,role in enumerate(ROLES):
        # Claim and read must be a single SQLite write-serialized transaction.
        db.execute("BEGIN IMMEDIATE")
        try:
            existing=db.execute(
                "SELECT status FROM steps WHERE job_id=? AND role=?",(job_id,role)
            ).fetchone()
            if existing and existing[0]=="COMPLETE":
                db.commit()
                continue
            if existing and existing[0] in ("RUNNING","BLOCKED"):
                raise PermissionError("UNCERTAIN_PROVIDER_OUTCOME_RECONCILIATION_REQUIRED")
            db.execute(
                "INSERT INTO steps VALUES(?,?,?,?,?) "
                "ON CONFLICT(job_id,role) DO UPDATE SET status='RUNNING',receipt=NULL",
                (job_id,role,index,"RUNNING",None))
            db.commit()
        except BaseException:
            db.rollback()
            raise
        try:
            receipt=worker(role,task)
            if type(receipt) is not dict or not isinstance(receipt.get("receipt_id"),str):
                raise ValueError("MISSING_WORKER_RECEIPT")
            receipt_id=receipt["receipt_id"]
            if not 1 <= len(receipt_id) <= 256 or not receipt_id.isprintable():
                raise ValueError("INVALID_RECEIPT_ID")
            if set(receipt) - {"receipt_id","input_tokens","output_tokens","model","response_sha256"}:
                raise ValueError("SENSITIVE_OR_UNKNOWN_RECEIPT_FIELDS")
            input_tokens=receipt.get("input_tokens",0)
            output_tokens=receipt.get("output_tokens",0)
            if any(type(n) is not int or n<0 for n in (input_tokens,output_tokens)):
                raise ValueError("INVALID_USAGE")
            if db.execute(
                "SELECT COUNT(*) FROM usage_events WHERE job_id=? AND provider_receipt=?",
                (job_id,receipt_id)
            ).fetchone()[0]:
                raise ValueError("DUPLICATE_PROVIDER_RECEIPT")
            # Receipt + usage are committed atomically; never persist prompts or model output.
            with db:
                db.execute("UPDATE steps SET status='COMPLETE',receipt=? WHERE job_id=? AND role=?",
                           (json.dumps(receipt,sort_keys=True),job_id,role))
                db.execute(
                    "INSERT INTO usage_events(job_id,role,input_tokens,output_tokens,"
                    "estimated_krw,provider_receipt) VALUES(?,?,?,?,?,?)",
                    (job_id,role,input_tokens,output_tokens,None,receipt_id))
        except BaseException:
            with db:
                db.execute("UPDATE steps SET status='BLOCKED' WHERE job_id=? AND role=?",
                           (job_id,role))
                db.execute("UPDATE jobs SET state='BLOCKED',updated=? WHERE id=?",
                           (int(time.time()),job_id))
            raise
        if fail_after==role:
            raise RuntimeError("SIMULATED_PROCESS_INTERRUPTION")
    with db:
        db.execute("UPDATE jobs SET state='REVIEW_REQUIRED',updated=? WHERE id=?",
                   (int(time.time()),job_id))
    return {"job_id":job_id,"state":"REVIEW_REQUIRED","role_receipts":5,
            "independent_review":"NOT_ATTESTED","release":"BLOCKED"}

def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("--db",type=Path,required=True)
    p.add_argument("--job-id",required=True)
    p.add_argument("--task",required=True)
    a=p.parse_args(argv)
    a.db.parent.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(a.db) as db:
        setup(db)
        try:dispatch(db,a.job_id,a.task)
        except PermissionError as e:
            print(json.dumps({"status":"BLOCKED","reason":str(e),"paid_calls":0}))
            return 3
    return 0
if __name__=="__main__":raise SystemExit(main())
