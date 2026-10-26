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
    """Worker returns receipt dict; no worker => fail closed before any role runs."""
    if worker is None:raise PermissionError("NO_AUTHORIZED_MODEL_WORKER")
    digest=hashlib.sha256(task.encode("utf-8")).hexdigest()
    now=int(time.time())
    with db:
        row=db.execute("SELECT task_hash FROM jobs WHERE id=?",(job_id,)).fetchone()
        if row and row[0]!=digest:raise ValueError("JOB_ID_TASK_MISMATCH")
        if not row:db.execute("INSERT INTO jobs VALUES(?,?,?,?)",(job_id,digest,"RUNNING",now))
    for index,role in enumerate(ROLES):
        existing=db.execute("SELECT status FROM steps WHERE job_id=? AND role=?",(job_id,role)).fetchone()
        if existing and existing[0]=="COMPLETE":continue
        # An unfinished role is retried only with an idempotent, explicitly supplied worker.
        with db:
            db.execute("INSERT INTO steps VALUES(?,?,?,?,?) ON CONFLICT(job_id,role) DO UPDATE SET status='RUNNING',receipt=NULL",(job_id,role,index,"RUNNING",None))
        try:
            receipt=worker(role,task)
            if not isinstance(receipt,dict) or not receipt.get("receipt_id"):raise ValueError("MISSING_WORKER_RECEIPT")
            input_tokens=receipt.get("input_tokens",0)
            output_tokens=receipt.get("output_tokens",0)
            if any(type(n) is not int or n<0 for n in (input_tokens,output_tokens)):raise ValueError("INVALID_USAGE")
            with db:
                db.execute("UPDATE steps SET status='COMPLETE',receipt=? WHERE job_id=? AND role=?",(json.dumps(receipt,sort_keys=True),job_id,role))
                db.execute("INSERT INTO usage_events(job_id,role,input_tokens,output_tokens,estimated_krw,provider_receipt) VALUES(?,?,?,?,?,?)",(job_id,role,input_tokens,output_tokens,None,receipt["receipt_id"]))
        except Exception:
            with db:
                db.execute("UPDATE steps SET status='BLOCKED' WHERE job_id=? AND role=?",(job_id,role))
                db.execute("UPDATE jobs SET state='BLOCKED',updated=? WHERE id=?",(int(time.time()),job_id))
            raise
        if fail_after==role:raise RuntimeError("SIMULATED_PROCESS_INTERRUPTION")
    with db:db.execute("UPDATE jobs SET state='REVIEW_REQUIRED',updated=? WHERE id=?",(int(time.time()),job_id))
    return {"job_id":job_id,"state":"REVIEW_REQUIRED","role_receipts":5,"independent_review":"NOT_ATTESTED","release":"BLOCKED"}
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
