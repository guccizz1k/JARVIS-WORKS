"""Offline durable J team simulation with SQLite task checkpoints.
No API calls. No real independent AI execution. Standard library only.
"""
import argparse
import hashlib
import json
import sqlite3
import time
import uuid
from pathlib import Path

ROLES=("deputy","deputy_manager","manager","director","jarvis_lead")
def initialize(db):
    db.execute("""CREATE TABLE IF NOT EXISTS jobs (
        id TEXT PRIMARY KEY, task_hash TEXT NOT NULL, state TEXT NOT NULL,
        created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS checkpoints (
        job_id TEXT NOT NULL, role TEXT NOT NULL, ordinal INTEGER NOT NULL,
        status TEXT NOT NULL, receipt TEXT NOT NULL,
        PRIMARY KEY(job_id,role),
        FOREIGN KEY(job_id) REFERENCES jobs(id))""")
    db.commit()
def simulate(db,job_id,task):
    now=int(time.time())
    digest=hashlib.sha256(task.encode()).hexdigest()
    with db:
        old=db.execute("SELECT task_hash FROM jobs WHERE id=?",(job_id,)).fetchone()
        if old and old[0]!=digest:raise ValueError("JOB_ID_TASK_MISMATCH")
        if not old:db.execute("INSERT INTO jobs VALUES (?,?,?,?,?)",(job_id,digest,"RUNNING",now,now))
        for i,role in enumerate(ROLES):
            receipt=json.dumps({"role":role,"kind":"OFFLINE_SIMULATION","provider_response_id":None,
                                "real_model_executed":False,"test_status":"NOT_RUN"},sort_keys=True)
            db.execute("INSERT OR IGNORE INTO checkpoints VALUES (?,?,?,?,?)",
                       (job_id,role,i,"SIMULATED",receipt))
        db.execute("UPDATE jobs SET state='SIMULATED_ONLY',updated_at=? WHERE id=?",(now,job_id))
    return {"job_id":job_id,"state":"SIMULATED_ONLY","roles":[x[0] for x in db.execute(
        "SELECT role FROM checkpoints WHERE job_id=? ORDER BY ordinal",(job_id,))],
        "actual_model_calls":0,"independent_review":"NOT_RUN","release":"BLOCKED"}
def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("--db",type=Path,required=True)
    p.add_argument("--task",required=True)
    p.add_argument("--job-id")
    a=p.parse_args(argv)
    a.db.parent.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(a.db) as db:
        db.execute("PRAGMA foreign_keys=ON")
        initialize(db)
        try: result=simulate(db,a.job_id or str(uuid.uuid4()),a.task)
        except ValueError as e:
            print(json.dumps({"status":"BLOCKED","reason":str(e)}))
            return 3
    print(json.dumps(result,ensure_ascii=False))
    return 0
if __name__=="__main__":raise SystemExit(main())
