import json

import psycopg2.extras
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from .config import users
from .db import enqueue_job, get_conn, get_job, init_db
from .scoring import load_baseline

app = FastAPI(title="SecurityPerspective API", version="0.2.0")
security = HTTPBasic()


def current_user(credentials: HTTPBasicCredentials = Depends(security)) -> dict:
    user = users().get(credentials.username)
    if not user or user["password"] != credentials.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return {"username": credentials.username, "role": user["role"]}


def role_guard(*allowed: str):
    def checker(user: dict = Depends(current_user)):
        if user["role"] not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user

    return checker


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/collect")
def collect(user: dict = Depends(role_guard("admin", "analyst"))) -> dict:
    job_id = enqueue_job("collect", {"requested_by": user["username"]})
    return {"job_id": job_id, "status": "queued"}


@app.get("/api/jobs/{job_id}")
def job(job_id: int, user: dict = Depends(role_guard("admin", "analyst", "viewer"))) -> dict:
    item = get_job(job_id)
    if not item:
        raise HTTPException(status_code=404, detail="Job not found")
    return item


@app.get("/api/snapshots")
def snapshots(user: dict = Depends(role_guard("admin", "analyst", "viewer"))) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id, source, collected_at, version_tag FROM raw_snapshots ORDER BY id DESC LIMIT 100")
            return [dict(r) for r in cur.fetchall()]


@app.get("/api/snapshots/{snapshot_id}")
def snapshot(snapshot_id: int, user: dict = Depends(role_guard("admin", "analyst", "viewer"))) -> dict:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM raw_snapshots WHERE id=%s", (snapshot_id,))
            raw = cur.fetchone()
            if not raw:
                raise HTTPException(status_code=404, detail="Snapshot not found")
            cur.execute("SELECT control_id, category, expected, actual, status, score, weight FROM parsed_controls WHERE snapshot_id=%s", (snapshot_id,))
            parsed = [dict(r) for r in cur.fetchall()]
            return {"snapshot": dict(raw), "parsed_controls": parsed}


@app.get("/api/assessments/{snapshot_id}")
def assessment(snapshot_id: int, user: dict = Depends(role_guard("admin", "analyst", "viewer"))) -> dict:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM assessments WHERE snapshot_id=%s ORDER BY id DESC LIMIT 1", (snapshot_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Assessment not found")
            return dict(row)


@app.get("/api/reports/{snapshot_id}")
def report(snapshot_id: int, user: dict = Depends(role_guard("admin", "analyst", "viewer"))) -> JSONResponse:
    snapshot_data = snapshot(snapshot_id, user)
    assessment_data = assessment(snapshot_id, user)
    payload = {"snapshot": snapshot_data, "assessment": assessment_data}
    return JSONResponse(payload, headers={"Content-Disposition": f"attachment; filename=report-{snapshot_id}.json"})


@app.get("/api/baseline")
def baseline(user: dict = Depends(role_guard("admin", "analyst", "viewer"))) -> dict:
    return load_baseline()


@app.get("/api/dashboard")
def dashboard(user: dict = Depends(role_guard("admin", "analyst", "viewer"))) -> dict:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id, source, collected_at FROM raw_snapshots ORDER BY id DESC LIMIT 10")
            snapshots = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT snapshot_id, overall_score, maturity_level, assessed_at FROM assessments ORDER BY id DESC LIMIT 10")
            assessments = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT COUNT(*) FROM jobs WHERE status='pending'")
            pending_jobs = cur.fetchone()["count"]
    return {"snapshots": snapshots, "assessments": assessments, "pending_jobs": pending_jobs}
