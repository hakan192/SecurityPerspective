import json
from contextlib import contextmanager
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras

from .config import db_dsn


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def get_conn():
    conn = psycopg2.connect(db_dsn())
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS raw_snapshots (
                    id BIGSERIAL PRIMARY KEY,
                    source TEXT NOT NULL,
                    collected_at TIMESTAMPTZ NOT NULL,
                    version_tag TEXT NOT NULL,
                    raw_payload JSONB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS parsed_controls (
                    id BIGSERIAL PRIMARY KEY,
                    snapshot_id BIGINT REFERENCES raw_snapshots(id) ON DELETE CASCADE,
                    control_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    expected BOOLEAN NOT NULL,
                    actual BOOLEAN NOT NULL,
                    status TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    weight INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS assessments (
                    id BIGSERIAL PRIMARY KEY,
                    snapshot_id BIGINT REFERENCES raw_snapshots(id) ON DELETE CASCADE,
                    assessed_at TIMESTAMPTZ NOT NULL,
                    overall_score NUMERIC(5,2) NOT NULL,
                    maturity_level TEXT NOT NULL,
                    category_scores JSONB NOT NULL,
                    per_control JSONB NOT NULL,
                    improvements JSONB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS jobs (
                    id BIGSERIAL PRIMARY KEY,
                    job_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload JSONB,
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL,
                    error TEXT
                );
                """
            )
            conn.commit()


def enqueue_job(job_type: str, payload: dict) -> int:
    now = utc_now()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO jobs(job_type, status, payload, created_at, updated_at)
                VALUES(%s, 'pending', %s::jsonb, %s, %s)
                RETURNING id
                """,
                (job_type, json.dumps(payload), now, now),
            )
            job_id = cur.fetchone()[0]
            conn.commit()
            return int(job_id)


def get_job(job_id: int) -> dict | None:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM jobs WHERE id=%s", (job_id,))
            row = cur.fetchone()
            return dict(row) if row else None
