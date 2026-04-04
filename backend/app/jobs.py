import json

import psycopg2.extras

from .db import get_conn, utc_now
from .fortiweb import pull_config
from .parser import extract_controls
from .scoring import evaluate, load_baseline


async def run_collect_job(job_id: int) -> None:
    _set_job_status(job_id, "running")
    try:
        raw = await pull_config()
        parsed = extract_controls(raw)
        result = evaluate(parsed, load_baseline())
        snapshot_id = _store_snapshot(raw)
        _store_parsed(snapshot_id, result["per_control"])
        _store_assessment(snapshot_id, result)
        _set_job_status(job_id, "completed")
    except Exception as exc:
        _set_job_status(job_id, "failed", str(exc))


def _set_job_status(job_id: int, status: str, error: str | None = None) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE jobs SET status=%s, updated_at=%s, error=%s WHERE id=%s",
                (status, utc_now(), error, job_id),
            )
            conn.commit()


def _store_snapshot(raw: dict) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO raw_snapshots(source, collected_at, version_tag, raw_payload)
                VALUES(%s, %s, %s, %s::jsonb)
                RETURNING id
                """,
                ("fortiweb", utc_now(), utc_now(), json.dumps(raw)),
            )
            snapshot_id = cur.fetchone()[0]
            conn.commit()
            return int(snapshot_id)


def _store_parsed(snapshot_id: int, controls: list[dict]) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            for control in controls:
                cur.execute(
                    """
                    INSERT INTO parsed_controls(snapshot_id, control_id, category, expected, actual, status, score, weight)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        snapshot_id,
                        control["control_id"],
                        control["category"],
                        control["expected"],
                        control["actual"],
                        control["status"],
                        control["score"],
                        control["weight"],
                    ),
                )
            conn.commit()


def _store_assessment(snapshot_id: int, result: dict) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assessments(snapshot_id, assessed_at, overall_score, maturity_level, category_scores, per_control, improvements)
                VALUES(%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s::jsonb)
                """,
                (
                    snapshot_id,
                    utc_now(),
                    result["overall_score"],
                    result["maturity_level"],
                    json.dumps(result["category_scores"]),
                    json.dumps(result["per_control"]),
                    json.dumps(result["improvements"]),
                ),
            )
            conn.commit()


def fetch_next_pending_job() -> dict | None:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT * FROM jobs
                WHERE status='pending' AND job_type='collect'
                ORDER BY created_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
                """
            )
            job = cur.fetchone()
            conn.commit()
            return dict(job) if job else None
