"""CLI app to parse a FortiWeb server-policy API response and store required fields in PostgreSQL.

Usage:
  python -m app.server_policy_parser --json-file /path/to/server_policies.json --device-name fw-ank-prod
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Any


def fortiweb_text_to_bool(value: Any) -> bool | None:
    if value is None:
        return None

    normalized = str(value).strip().lower()
    if normalized in {"enable", "enabled", "true", "1", "yes"}:
        return True
    if normalized in {"disable", "disabled", "false", "0", "no"}:
        return False
    return None


def extract_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("results"), list):
        return [item for item in payload["results"] if isinstance(item, dict)]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [payload]
    raise ValueError("Payload must be an object, array, or an object containing a results array.")


def parse_required_fields(record: dict[str, Any]) -> dict[str, Any] | None:
    server_policy_name = (
        record.get("server_policy_name")
        or record.get("server-policy-name")
        or record.get("server-policy")
        or record.get("name")
    )
    if not server_policy_name:
        return None

    return {
        "server_policy_name": server_policy_name,
        "web_protection_profile_name": (
            record.get("web_protection_profile_name")
            or record.get("web-protection-profile-name")
            or record.get("web-protection-profile")
        ),
        "server_pool_name": record.get("server_pool_name") or record.get("server-pool-name") or record.get("server-pool"),
        "traffic_mirror": fortiweb_text_to_bool(record.get("traffic_mirror") or record.get("traffic-mirror")),
        "fortiweb_id": record.get("id"),
        "policy_id": record.get("policy-id"),
        "deployment_mode": record.get("deployment-mode"),
        "protocol": record.get("protocol"),
        "v_zone": record.get("v-zone"),
        "status": fortiweb_text_to_bool(record.get("status")),
        "ssl_enabled": fortiweb_text_to_bool(record.get("ssl")),
        "http2_enabled": fortiweb_text_to_bool(record.get("http2")),
        "tlog_enabled": fortiweb_text_to_bool(record.get("tlog")),
        "monitor_mode_enabled": fortiweb_text_to_bool(record.get("monitor-mode")),
        "traffic_mirror_profile": record.get("traffic-mirror-profile"),
        "traffic_mirror_type": record.get("traffic-mirror-type"),
        "allow_hosts_policy_name": record.get("allow-hosts"),
        "replacemsg_name": record.get("replacemsg"),
        "half_open_threshold": record.get("half-open-threshold"),
        "client_timeout": record.get("client-timeout"),
        "tcp_conn_timeout": record.get("tcp-conn-timeout"),
        "comment_text": record.get("comment"),
        "raw_json": record,
    }


def ensure_device(cursor: Any, device_name: str) -> int:
    cursor.execute("SELECT id FROM devices WHERE device_name = %s", (device_name,))
    row = cursor.fetchone()
    if row:
        return int(row[0])

    cursor.execute("INSERT INTO devices (device_name) VALUES (%s) RETURNING id", (device_name,))
    return int(cursor.fetchone()[0])


def upsert_server_policies(conn: Any, device_id: int, parsed_records: list[dict[str, Any]]) -> int:
    from psycopg2.extras import Json, execute_values

    if not parsed_records:
        return 0

    rows = [
        (
            device_id,
            rec["server_policy_name"],
            rec["web_protection_profile_name"],
            rec["server_pool_name"],
            rec["traffic_mirror"],
            rec["fortiweb_id"],
            rec["policy_id"],
            rec["deployment_mode"],
            rec["protocol"],
            rec["v_zone"],
            rec["status"],
            rec["ssl_enabled"],
            rec["http2_enabled"],
            rec["tlog_enabled"],
            rec["monitor_mode_enabled"],
            rec["traffic_mirror_profile"],
            rec["traffic_mirror_type"],
            rec["allow_hosts_policy_name"],
            rec["replacemsg_name"],
            rec["half_open_threshold"],
            rec["client_timeout"],
            rec["tcp_conn_timeout"],
            rec["comment_text"],
            Json(rec["raw_json"]),
        )
        for rec in parsed_records
    ]

    with conn.cursor() as cursor:
        execute_values(
            cursor,
            """
            INSERT INTO server_policies (
                device_id, server_policy_name, web_protection_profile_name, server_pool_name,
                traffic_mirror, fortiweb_id, policy_id, deployment_mode, protocol, v_zone,
                status, ssl_enabled, http2_enabled, tlog_enabled, monitor_mode_enabled,
                traffic_mirror_profile, traffic_mirror_type, allow_hosts_policy_name, replacemsg_name,
                half_open_threshold, client_timeout, tcp_conn_timeout, comment_text, raw_json
            ) VALUES %s
            ON CONFLICT (device_id, server_policy_name)
            DO UPDATE SET
                web_protection_profile_name = EXCLUDED.web_protection_profile_name,
                server_pool_name = EXCLUDED.server_pool_name,
                traffic_mirror = EXCLUDED.traffic_mirror,
                fortiweb_id = EXCLUDED.fortiweb_id,
                policy_id = EXCLUDED.policy_id,
                deployment_mode = EXCLUDED.deployment_mode,
                protocol = EXCLUDED.protocol,
                v_zone = EXCLUDED.v_zone,
                status = EXCLUDED.status,
                ssl_enabled = EXCLUDED.ssl_enabled,
                http2_enabled = EXCLUDED.http2_enabled,
                tlog_enabled = EXCLUDED.tlog_enabled,
                monitor_mode_enabled = EXCLUDED.monitor_mode_enabled,
                traffic_mirror_profile = EXCLUDED.traffic_mirror_profile,
                traffic_mirror_type = EXCLUDED.traffic_mirror_type,
                allow_hosts_policy_name = EXCLUDED.allow_hosts_policy_name,
                replacemsg_name = EXCLUDED.replacemsg_name,
                half_open_threshold = EXCLUDED.half_open_threshold,
                client_timeout = EXCLUDED.client_timeout,
                tcp_conn_timeout = EXCLUDED.tcp_conn_timeout,
                comment_text = EXCLUDED.comment_text,
                raw_json = EXCLUDED.raw_json,
                updated_at = NOW()
            """,
            rows,
        )

    conn.commit()
    return len(rows)


def normalize_database_url(url: str) -> str:
    return url.replace("postgresql+psycopg2://", "postgresql://", 1)


def main() -> None:
    import psycopg2

    parser = argparse.ArgumentParser(description="Parse FortiWeb server-policy JSON and upsert required fields.")
    parser.add_argument("--json-file", required=True, help="Path to API response JSON file.")
    parser.add_argument("--device-name", required=True, help="Device name used in devices table.")
    parser.add_argument(
        "--database-url",
        default=os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/fortiweb_inventory"),
        help="PostgreSQL connection URL.",
    )
    args = parser.parse_args()

    with open(args.json_file, "r", encoding="utf-8") as f:
        payload = json.load(f)

    records = extract_records(payload)
    parsed = [row for row in (parse_required_fields(record) for record in records) if row is not None]

    conn = psycopg2.connect(normalize_database_url(args.database_url))
    try:
        with conn.cursor() as cursor:
            device_id = ensure_device(cursor, args.device_name)
            conn.commit()

        upserted_count = upsert_server_policies(conn, device_id, parsed)
    finally:
        conn.close()

    print(f"Device ID: {device_id}")
    print(f"Records in payload: {len(records)}")
    print(f"Records upserted: {upserted_count}")


if __name__ == "__main__":
    main()
