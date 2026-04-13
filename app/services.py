import json
from urllib.parse import urlparse

import requests
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.models import ManagedDevice


def _build_device_base_url(device_ip: str) -> str:
    parsed = urlparse(settings.fortiweb_base_url)
    scheme = parsed.scheme or "https"
    port = f":{parsed.port}" if parsed.port else ""
    return f"{scheme}://{device_ip}{port}"


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"true", "1", "yes", "on", "enable", "enabled"}
    return None


def _normalize_optional_text(value):
    if value is None:
        return None
    if not isinstance(value, str):
        return str(value)
    normalized = value.strip()
    return normalized or None


def _extract_policy_rows(payload: dict) -> list[dict]:
    results = payload.get("results", []) if isinstance(payload, dict) else []
    rows = []
    for item in results:
        if not isinstance(item, dict):
            continue
        policy_name = item.get("name")
        if not isinstance(policy_name, str) or not policy_name.strip():
            continue

        web_protection_profile_name = _normalize_optional_text(
            item.get("web_protection_profile_name")
            or item.get("web_protection_profile")
            or item.get("web-protection-profile")
        )
        server_pool_name = _normalize_optional_text(item.get("server_pool_name") or item.get("server_pool") or item.get("server-pool"))
        rows.append(
            {
                "server_policy_name": policy_name,
                "web_protection_profile_name": web_protection_profile_name,
                "server_pool_name": server_pool_name,
                "traffic_mirror": _as_bool(item.get("traffic_mirror")),
                "raw_json": item,
            }
        )
    return rows


def _upsert_server_policy_rows(db: Session, device_id: int, rows: list[dict]):
    for row in rows:
        if row["web_protection_profile_name"]:
            db.execute(
                text(
                    """
                    INSERT INTO web_protection_profiles (device_id, web_protection_profile_name)
                    VALUES (:device_id, :web_protection_profile_name)
                    ON CONFLICT (device_id, web_protection_profile_name) DO NOTHING
                    """
                ),
                {
                    "device_id": device_id,
                    "web_protection_profile_name": row["web_protection_profile_name"],
                },
            )

        if row["server_pool_name"]:
            db.execute(
                text(
                    """
                    INSERT INTO server_pool (device_id, server_pool_name)
                    VALUES (:device_id, :server_pool_name)
                    ON CONFLICT (device_id, server_pool_name) DO NOTHING
                    """
                ),
                {
                    "device_id": device_id,
                    "server_pool_name": row["server_pool_name"],
                },
            )

        db.execute(
            text(
                """
                INSERT INTO server_policy (
                    device_id,
                    server_policy_name,
                    web_protection_profile_name,
                    server_pool_name,
                    traffic_mirror,
                    raw_json
                )
                VALUES (
                    :device_id,
                    :server_policy_name,
                    :web_protection_profile_name,
                    :server_pool_name,
                    :traffic_mirror,
                    CAST(:raw_json AS jsonb)
                )
                ON CONFLICT (device_id, server_policy_name) DO UPDATE SET
                    web_protection_profile_name = EXCLUDED.web_protection_profile_name,
                    server_pool_name = EXCLUDED.server_pool_name,
                    traffic_mirror = EXCLUDED.traffic_mirror,
                    raw_json = EXCLUDED.raw_json,
                    updated_at = now()
                """
            ),
            {
                "device_id": device_id,
                "server_policy_name": row["server_policy_name"],
                "web_protection_profile_name": row["web_protection_profile_name"],
                "server_pool_name": row["server_pool_name"],
                "traffic_mirror": row["traffic_mirror"],
                "raw_json": json.dumps(row["raw_json"]),
            },
        )


def fetch_and_store_server_policies_by_device(db: Session, devices: list[ManagedDevice]) -> dict:
    per_device = []
    endpoint = settings.fortiweb_server_policy_endpoint

    for device in devices:
        headers = {}
        if device.apikey:
            headers["Authorization"] = device.apikey
        elif settings.fortiweb_token:
            headers["Authorization"] = settings.fortiweb_token

        device_result = {
            "device_id": device.id,
            "device_name": device.name,
            "device_ip": device.ip,
            "server_policies": [],
            "error": "",
        }

        try:
            url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
            response = requests.get(
                url,
                headers=headers,
                timeout=30,
                verify=settings.fortiweb_verify_ssl,
            )
            response.raise_for_status()
            payload = response.json()
            rows = _extract_policy_rows(payload)
            _upsert_server_policy_rows(db, device.id, rows)
            db.commit()
            device_result["server_policies"] = [row["server_policy_name"] for row in rows]
        except Exception as exc:
            db.rollback()
            device_result["error"] = str(exc)

        per_device.append(device_result)

    return {"devices": per_device}


def load_server_policies_from_db(db: Session) -> dict:
    rows = db.execute(
        text(
            """
            SELECT
                d.id AS device_id,
                d.name AS device_name,
                d.ip AS device_ip,
                sp.server_policy_name
            FROM managed_devices d
            LEFT JOIN server_policy sp ON sp.device_id = d.id
            ORDER BY d.id DESC, sp.server_policy_name ASC
            """
        )
    ).mappings().all()

    by_device = {}
    for row in rows:
        device_id = row["device_id"]
        if device_id not in by_device:
            by_device[device_id] = {
                "device_id": row["device_id"],
                "device_name": row["device_name"],
                "device_ip": row["device_ip"],
                "server_policies": [],
                "error": "",
            }
        if row["server_policy_name"]:
            by_device[device_id]["server_policies"].append(row["server_policy_name"])

    return {"devices": list(by_device.values())}
