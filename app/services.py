import json
from urllib.parse import urlparse
from urllib.parse import quote

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
    if isinstance(value, (int, float)):
        return value != 0
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
        allow_hosts = _normalize_optional_text(item.get("allow_hosts") or item.get("allow-hosts") or item.get("allowhosts"))
        rows.append(
            {
                "server_policy_name": policy_name,
                "web_protection_profile_name": web_protection_profile_name,
                "server_pool_name": server_pool_name,
                "allow_hosts": allow_hosts,
                "traffic_mirror": _as_bool(
                    item.get("traffic_mirror")
                    or item.get("traffic-mirror")
                    or item.get("traffic_mirror_val")
                    or item.get("traffic-mirror_val")
                ),
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

        db.execute(
            text(
                """
                INSERT INTO server_policy (
                    device_id,
                    server_policy_name,
                    web_protection_profile_name,
                    server_pool_name,
                    allow_hosts,
                    traffic_mirror,
                    raw_json
                )
                VALUES (
                    :device_id,
                    :server_policy_name,
                    :web_protection_profile_name,
                    :server_pool_name,
                    :allow_hosts,
                    :traffic_mirror,
                    CAST(:raw_json AS jsonb)
                )
                ON CONFLICT (device_id, server_policy_name) DO UPDATE SET
                    web_protection_profile_name = EXCLUDED.web_protection_profile_name,
                    server_pool_name = EXCLUDED.server_pool_name,
                    allow_hosts = EXCLUDED.allow_hosts,
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
                "allow_hosts": row["allow_hosts"],
                "traffic_mirror": row["traffic_mirror"],
                "raw_json": json.dumps(row["raw_json"]),
            },
        )


def _extract_allow_hosts_rows(payload: dict, allow_hosts_name: str) -> list[dict]:
    results = payload.get("results", []) if isinstance(payload, dict) else []
    rows = []
    if not isinstance(results, list):
        return rows

    for item in results:
        if not isinstance(item, dict):
            continue
        host = _normalize_optional_text(item.get("host") or item.get("name") or item.get("ip") or item.get("address"))
        rows.append(
            {
                "allow_hosts": allow_hosts_name,
                "host": host,
                "raw_json": item,
            }
        )
    return rows


def _upsert_allow_hosts_rows(db: Session, device_id: int, server_policy_name: str, allow_hosts_name: str, rows: list[dict]):
    db.execute(
        text(
            """
            DELETE FROM server_policy_allow_hosts
            WHERE device_id = :device_id
              AND server_policy_name = :server_policy_name
              AND allow_hosts = :allow_hosts
            """
        ),
        {"device_id": device_id, "server_policy_name": server_policy_name, "allow_hosts": allow_hosts_name},
    )

    for row in rows:
        db.execute(
            text(
                """
                INSERT INTO server_policy_allow_hosts (
                    device_id,
                    server_policy_name,
                    allow_hosts,
                    host,
                    raw_json
                )
                VALUES (
                    :device_id,
                    :server_policy_name,
                    :allow_hosts,
                    :host,
                    CAST(:raw_json AS jsonb)
                )
                ON CONFLICT (device_id, server_policy_name, allow_hosts, host) DO UPDATE SET
                    raw_json = EXCLUDED.raw_json,
                    updated_at = now()
                """
            ),
            {
                "device_id": device_id,
                "server_policy_name": server_policy_name,
                "allow_hosts": row["allow_hosts"],
                "host": row["host"],
                "raw_json": json.dumps(row["raw_json"]),
            },
        )


def _extract_server_pool_row(payload: dict, server_pool_name: str) -> dict:
    results = payload.get("results", []) if isinstance(payload, dict) else []
    result = results[0] if isinstance(results, list) and results and isinstance(results[0], dict) else {}

    return {
        "server_pool_name": server_pool_name,
        "ip": _normalize_optional_text(result.get("ip") or result.get("address")),
        "certificate_name": _normalize_optional_text(result.get("certificate_name") or result.get("certificate")),
        "sni_certificate_name": _normalize_optional_text(result.get("sni_certificate_name") or result.get("sni_name")),
        "intermediate_certificate_group_name": _normalize_optional_text(
            result.get("intermediate_certificate_group_name")
            or result.get("intermediate-group")
            or result.get("intermediate_group")
        ),
        "ssl_custom_cipher": _normalize_optional_text(result.get("ssl_custom_cipher") or result.get("ssl-custom-cipher")),
        "tls13_custom_cipher": _normalize_optional_text(result.get("tls13_custom_cipher") or result.get("tls13-custom-cipher")),
        "tls_v10": _as_bool(result.get("tls_v10") or result.get("tls-v10")),
        "tls_v11": _as_bool(result.get("tls_v11") or result.get("tls-v11")),
        "tls_v12": _as_bool(result.get("tls_v12") or result.get("tls-v12")),
        "tls_v13": _as_bool(result.get("tls_v13") or result.get("tls-v13")),
        "http2": _as_bool(result.get("http2")),
        "raw_json": result or {"server_pool_name": server_pool_name},
    }


def _upsert_server_pool_row(db: Session, device_id: int, row: dict):
    if row["certificate_name"]:
        db.execute(
            text(
                """
                INSERT INTO certificate_local (device_id, certificate_name)
                VALUES (:device_id, :certificate_name)
                ON CONFLICT (device_id, certificate_name) DO NOTHING
                """
            ),
            {"device_id": device_id, "certificate_name": row["certificate_name"]},
        )

    if row["sni_certificate_name"]:
        db.execute(
            text(
                """
                INSERT INTO certificate_sni (device_id, sni_name)
                VALUES (:device_id, :sni_name)
                ON CONFLICT (device_id, sni_name) DO NOTHING
                """
            ),
            {"device_id": device_id, "sni_name": row["sni_certificate_name"]},
        )

    if row["intermediate_certificate_group_name"]:
        db.execute(
            text(
                """
                INSERT INTO intermediate_certificate_groups (device_id, intermediate_certificate_group_name)
                VALUES (:device_id, :intermediate_certificate_group_name)
                ON CONFLICT (device_id, intermediate_certificate_group_name) DO NOTHING
                """
            ),
            {
                "device_id": device_id,
                "intermediate_certificate_group_name": row["intermediate_certificate_group_name"],
            },
        )

    db.execute(
        text(
            """
            INSERT INTO server_pool (
                device_id,
                server_pool_name,
                ip,
                certificate_name,
                sni_certificate_name,
                intermediate_certificate_group_name,
                ssl_custom_cipher,
                tls13_custom_cipher,
                tls_v10,
                tls_v11,
                tls_v12,
                tls_v13,
                http2,
                raw_json
            )
            VALUES (
                :device_id,
                :server_pool_name,
                CAST(:ip AS inet),
                :certificate_name,
                :sni_certificate_name,
                :intermediate_certificate_group_name,
                :ssl_custom_cipher,
                :tls13_custom_cipher,
                :tls_v10,
                :tls_v11,
                :tls_v12,
                :tls_v13,
                :http2,
                CAST(:raw_json AS jsonb)
            )
            ON CONFLICT (device_id, server_pool_name) DO UPDATE SET
                ip = EXCLUDED.ip,
                certificate_name = EXCLUDED.certificate_name,
                sni_certificate_name = EXCLUDED.sni_certificate_name,
                intermediate_certificate_group_name = EXCLUDED.intermediate_certificate_group_name,
                ssl_custom_cipher = EXCLUDED.ssl_custom_cipher,
                tls13_custom_cipher = EXCLUDED.tls13_custom_cipher,
                tls_v10 = EXCLUDED.tls_v10,
                tls_v11 = EXCLUDED.tls_v11,
                tls_v12 = EXCLUDED.tls_v12,
                tls_v13 = EXCLUDED.tls_v13,
                http2 = EXCLUDED.http2,
                raw_json = EXCLUDED.raw_json,
                updated_at = now()
            """
        ),
        {
            "device_id": device_id,
            "server_pool_name": row["server_pool_name"],
            "ip": row["ip"],
            "certificate_name": row["certificate_name"],
            "sni_certificate_name": row["sni_certificate_name"],
            "intermediate_certificate_group_name": row["intermediate_certificate_group_name"],
            "ssl_custom_cipher": row["ssl_custom_cipher"],
            "tls13_custom_cipher": row["tls13_custom_cipher"],
            "tls_v10": row["tls_v10"],
            "tls_v11": row["tls_v11"],
            "tls_v12": row["tls_v12"],
            "tls_v13": row["tls_v13"],
            "http2": row["http2"],
            "raw_json": json.dumps(row["raw_json"]),
        },
    )


def _fetch_and_upsert_server_pool(
    db: Session,
    device: ManagedDevice,
    server_pool_name: str,
    headers: dict,
):
    encoded_name = quote(server_pool_name, safe="")
    endpoint = f"/api/v2.0/cmdb/server-policy/server-pool/pserver-list?mkey={encoded_name}"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    server_pool_row = _extract_server_pool_row(payload, server_pool_name)
    _upsert_server_pool_row(db, device.id, server_pool_row)


def _fetch_and_upsert_allow_hosts(
    db: Session,
    device: ManagedDevice,
    server_policy_name: str,
    allow_hosts_name: str,
    headers: dict,
):
    encoded_name = quote(allow_hosts_name, safe="")
    endpoint = f"/api/v2.0/cmdb/server-policy/allow-hosts/host-list?mkey={encoded_name}"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    allow_host_rows = _extract_allow_hosts_rows(payload, allow_hosts_name)
    _upsert_allow_hosts_rows(db, device.id, server_policy_name, allow_hosts_name, allow_host_rows)


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
            unique_server_pools = {row["server_pool_name"] for row in rows if row["server_pool_name"]}
            for server_pool_name in unique_server_pools:
                _fetch_and_upsert_server_pool(db, device, server_pool_name, headers)
            _upsert_server_policy_rows(db, device.id, rows)
            for row in rows:
                if row["allow_hosts"]:
                    _fetch_and_upsert_allow_hosts(db, device, row["server_policy_name"], row["allow_hosts"], headers)
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
                sp.server_policy_name,
                sp.server_pool_name,
                sp.allow_hosts,
                pool.ip AS server_pool_ip,
                pool.tls13_custom_cipher,
                pool.tls_v10,
                pool.tls_v11,
                pool.tls_v12,
                pool.tls_v13,
                pool.http2
            FROM managed_devices d
            LEFT JOIN server_policy sp ON sp.device_id = d.id
            LEFT JOIN server_pool pool
                ON pool.device_id = sp.device_id
                AND pool.server_pool_name = sp.server_pool_name
            ORDER BY d.id DESC, sp.server_policy_name ASC
            """
        )
    ).mappings().all()

    allow_host_rows = db.execute(
        text(
            """
            SELECT
                device_id,
                server_policy_name,
                allow_hosts,
                host,
                raw_json
            FROM server_policy_allow_hosts
            ORDER BY id ASC
            """
        )
    ).mappings().all()

    allow_hosts_by_policy = {}
    for row in allow_host_rows:
        key = (row["device_id"], row["server_policy_name"])
        allow_hosts_by_policy.setdefault(key, []).append(
            {
                "allow_hosts": row["allow_hosts"],
                "host": row["host"],
                "raw_json": row["raw_json"],
            }
        )

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
            by_device[device_id]["server_policies"].append(
                {
                    "server_policy_name": row["server_policy_name"],
                    "server_pool_name": row["server_pool_name"],
                    "allow_hosts": row["allow_hosts"],
                    "ip": row["server_pool_ip"],
                    "tls13_custom_cipher": row["tls13_custom_cipher"],
                    "tls_v10": row["tls_v10"],
                    "tls_v11": row["tls_v11"],
                    "tls_v12": row["tls_v12"],
                    "tls_v13": row["tls_v13"],
                    "http2": row["http2"],
                    "allow_hosts_entries": allow_hosts_by_policy.get((device_id, row["server_policy_name"]), []),
                }
            )

    return {"devices": list(by_device.values())}
