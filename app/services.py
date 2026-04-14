import json
from urllib.parse import urlparse
from urllib.parse import quote

import requests
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.models import ManagedDevice

WEB_PROTECTION_PROFILE_FIELD_MAP = {
    "signature_rule": ["signature_rule", "signature-rule"],
    "http_protocol_parameter_restriction": ["http_protocol_parameter_restriction", "http-protocol-parameter-restriction"],
    "cookie_security_policy": ["cookie_security_policy", "cookie-security-policy"],
    "custom_access_policy": ["custom_access_policy", "custom-access-policy"],
    "csrf_protection": ["csrf_protection", "csrf-protection"],
    "syntax_based_attack_detection": ["syntax_based_attack_detection", "syntax-based-attack-detection"],
    "parameter_validation_rule": ["parameter_validation_rule", "parameter-validation-rule"],
    "hidden_fields_protection": ["hidden_fields_protection", "hidden-fields-protection"],
    "file_upload_policy": ["file_upload_policy", "file-upload-policy"],
    "webshell_detection_policy": ["webshell_detection_policy", "webshell-detection-policy"],
    "allow_method_policy": ["allow_method_policy", "allow-method-policy"],
    "bot_mitigate_policy": ["bot_mitigate_policy", "bot-mitigate-policy"],
    "xml_validation_policy": ["xml_validation_policy", "xml-validation-policy"],
    "json_validation_policy": ["json_validation_policy", "json-validation-policy"],
    "graphql_validation_policy": ["graphql_validation_policy", "graphql-validation-policy"],
    "openapi_validation_policy": ["openapi_validation_policy", "openapi-validation-policy"],
    "application_layer_dos_prevention": ["application_layer_dos_prevention", "application-layer-dos-prevention"],
    "ip_list_policy": ["ip_list_policy", "ip-list-policy"],
    "ip_intelligence": ["ip_intelligence", "ip-intelligence"],
    "geo_block_list_policy": ["geo_block_list_policy", "geo-block-list-policy"],
    "waiting_room_policy": ["waiting_room_policy", "waiting-room-policy"],
    "user_tracking_policy": ["user_tracking_policy", "user-tracking-policy"],
    "websocket_security_policy": ["websocket_security_policy", "websocket-security-policy"],
    "cors_protection_policy": ["cors_protection_policy", "cors-protection-policy"],
}

SIGNATURE_FIELD_MAP = {
    "cross_site_scripting": ["Cross Site Scripting", "cross_site_scripting", "cross-site-scripting"],
    "cross_site_scripting_extended": ["Cross Site Scripting (Extended)", "cross_site_scripting_extended", "cross-site-scripting-extended"],
    "sql_injection": ["SQL Injection", "sql_injection", "sql-injection"],
    "sql_injection_extended": ["SQL Injection (Extended)", "sql_injection_extended", "sql-injection-extended"],
    "generic_attacks": ["Generic Attacks", "generic_attacks", "generic-attacks"],
    "generic_attacks_extended": ["Generic Attacks(Extended)", "Generic Attacks (Extended)", "generic_attacks_extended", "generic-attacks-extended"],
    "known_exploits": ["Known Exploits", "known_exploits", "known-exploits"],
    "trojans": ["Trojans", "trojans"],
    "information_disclosure": ["Information Disclosure", "information_disclosure", "information-disclosure"],
    "personally_identifiable_information": [
        "Personally Identifiable Information",
        "personally_identifiable_information",
        "personally-identifiable-information",
    ],
}


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


def _extract_by_aliases(item: dict, aliases: list[str]):
    for alias in aliases:
        if alias in item:
            return item[alias]
    return None


def _extract_web_protection_profile_rows(payload: dict) -> list[dict]:
    results = payload.get("results", []) if isinstance(payload, dict) else []
    rows = []
    if not isinstance(results, list):
        return rows

    for item in results:
        if not isinstance(item, dict):
            continue
        profile_name = _normalize_optional_text(item.get("name") or item.get("web-protection-profile") or item.get("web_protection_profile"))
        if not profile_name:
            continue
        row = {"web_protection_profile_name": profile_name}
        for normalized_key, aliases in WEB_PROTECTION_PROFILE_FIELD_MAP.items():
            row[normalized_key] = _normalize_optional_text(_extract_by_aliases(item, aliases))
        rows.append(row)
    return rows


def _upsert_web_protection_profile_rows(db: Session, device_id: int, rows: list[dict]):
    for row in rows:
        db.execute(
            text(
                """
                INSERT INTO web_protection_profiles (
                    device_id,
                    web_protection_profile_name,
                    signature_rule,
                    http_protocol_parameter_restriction,
                    cookie_security_policy,
                    custom_access_policy,
                    csrf_protection,
                    syntax_based_attack_detection,
                    parameter_validation_rule,
                    hidden_fields_protection,
                    file_upload_policy,
                    webshell_detection_policy,
                    allow_method_policy,
                    bot_mitigate_policy,
                    xml_validation_policy,
                    json_validation_policy,
                    graphql_validation_policy,
                    openapi_validation_policy,
                    application_layer_dos_prevention,
                    ip_list_policy,
                    ip_intelligence,
                    geo_block_list_policy,
                    waiting_room_policy,
                    user_tracking_policy,
                    websocket_security_policy,
                    cors_protection_policy
                )
                VALUES (
                    :device_id,
                    :web_protection_profile_name,
                    :signature_rule,
                    :http_protocol_parameter_restriction,
                    :cookie_security_policy,
                    :custom_access_policy,
                    :csrf_protection,
                    :syntax_based_attack_detection,
                    :parameter_validation_rule,
                    :hidden_fields_protection,
                    :file_upload_policy,
                    :webshell_detection_policy,
                    :allow_method_policy,
                    :bot_mitigate_policy,
                    :xml_validation_policy,
                    :json_validation_policy,
                    :graphql_validation_policy,
                    :openapi_validation_policy,
                    :application_layer_dos_prevention,
                    :ip_list_policy,
                    :ip_intelligence,
                    :geo_block_list_policy,
                    :waiting_room_policy,
                    :user_tracking_policy,
                    :websocket_security_policy,
                    :cors_protection_policy
                )
                ON CONFLICT (device_id, web_protection_profile_name) DO UPDATE SET
                    signature_rule = EXCLUDED.signature_rule,
                    http_protocol_parameter_restriction = EXCLUDED.http_protocol_parameter_restriction,
                    cookie_security_policy = EXCLUDED.cookie_security_policy,
                    custom_access_policy = EXCLUDED.custom_access_policy,
                    csrf_protection = EXCLUDED.csrf_protection,
                    syntax_based_attack_detection = EXCLUDED.syntax_based_attack_detection,
                    parameter_validation_rule = EXCLUDED.parameter_validation_rule,
                    hidden_fields_protection = EXCLUDED.hidden_fields_protection,
                    file_upload_policy = EXCLUDED.file_upload_policy,
                    webshell_detection_policy = EXCLUDED.webshell_detection_policy,
                    allow_method_policy = EXCLUDED.allow_method_policy,
                    bot_mitigate_policy = EXCLUDED.bot_mitigate_policy,
                    xml_validation_policy = EXCLUDED.xml_validation_policy,
                    json_validation_policy = EXCLUDED.json_validation_policy,
                    graphql_validation_policy = EXCLUDED.graphql_validation_policy,
                    openapi_validation_policy = EXCLUDED.openapi_validation_policy,
                    application_layer_dos_prevention = EXCLUDED.application_layer_dos_prevention,
                    ip_list_policy = EXCLUDED.ip_list_policy,
                    ip_intelligence = EXCLUDED.ip_intelligence,
                    geo_block_list_policy = EXCLUDED.geo_block_list_policy,
                    waiting_room_policy = EXCLUDED.waiting_room_policy,
                    user_tracking_policy = EXCLUDED.user_tracking_policy,
                    websocket_security_policy = EXCLUDED.websocket_security_policy,
                    cors_protection_policy = EXCLUDED.cors_protection_policy,
                    updated_at = now()
                """
            ),
            {"device_id": device_id, **row},
        )


def _extract_signature_row(payload: dict, signature_set_name: str) -> dict:
    results = payload.get("results", []) if isinstance(payload, dict) else []
    result = results[0] if isinstance(results, list) and results and isinstance(results[0], dict) else {}
    row = {"signature_set_name": signature_set_name, "raw_json": result or {"signature_set_name": signature_set_name}}
    for normalized_key, aliases in SIGNATURE_FIELD_MAP.items():
        row[normalized_key] = _normalize_optional_text(_extract_by_aliases(result, aliases))
    return row


def _upsert_signature_row(db: Session, device_id: int, row: dict):
    db.execute(
        text(
            """
            INSERT INTO signature (
                device_id,
                signature_set_name,
                cross_site_scripting,
                cross_site_scripting_extended,
                sql_injection,
                sql_injection_extended,
                generic_attacks,
                generic_attacks_extended,
                known_exploits,
                trojans,
                information_disclosure,
                personally_identifiable_information,
                raw_json
            )
            VALUES (
                :device_id,
                :signature_set_name,
                :cross_site_scripting,
                :cross_site_scripting_extended,
                :sql_injection,
                :sql_injection_extended,
                :generic_attacks,
                :generic_attacks_extended,
                :known_exploits,
                :trojans,
                :information_disclosure,
                :personally_identifiable_information,
                CAST(:raw_json AS jsonb)
            )
            ON CONFLICT (device_id, signature_set_name) DO UPDATE SET
                cross_site_scripting = EXCLUDED.cross_site_scripting,
                cross_site_scripting_extended = EXCLUDED.cross_site_scripting_extended,
                sql_injection = EXCLUDED.sql_injection,
                sql_injection_extended = EXCLUDED.sql_injection_extended,
                generic_attacks = EXCLUDED.generic_attacks,
                generic_attacks_extended = EXCLUDED.generic_attacks_extended,
                known_exploits = EXCLUDED.known_exploits,
                trojans = EXCLUDED.trojans,
                information_disclosure = EXCLUDED.information_disclosure,
                personally_identifiable_information = EXCLUDED.personally_identifiable_information,
                raw_json = EXCLUDED.raw_json,
                updated_at = now()
            """
        ),
        {"device_id": device_id, **row, "raw_json": json.dumps(row["raw_json"])},
    )


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


def _upsert_allow_hosts_rows(db: Session, device_id: int, allow_hosts_name: str, rows: list[dict]):
    db.execute(
        text(
            """
            DELETE FROM allow_hosts
            WHERE device_id = :device_id
              AND allow_hosts = :allow_hosts
            """
        ),
        {"device_id": device_id, "allow_hosts": allow_hosts_name},
    )

    for row in rows:
        db.execute(
            text(
                """
                INSERT INTO allow_hosts (
                    device_id,
                    allow_hosts,
                    host,
                    raw_json
                )
                VALUES (
                    :device_id,
                    :allow_hosts,
                    :host,
                    CAST(:raw_json AS jsonb)
                )
                ON CONFLICT (device_id, allow_hosts, host) DO UPDATE SET
                    raw_json = EXCLUDED.raw_json,
                    updated_at = now()
                """
            ),
            {
                "device_id": device_id,
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
    _upsert_allow_hosts_rows(db, device.id, allow_hosts_name, allow_host_rows)


def _fetch_and_upsert_web_protection_profiles(
    db: Session,
    device: ManagedDevice,
    headers: dict,
):
    endpoint = "/api/v2.0/cmdb/waf/web-protection-profile.inline-protection"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    web_protection_profile_rows = _extract_web_protection_profile_rows(payload)
    _upsert_web_protection_profile_rows(db, device.id, web_protection_profile_rows)
    return web_protection_profile_rows


def _fetch_and_upsert_signature(
    db: Session,
    device: ManagedDevice,
    signature_rule: str,
    headers: dict,
):
    encoded_name = quote(signature_rule, safe="")
    endpoint = f"/api/v2.0/waf/signatures?mkey={encoded_name}"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    signature_row = _extract_signature_row(payload, signature_rule)
    _upsert_signature_row(db, device.id, signature_row)


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
            web_protection_profile_rows = _fetch_and_upsert_web_protection_profiles(db, device, headers)
            unique_signature_rules = {row["signature_rule"] for row in web_protection_profile_rows if row.get("signature_rule")}
            for signature_rule in unique_signature_rules:
                _fetch_and_upsert_signature(db, device, signature_rule, headers)
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
            unique_allow_hosts = {row["allow_hosts"] for row in rows if row["allow_hosts"]}
            for allow_hosts_name in unique_allow_hosts:
                _fetch_and_upsert_allow_hosts(db, device, allow_hosts_name, headers)
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
                sp.web_protection_profile_name,
                sp.server_pool_name,
                sp.allow_hosts,
                wpp.signature_rule,
                wpp.http_protocol_parameter_restriction,
                wpp.cookie_security_policy,
                wpp.custom_access_policy,
                wpp.csrf_protection,
                wpp.syntax_based_attack_detection,
                wpp.parameter_validation_rule,
                wpp.hidden_fields_protection,
                wpp.file_upload_policy,
                wpp.webshell_detection_policy,
                wpp.allow_method_policy,
                wpp.bot_mitigate_policy,
                wpp.xml_validation_policy,
                wpp.json_validation_policy,
                wpp.graphql_validation_policy,
                wpp.openapi_validation_policy,
                wpp.application_layer_dos_prevention,
                wpp.ip_list_policy,
                wpp.ip_intelligence,
                wpp.geo_block_list_policy,
                wpp.waiting_room_policy,
                wpp.user_tracking_policy,
                wpp.websocket_security_policy,
                wpp.cors_protection_policy,
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
            LEFT JOIN web_protection_profiles wpp
                ON wpp.device_id = sp.device_id
                AND wpp.web_protection_profile_name = sp.web_protection_profile_name
            ORDER BY d.id DESC, sp.server_policy_name ASC
            """
        )
    ).mappings().all()

    allow_host_rows = db.execute(
        text(
            """
            SELECT
                device_id,
                allow_hosts,
                host,
                raw_json
            FROM allow_hosts
            ORDER BY id ASC
            """
        )
    ).mappings().all()

    allow_hosts_by_policy = {}
    for row in allow_host_rows:
        key = (row["device_id"], row["allow_hosts"])
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
                    "web_protection_profile_name": row["web_protection_profile_name"],
                    "server_pool_name": row["server_pool_name"],
                    "allow_hosts": row["allow_hosts"],
                    "ip": row["server_pool_ip"],
                    "tls13_custom_cipher": row["tls13_custom_cipher"],
                    "tls_v10": row["tls_v10"],
                    "tls_v11": row["tls_v11"],
                    "tls_v12": row["tls_v12"],
                    "tls_v13": row["tls_v13"],
                    "http2": row["http2"],
                    "allow_hosts_entries": allow_hosts_by_policy.get((device_id, row["allow_hosts"]), []),
                    "web_protection_profile_details": {
                        "signature_rule": row["signature_rule"],
                        "http_protocol_parameter_restriction": row["http_protocol_parameter_restriction"],
                        "cookie_security_policy": row["cookie_security_policy"],
                        "custom_access_policy": row["custom_access_policy"],
                        "csrf_protection": row["csrf_protection"],
                        "syntax_based_attack_detection": row["syntax_based_attack_detection"],
                        "parameter_validation_rule": row["parameter_validation_rule"],
                        "hidden_fields_protection": row["hidden_fields_protection"],
                        "file_upload_policy": row["file_upload_policy"],
                        "webshell_detection_policy": row["webshell_detection_policy"],
                        "allow_method_policy": row["allow_method_policy"],
                        "bot_mitigate_policy": row["bot_mitigate_policy"],
                        "xml_validation_policy": row["xml_validation_policy"],
                        "json_validation_policy": row["json_validation_policy"],
                        "graphql_validation_policy": row["graphql_validation_policy"],
                        "openapi_validation_policy": row["openapi_validation_policy"],
                        "application_layer_dos_prevention": row["application_layer_dos_prevention"],
                        "ip_list_policy": row["ip_list_policy"],
                        "ip_intelligence": row["ip_intelligence"],
                        "geo_block_list_policy": row["geo_block_list_policy"],
                        "waiting_room_policy": row["waiting_room_policy"],
                        "user_tracking_policy": row["user_tracking_policy"],
                        "websocket_security_policy": row["websocket_security_policy"],
                        "cors_protection_policy": row["cors_protection_policy"],
                    },
                }
            )

    return {"devices": list(by_device.values())}
