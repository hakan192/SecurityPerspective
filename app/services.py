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

HTTP_PROTOCOL_PARAMETER_RESTRICTION_FIELDS = [
    "max_http_header_length_check",
    "max_http_content_length_check",
    "max_http_body_length_check",
    "max_http_request_length_check",
    "max_url_parameter_length_check",
    "illegal_http_version_check",
    "max_cookie_in_request_check",
    "max_header_line_request_check",
    "illegal_http_request_method_check",
    "max_url_parameter_check",
    "illegal_host_name_check",
    "number_of_ranges_in_range_header_check",
    "http2_max_requests_check",
    "block_malformed_request_check",
    "illegal_content_length_check",
    "illegal_content_type_check",
    "illegal_response_code_check",
    "post_request_ctype_check",
    "max_http_header_name_length_check",
    "max_http_header_value_length_check",
    "parameter_name_check",
    "parameter_value_check",
    "illegal_header_name_check",
    "illegal_header_value_check",
    "max_http_body_parameter_length_check",
    "max_http_request_filename_length_check",
    "web_socket_protocol_check",
    "max_setting_header_table_size_check",
    "max_setting_current_streams_num_check",
    "max_setting_initial_window_size_check",
    "max_setting_frame_size_check",
    "max_setting_header_list_size_check",
    "max_url_param_name_len_check",
    "url_param_name_check",
    "url_param_value_check",
    "null_byte_in_url_check",
    "illegal_byte_in_url_check",
    "malformed_url_check",
    "redundant_header_check",
    "chunk_size_check",
    "internal_resource_limits_check",
    "rpc_protocol_check",
    "duplicate_paramname_check",
    "odd_and_even_space_attack_check",
    "cl_te_coexist_check",
    "inconsistent_cl_check",
    "missing_host_check",
    "range_overlapping_check",
    "multipart_formdata_bad_request_check",
    "h2_rst_stream_check",
]

SYNTAX_BASED_ATTACK_DETECTION_FIELDS = [
    "xss_html_tag_based_status",
    "xss_html_tag_based_action",
    "xss_html_attribute_based_status",
    "xss_html_attribute_based_action",
    "xss_javascript_function_based_status",
    "xss_javascript_function_based_action",
    "xss_javascript_variable_based_status",
    "xss_javascript_variable_based_action",
    "sql_stacked_queries_status",
    "sql_stacked_queries_action",
    "sql_embeded_queries_status",
    "sql_embeded_queries_action",
    "sql_condition_based_status",
    "sql_condition_based_action",
    "sql_arithmetic_operation_status",
    "sql_arithmetic_operation_action",
    "sql_line_comments_status",
    "sql_line_comments_action",
    "sql_function_based_status",
    "sql_function_based_action",
]


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


def _normalize_key(value: str) -> str:
    return "".join(ch for ch in str(value or "").lower() if ch.isalnum())


def _extract_by_normalized_aliases(item: dict, aliases: list[str]):
    if not isinstance(item, dict):
        return None
    normalized_aliases = {_normalize_key(alias) for alias in aliases}
    for key, value in item.items():
        if _normalize_key(key) in normalized_aliases:
            return value
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


def _extract_http_protocol_parameter_restriction_rows(payload: dict) -> list[dict]:
    results = payload.get("results", []) if isinstance(payload, dict) else []
    if isinstance(results, dict):
        results = [results]
    if not isinstance(results, list):
        return []

    rows = []
    for item in results:
        if not isinstance(item, dict):
            continue
        name = _normalize_optional_text(item.get("name"))
        if not name:
            continue
        row = {"name": name, "raw_json": item}
        for field in HTTP_PROTOCOL_PARAMETER_RESTRICTION_FIELDS:
            aliases = [field, field.replace("_", "-"), field.replace("_", " ")]
            alias_root = field[:-6] if field.endswith("_check") else field
            action_aliases = [
                f"{field}_action",
                f"{field}-action",
                f"{field} action",
                f"{field.replace('_', '-')}-action",
                f"{alias_root}_action",
                f"{alias_root}-action",
                f"{alias_root} action",
                f"{alias_root.replace('_', '-')}-action",
            ]
            row[field] = _normalize_optional_text(_extract_by_normalized_aliases(item, aliases))
            row[f"{field}_action"] = _normalize_optional_text(_extract_by_normalized_aliases(item, action_aliases))
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


def _upsert_http_protocol_parameter_restriction_rows(db: Session, device_id: int, rows: list[dict]):
    table_name = "http_protocol_parameter_restriction"
    dynamic_fields = []
    for field in HTTP_PROTOCOL_PARAMETER_RESTRICTION_FIELDS:
        dynamic_fields.extend([field, f"{field}_action"])

    insert_columns = ["device_id", "name", *dynamic_fields, "raw_json"]
    insert_columns_sql = ", ".join(insert_columns)
    insert_values_sql = ", ".join("CAST(:raw_json AS jsonb)" if col == "raw_json" else f":{col}" for col in insert_columns)
    update_columns_sql = ", ".join(f"{col} = EXCLUDED.{col}" for col in [*dynamic_fields, "raw_json"])

    statement = text(
        f"""
        INSERT INTO {table_name} ({insert_columns_sql})
        VALUES ({insert_values_sql})
        ON CONFLICT (device_id, name) DO UPDATE SET
            {update_columns_sql},
            updated_at = now()
        """
    )

    for row in rows:
        params = {"device_id": device_id, **row, "raw_json": json.dumps(row["raw_json"])}
        db.execute(statement, params)


def _extract_cookie_security_row(payload: dict, cookie_security_name: str) -> dict:
    results = payload.get("results", []) if isinstance(payload, dict) else []
    if isinstance(results, dict):
        result = results
    elif isinstance(results, list) and results and isinstance(results[0], dict):
        result = results[0]
    else:
        result = {}

    return {
        "cookie_security_name": cookie_security_name,
        "action": _normalize_optional_text(result.get("action")),
        "raw_json": payload if isinstance(payload, dict) else {"results": result},
    }


def _extract_syntax_based_attack_detection_rows(payload: dict) -> list[dict]:
    results = payload.get("results", []) if isinstance(payload, dict) else []
    if isinstance(results, dict):
        results = [results]
    if not isinstance(results, list):
        return []

    rows = []
    for item in results:
        if not isinstance(item, dict):
            continue
        name = _normalize_optional_text(item.get("name"))
        if not name:
            continue
        row = {"name": name, "raw_json": item}
        for field in SYNTAX_BASED_ATTACK_DETECTION_FIELDS:
            aliases = [field, field.replace("_", "-"), field.replace("_", " ")]
            row[field] = _normalize_optional_text(_extract_by_normalized_aliases(item, aliases))
        rows.append(row)
    return rows


def _upsert_cookie_security_row(db: Session, device_id: int, row: dict):
    db.execute(
        text(
            """
            INSERT INTO "cookie-security-policy" (
                device_id,
                cookie_security_name,
                action,
                raw_json
            )
            VALUES (
                :device_id,
                :cookie_security_name,
                :action,
                CAST(:raw_json AS jsonb)
            )
            ON CONFLICT (device_id, cookie_security_name) DO UPDATE SET
                action = EXCLUDED.action,
                raw_json = EXCLUDED.raw_json,
                updated_at = now()
            """
        ),
        {"device_id": device_id, **row, "raw_json": json.dumps(row["raw_json"])},
    )


def _upsert_syntax_based_attack_detection_rows(db: Session, device_id: int, rows: list[dict]):
    dynamic_fields = SYNTAX_BASED_ATTACK_DETECTION_FIELDS
    insert_columns = ["device_id", "name", *dynamic_fields, "raw_json"]
    insert_columns_sql = ", ".join(insert_columns)
    insert_values_sql = ", ".join("CAST(:raw_json AS jsonb)" if col == "raw_json" else f":{col}" for col in insert_columns)
    update_columns_sql = ", ".join(f"{col} = EXCLUDED.{col}" for col in [*dynamic_fields, "raw_json"])

    statement = text(
        f"""
        INSERT INTO "syntax-based-attack-detection" ({insert_columns_sql})
        VALUES ({insert_values_sql})
        ON CONFLICT (device_id, name) DO UPDATE SET
            {update_columns_sql},
            updated_at = now()
        """
    )

    for row in rows:
        params = {"device_id": device_id, **row, "raw_json": json.dumps(row["raw_json"])}
        db.execute(statement, params)


def _extract_results(payload: dict):
    results = payload.get("results", []) if isinstance(payload, dict) else []
    if isinstance(results, dict):
        return [results]
    if isinstance(results, list):
        return [item for item in results if isinstance(item, dict)]
    return []


def _extract_custom_access_rule_names(payload: dict) -> list[str]:
    rows = _extract_results(payload)
    rule_names = []
    for row in rows:
        rule_name = _normalize_optional_text(row.get("name") or row.get("rule_name") or row.get("rule-name"))
        if rule_name:
            rule_names.append(rule_name)
    return rule_names


def _extract_custom_access_rule_details(payload: dict, custom_access_policy_name: str, custom_access_rules: str) -> dict:
    rows = _extract_results(payload)
    result = rows[0] if rows else {}
    return {
        "custom_access_policy_name": custom_access_policy_name,
        "custom_access_rules": custom_access_rules,
        "visfilterType": _normalize_optional_text(result.get("visfilterType") or result.get("visfilter-type")),
        "visvalue": _normalize_optional_text(result.get("visvalue") or result.get("vis-value")),
        "raw_json": payload if isinstance(payload, dict) else {"results": result},
    }


def _upsert_custom_access_policy_row(db: Session, device_id: int, row: dict):
    db.execute(
        text(
            """
            INSERT INTO "custom-access-policy" (
                device_id,
                custom_access_policy_name,
                custom_access_rules,
                visfilterType,
                visvalue,
                raw_json
            )
            VALUES (
                :device_id,
                :custom_access_policy_name,
                :custom_access_rules,
                :visfilterType,
                :visvalue,
                CAST(:raw_json AS jsonb)
            )
            ON CONFLICT (device_id, custom_access_policy_name, custom_access_rules) DO UPDATE SET
                visfilterType = EXCLUDED.visfilterType,
                visvalue = EXCLUDED.visvalue,
                raw_json = EXCLUDED.raw_json,
                updated_at = now()
            """
        ),
        {"device_id": device_id, **row, "raw_json": json.dumps(row["raw_json"])},
    )


def _extract_signature_row(payload: dict, signature_set_name: str) -> dict:
    results = payload.get("results", []) if isinstance(payload, dict) else []
    if isinstance(results, dict):
        result = results
    elif isinstance(results, list) and results and isinstance(results[0], dict):
        result = results[0]
    else:
        result = {}

    row = {
        "signature_set_name": signature_set_name,
        "raw_json": payload if isinstance(payload, dict) else {"results": result or {"signature_set_name": signature_set_name}},
    }
    for normalized_key, aliases in SIGNATURE_FIELD_MAP.items():
        row[normalized_key] = _normalize_optional_text(_extract_by_aliases(result, aliases))

    main_class_lookup = {}
    main_class_list = result.get("main_class_list", [])
    if isinstance(main_class_list, list):
        for item in main_class_list:
            if isinstance(item, dict):
                name = _normalize_optional_text(item.get("name"))
                if name:
                    main_class_lookup[name] = {
                        "status": _normalize_optional_text(item.get("status")),
                        "action": _normalize_optional_text(item.get("action")),
                    }

    class_name_to_field = {
        "Cross Site Scripting": "cross_site_scripting",
        "Cross Site Scripting (Extended)": "cross_site_scripting_extended",
        "SQL Injection": "sql_injection",
        "SQL Injection (Extended)": "sql_injection_extended",
        "Generic Attacks": "generic_attacks",
        "Generic Attacks(Extended)": "generic_attacks_extended",
        "Known Exploits": "known_exploits",
        "Trojans": "trojans",
        "Information Disclosure": "information_disclosure",
        "Personally Identifiable Information": "personally_identifiable_information",
    }
    for class_name, field_name in class_name_to_field.items():
        if class_name in main_class_lookup:
            class_data = main_class_lookup[class_name]
            if not row.get(field_name) and class_data.get("status"):
                row[field_name] = class_data["status"]
            row[f"{field_name}_action"] = class_data.get("action")
        else:
            row.setdefault(f"{field_name}_action", None)

    return row


def _upsert_signature_row(db: Session, device_id: int, row: dict):
    db.execute(
        text(
            """
            INSERT INTO signature (
                device_id,
                signature_set_name,
                cross_site_scripting,
                cross_site_scripting_action,
                cross_site_scripting_extended,
                cross_site_scripting_extended_action,
                sql_injection,
                sql_injection_action,
                sql_injection_extended,
                sql_injection_extended_action,
                generic_attacks,
                generic_attacks_action,
                generic_attacks_extended,
                generic_attacks_extended_action,
                known_exploits,
                known_exploits_action,
                trojans,
                trojans_action,
                information_disclosure,
                information_disclosure_action,
                personally_identifiable_information,
                personally_identifiable_information_action,
                raw_json
            )
            VALUES (
                :device_id,
                :signature_set_name,
                :cross_site_scripting,
                :cross_site_scripting_action,
                :cross_site_scripting_extended,
                :cross_site_scripting_extended_action,
                :sql_injection,
                :sql_injection_action,
                :sql_injection_extended,
                :sql_injection_extended_action,
                :generic_attacks,
                :generic_attacks_action,
                :generic_attacks_extended,
                :generic_attacks_extended_action,
                :known_exploits,
                :known_exploits_action,
                :trojans,
                :trojans_action,
                :information_disclosure,
                :information_disclosure_action,
                :personally_identifiable_information,
                :personally_identifiable_information_action,
                CAST(:raw_json AS jsonb)
            )
            ON CONFLICT (device_id, signature_set_name) DO UPDATE SET
                cross_site_scripting = EXCLUDED.cross_site_scripting,
                cross_site_scripting_action = EXCLUDED.cross_site_scripting_action,
                cross_site_scripting_extended = EXCLUDED.cross_site_scripting_extended,
                cross_site_scripting_extended_action = EXCLUDED.cross_site_scripting_extended_action,
                sql_injection = EXCLUDED.sql_injection,
                sql_injection_action = EXCLUDED.sql_injection_action,
                sql_injection_extended = EXCLUDED.sql_injection_extended,
                sql_injection_extended_action = EXCLUDED.sql_injection_extended_action,
                generic_attacks = EXCLUDED.generic_attacks,
                generic_attacks_action = EXCLUDED.generic_attacks_action,
                generic_attacks_extended = EXCLUDED.generic_attacks_extended,
                generic_attacks_extended_action = EXCLUDED.generic_attacks_extended_action,
                known_exploits = EXCLUDED.known_exploits,
                known_exploits_action = EXCLUDED.known_exploits_action,
                trojans = EXCLUDED.trojans,
                trojans_action = EXCLUDED.trojans_action,
                information_disclosure = EXCLUDED.information_disclosure,
                information_disclosure_action = EXCLUDED.information_disclosure_action,
                personally_identifiable_information = EXCLUDED.personally_identifiable_information,
                personally_identifiable_information_action = EXCLUDED.personally_identifiable_information_action,
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


def _fetch_and_upsert_http_protocol_parameter_restrictions(
    db: Session,
    device: ManagedDevice,
    headers: dict,
):
    endpoint = "/api/v2.0/cmdb/waf/http-protocol-parameter-restriction"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    rows = _extract_http_protocol_parameter_restriction_rows(payload)
    _upsert_http_protocol_parameter_restriction_rows(db, device.id, rows)


def _fetch_and_upsert_cookie_security_policy(
    db: Session,
    device: ManagedDevice,
    cookie_security_name: str,
    headers: dict,
):
    encoded_name = quote(cookie_security_name, safe="")
    endpoint = f"/api/v2.0/cmdb/waf/cookie-security?mkey={encoded_name}"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    row = _extract_cookie_security_row(payload, cookie_security_name)
    _upsert_cookie_security_row(db, device.id, row)


def _fetch_and_upsert_syntax_based_attack_detection(
    db: Session,
    device: ManagedDevice,
    headers: dict,
):
    endpoint = "/api/v2.0/cmdb/waf/syntax-based-attack-detection"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    rows = _extract_syntax_based_attack_detection_rows(payload)
    _upsert_syntax_based_attack_detection_rows(db, device.id, rows)


def _fetch_and_upsert_custom_access_policy(
    db: Session,
    device: ManagedDevice,
    custom_access_policy_name: str,
    headers: dict,
):
    encoded_policy_name = quote(custom_access_policy_name, safe="")
    rules_endpoint = f"/api/v2.0/cmdb/waf/custom-access.policy/rule?mkey={encoded_policy_name}"
    rules_url = f"{_build_device_base_url(device.ip).rstrip('/')}{rules_endpoint}"
    rules_response = requests.get(
        rules_url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    rules_response.raise_for_status()
    rules_payload = rules_response.json()
    rule_names = _extract_custom_access_rule_names(rules_payload)

    for rule_name in rule_names:
        encoded_rule_name = quote(rule_name, safe="")
        details_endpoint = f"/waf/webprotection.advancedprotection.customrule.newcustomaccessrule?name={encoded_rule_name}"
        details_url = f"{_build_device_base_url(device.ip).rstrip('/')}{details_endpoint}"
        details_response = requests.get(
            details_url,
            headers=headers,
            timeout=30,
            verify=settings.fortiweb_verify_ssl,
        )
        details_response.raise_for_status()
        details_payload = details_response.json()
        row = _extract_custom_access_rule_details(details_payload, custom_access_policy_name, rule_name)
        _upsert_custom_access_policy_row(db, device.id, row)


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
            web_protection_profile_rows = []
            try:
                web_protection_profile_rows = _fetch_and_upsert_web_protection_profiles(db, device, headers)
            except Exception:
                web_protection_profile_rows = []

            try:
                _fetch_and_upsert_http_protocol_parameter_restrictions(db, device, headers)
            except Exception:
                pass

            try:
                _fetch_and_upsert_syntax_based_attack_detection(db, device, headers)
            except Exception:
                pass

            unique_custom_access_policies = {row["custom_access_policy"] for row in web_protection_profile_rows if row.get("custom_access_policy")}
            for custom_access_policy_name in unique_custom_access_policies:
                try:
                    _fetch_and_upsert_custom_access_policy(db, device, custom_access_policy_name, headers)
                except Exception:
                    pass

            unique_cookie_security_policies = {row["cookie_security_policy"] for row in web_protection_profile_rows if row.get("cookie_security_policy")}
            for cookie_security_name in unique_cookie_security_policies:
                try:
                    _fetch_and_upsert_cookie_security_policy(db, device, cookie_security_name, headers)
                except Exception:
                    pass

            unique_signature_rules = {row["signature_rule"] for row in web_protection_profile_rows if row.get("signature_rule")}
            for signature_rule in unique_signature_rules:
                try:
                    _fetch_and_upsert_signature(db, device, signature_rule, headers)
                except Exception:
                    pass

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
