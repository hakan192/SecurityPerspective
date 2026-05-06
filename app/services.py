import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.parse import quote

import requests
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.models import ManagedDevice

BACKUP_FILENAME_PATTERN = re.compile(r"security_perspective_backup_(\d{2}_\d{2}_\d{2}_\d{2}_\d{2}_\d{2})\.sql$")
FALLBACK_INSERT_SERVER_POLICY_PATTERN = re.compile(
    r'INSERT INTO "server_policy"\s*\((?P<columns>.*?)\)\s*VALUES\s*\((?P<values>.*?)\);',
    re.IGNORECASE,
)
FALLBACK_INSERT_SERVER_POOL_PATTERN = re.compile(
    r'INSERT INTO "server_pool"\s*\((?P<columns>.*?)\)\s*VALUES\s*\((?P<values>.*?)\);',
    re.IGNORECASE,
)
FALLBACK_INSERT_CERTIFICATE_LOCAL_PATTERN = re.compile(
    r'INSERT INTO "certificate_local"\s*\((?P<columns>.*?)\)\s*VALUES\s*\((?P<values>.*?)\);',
    re.IGNORECASE,
)
FALLBACK_INSERT_WEB_PROTECTION_PROFILE_PATTERN = re.compile(
    r'INSERT INTO "web_protection_profiles"\s*\((?P<columns>.*?)\)\s*VALUES\s*\((?P<values>.*?)\);',
    re.IGNORECASE,
)
FALLBACK_INSERT_SIGNATURE_PATTERN = re.compile(
    r'INSERT INTO "signature"\s*\((?P<columns>.*?)\)\s*VALUES\s*\((?P<values>.*?)\);',
    re.IGNORECASE,
)
FALLBACK_INSERT_HTTP_PROTOCOL_PARAMETER_RESTRICTION_PATTERN = re.compile(
    r'INSERT INTO "http_protocol_parameter_restriction"\s*\((?P<columns>.*?)\)\s*VALUES\s*\((?P<values>.*?)\);',
    re.IGNORECASE,
)
PG_DUMP_COPY_SERVER_POLICY_PATTERN = re.compile(
    r"COPY\s+public\.server_policy\s*\((?P<columns>.*?)\)\s+FROM\s+stdin;",
    re.IGNORECASE,
)
PG_DUMP_COPY_SERVER_POOL_PATTERN = re.compile(
    r"COPY\s+public\.server_pool\s*\((?P<columns>.*?)\)\s+FROM\s+stdin;",
    re.IGNORECASE,
)
PG_DUMP_COPY_CERTIFICATE_LOCAL_PATTERN = re.compile(
    r"COPY\s+public\.certificate_local\s*\((?P<columns>.*?)\)\s+FROM\s+stdin;",
    re.IGNORECASE,
)
PG_DUMP_COPY_WEB_PROTECTION_PROFILE_PATTERN = re.compile(
    r"COPY\s+public\.web_protection_profiles\s*\((?P<columns>.*?)\)\s+FROM\s+stdin;",
    re.IGNORECASE,
)
PG_DUMP_COPY_SIGNATURE_PATTERN = re.compile(
    r"COPY\s+public\.signature\s*\((?P<columns>.*?)\)\s+FROM\s+stdin;",
    re.IGNORECASE,
)
PG_DUMP_COPY_HTTP_PROTOCOL_PARAMETER_RESTRICTION_PATTERN = re.compile(
    r"COPY\s+public\.http_protocol_parameter_restriction\s*\((?P<columns>.*?)\)\s+FROM\s+stdin;",
    re.IGNORECASE,
)


def _split_sql_values(raw_values: str) -> list[str]:
    parts = []
    token = []
    in_string = False
    i = 0
    while i < len(raw_values):
        char = raw_values[i]
        if char == "'":
            token.append(char)
            if in_string and i + 1 < len(raw_values) and raw_values[i + 1] == "'":
                token.append(raw_values[i + 1])
                i += 2
                continue
            in_string = not in_string
            i += 1
            continue
        if char == "," and not in_string:
            parts.append("".join(token).strip())
            token = []
        else:
            token.append(char)
        i += 1
    if token:
        parts.append("".join(token).strip())
    return parts


def _parse_sql_string(value: str):
    stripped = value.strip()
    if stripped.upper() == "NULL":
        return None
    if stripped.startswith("'") and stripped.endswith("'"):
        return stripped[1:-1].replace("''", "'")
    return stripped


def _extract_fallback_insert_rows(content: str, pattern: re.Pattern) -> list[dict]:
    rows = []
    for insert_match in pattern.finditer(content):
        columns = [col.strip().strip('"') for col in insert_match.group("columns").split(",")]
        values = _split_sql_values(insert_match.group("values"))
        if len(columns) != len(values):
            continue
        rows.append({columns[idx]: _parse_sql_string(values[idx]) for idx in range(len(columns))})
    return rows


def _extract_pg_dump_copy_rows(content: str, pattern: re.Pattern) -> list[dict]:
    copy_match = pattern.search(content)
    if not copy_match:
        return []

    rows = []
    columns = [col.strip().strip('"') for col in copy_match.group("columns").split(",")]
    copy_body = content[copy_match.end():]
    for line in copy_body.splitlines():
        stripped_line = line.strip()
        if stripped_line == r"\.":
            break
        if not stripped_line:
            continue
        values = stripped_line.split("\t")
        if len(values) != len(columns):
            continue
        rows.append({columns[idx]: (None if values[idx] == r"\N" else values[idx]) for idx in range(len(columns))})
    return rows


STANDARD_PROTECTION_FEATURES = {
    "signature": "Signature",
    "http_rfc": "HTTP RFC",
    "http2_rfc_control": "HTTP/2 RFC control",
}


def _format_standard_protection_state(value) -> str:
    return "enabled" if _as_enable_disable(value) == "enable" or str(value).strip().lower() == "enabled" else "disabled"


def _build_standard_protection_state(signature_row: dict, http_rfc_row: dict, http2_enabled) -> dict[str, str]:
    http2_row = {**http_rfc_row, "http2": http2_enabled}
    return {
        "signature": _build_signature_set_status(signature_row)["status"],
        "http_rfc": _build_http_rfc_control_status(http_rfc_row)["status"],
        "http2_rfc_control": _build_http2_rfc_control_status(http2_row)["status"],
    }


def _load_server_policy_state_from_backups(days: int = 7) -> dict[tuple[str, str], list[tuple[datetime, str, str | None, dict[str, str]]]]:
    backup_dirs = [Path("app/backups"), Path("backups")]
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    entries: dict[tuple[str, str], list[tuple[datetime, str, str | None, dict[str, str]]]] = {}
    backup_files = []
    for backup_dir in backup_dirs:
        if backup_dir.exists():
            backup_files.extend(backup_dir.glob("security_perspective_backup_*.sql"))
    for backup_file in sorted(backup_files):
        match = BACKUP_FILENAME_PATTERN.match(backup_file.name)
        if not match:
            continue
        try:
            backup_time = datetime.strptime(match.group(1), "%d_%m_%y_%H_%M_%S").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if backup_time < cutoff:
            continue
        try:
            content = backup_file.read_text(encoding="utf-8")
        except OSError:
            continue

        server_pool_rows = [
            *_extract_fallback_insert_rows(content, FALLBACK_INSERT_SERVER_POOL_PATTERN),
            *_extract_pg_dump_copy_rows(content, PG_DUMP_COPY_SERVER_POOL_PATTERN),
        ]
        server_pools = {
            (str(row.get("device_id")), str(row.get("server_pool_name"))): row
            for row in server_pool_rows
            if row.get("device_id") is not None and row.get("server_pool_name")
        }
        certificate_rows = [
            *_extract_fallback_insert_rows(content, FALLBACK_INSERT_CERTIFICATE_LOCAL_PATTERN),
            *_extract_pg_dump_copy_rows(content, PG_DUMP_COPY_CERTIFICATE_LOCAL_PATTERN),
        ]
        certificate_serials = {
            (str(row.get("device_id")), str(row.get("certificate_name"))): _normalize_optional_text(row.get("serial_number"))
            for row in certificate_rows
            if row.get("device_id") is not None and row.get("certificate_name")
        }
        web_protection_profile_rows = [
            *_extract_fallback_insert_rows(content, FALLBACK_INSERT_WEB_PROTECTION_PROFILE_PATTERN),
            *_extract_pg_dump_copy_rows(content, PG_DUMP_COPY_WEB_PROTECTION_PROFILE_PATTERN),
        ]
        web_protection_profiles = {
            (str(row.get("device_id")), str(row.get("web_protection_profile_name"))): row
            for row in web_protection_profile_rows
            if row.get("device_id") is not None and row.get("web_protection_profile_name")
        }
        signature_rows = [
            *_extract_fallback_insert_rows(content, FALLBACK_INSERT_SIGNATURE_PATTERN),
            *_extract_pg_dump_copy_rows(content, PG_DUMP_COPY_SIGNATURE_PATTERN),
        ]
        signatures = {
            (str(row.get("device_id")), str(row.get("signature_set_name"))): row
            for row in signature_rows
            if row.get("device_id") is not None and row.get("signature_set_name")
        }
        http_rfc_rows = [
            *_extract_fallback_insert_rows(content, FALLBACK_INSERT_HTTP_PROTOCOL_PARAMETER_RESTRICTION_PATTERN),
            *_extract_pg_dump_copy_rows(content, PG_DUMP_COPY_HTTP_PROTOCOL_PARAMETER_RESTRICTION_PATTERN),
        ]
        http_rfc_profiles = {
            (str(row.get("device_id")), str(row.get("name"))): row
            for row in http_rfc_rows
            if row.get("device_id") is not None and row.get("name")
        }
        server_policy_rows = [
            *_extract_fallback_insert_rows(content, FALLBACK_INSERT_SERVER_POLICY_PATTERN),
            *_extract_pg_dump_copy_rows(content, PG_DUMP_COPY_SERVER_POLICY_PATTERN),
        ]
        for row in server_policy_rows:
            device_id = row.get("device_id")
            policy_name = row.get("server_policy_name")
            if device_id is None or not policy_name:
                continue
            pool_key = (str(device_id), str(row.get("server_pool_name")))
            pool_row = server_pools.get(pool_key, {})
            certificate_name = _normalize_optional_text(pool_row.get("client_certificate")) or _normalize_optional_text(pool_row.get("certificate_name"))
            certificate_serial = certificate_serials.get((str(device_id), str(certificate_name))) if certificate_name else None
            web_profile = web_protection_profiles.get((str(device_id), str(row.get("web_protection_profile_name"))), {})
            signature_row = signatures.get((str(device_id), str(web_profile.get("signature_rule"))), {})
            http_rfc_row = http_rfc_profiles.get((str(device_id), str(web_profile.get("http_protocol_parameter_restriction"))), {})
            standard_protection_state = _build_standard_protection_state(signature_row, http_rfc_row, pool_row.get("http2"))
            key = (str(device_id), str(policy_name))
            entries.setdefault(key, []).append(
                (
                    backup_time,
                    _format_policy_status_label(row.get("monitor_mode"), pool_row.get("ip")),
                    certificate_serial,
                    standard_protection_state,
                )
            )
    return entries

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
        return value.strip().lower() in {"true", "t", "1", "yes", "on", "enable", "enabled"}
    return None


def _as_enable_disable(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return "enable" if value else "disable"
    if isinstance(value, (int, float)):
        return "enable" if value != 0 else "disable"
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "t", "1", "yes", "on", "enable", "enabled"}:
            return "enable"
        if normalized in {"false", "f", "0", "no", "off", "disable", "disabled"}:
            return "disable"
        return normalized or None
    return str(value).strip().lower() or None


def _format_policy_status_label(monitor_mode, policy_ip):
    if not _normalize_optional_text(policy_ip):
        return "Not Protected"
    return "Monitoring" if _as_enable_disable(monitor_mode) == "enable" else "Blocking"


def _format_recent_change_date(value: datetime) -> str:
    return value.strftime("%d/%m")


def _format_policy_status_change_summary(status: str) -> str:
    if status == "Not Protected":
        return "The policy is not protected because no server pool IP is configured."
    return f"The policy is now running in {status} mode."


def _format_certificate_change_summary(certificate_serial: str | None) -> str:
    if certificate_serial:
        return f"The client certificate serial number changed to {certificate_serial}."
    return "The client certificate serial number changed."


def _append_policy_state_changes(
    changes: list[dict],
    event_time: datetime,
    previous_status: str,
    next_status: str,
    previous_certificate_serial: str | None,
    next_certificate_serial: str | None,
    previous_standard_protection: dict[str, str] | None = None,
    next_standard_protection: dict[str, str] | None = None,
) -> None:
    event_timestamp = int(event_time.timestamp())
    if previous_status != next_status:
        changes.append(
            {
                "id": f"policy-status-{event_timestamp}",
                "title": f"Policy Status changed to {next_status}",
                "summary": _format_policy_status_change_summary(next_status),
                "time": _format_recent_change_date(event_time),
                "type": "Server Policy",
            }
        )

    normalized_previous_serial = _normalize_optional_text(previous_certificate_serial)
    normalized_next_serial = _normalize_optional_text(next_certificate_serial)
    serial_changed = normalized_previous_serial != normalized_next_serial
    serial_present = normalized_previous_serial or normalized_next_serial
    if serial_changed and serial_present:
        changes.append(
            {
                "id": f"certificate-serial-{event_timestamp}",
                "title": "Certificate changed or renewed",
                "summary": _format_certificate_change_summary(normalized_next_serial),
                "time": _format_recent_change_date(event_time),
                "type": "Certificate",
            }
        )

    previous_standard_protection = previous_standard_protection or {}
    next_standard_protection = next_standard_protection or {}
    for feature_key, feature_name in STANDARD_PROTECTION_FEATURES.items():
        previous_feature_status = _format_standard_protection_state(previous_standard_protection.get(feature_key))
        next_feature_status = _format_standard_protection_state(next_standard_protection.get(feature_key))
        if previous_feature_status != next_feature_status:
            changes.append(
                {
                    "id": f"standard-protection-{feature_key}-{event_timestamp}",
                    "title": f"{feature_name} control {next_feature_status}",
                    "summary": f"Standard Protection: {feature_name} changed to {next_feature_status.title()}.",
                    "time": _format_recent_change_date(event_time),
                    "type": "Standard Protection",
                }
            )


def _build_recent_policy_changes(
    current_status: str,
    current_certificate_serial: str | None,
    backup_events: list[tuple[datetime, str, str | None, dict[str, str]]] | list[tuple[datetime, str, str | None]],
    current_standard_protection: dict[str, str] | None = None,
    current_time: datetime | None = None,
) -> list[dict]:
    sorted_events = sorted(backup_events, key=lambda item: item[0])
    if not sorted_events:
        return []

    def unpack_event(event):
        if len(event) >= 4:
            return event[0], event[1], event[2], event[3]
        return event[0], event[1], event[2], {}

    changes = []
    _, previous_status, previous_certificate_serial, previous_standard_protection = unpack_event(sorted_events[0])
    for event in sorted_events[1:]:
        event_time, backup_status, backup_certificate_serial, backup_standard_protection = unpack_event(event)
        _append_policy_state_changes(
            changes,
            event_time,
            previous_status,
            backup_status,
            previous_certificate_serial,
            backup_certificate_serial,
            previous_standard_protection,
            backup_standard_protection,
        )
        previous_status = backup_status
        previous_certificate_serial = backup_certificate_serial
        previous_standard_protection = backup_standard_protection

    _append_policy_state_changes(
        changes,
        current_time or datetime.now(timezone.utc),
        previous_status,
        current_status,
        previous_certificate_serial,
        current_certificate_serial,
        previous_standard_protection,
        current_standard_protection,
    )
    return changes


def _normalize_optional_text(value):
    if value is None:
        return None
    if not isinstance(value, str):
        return str(value)
    normalized = value.strip()
    return normalized or None


def _normalize_optional_date(value):
    text_value = _normalize_optional_text(value)
    if not text_value:
        return None
    if len(text_value) >= 10 and text_value[4] == "-" and text_value[7] == "-":
        return text_value[:10]
    try:
        return datetime.fromisoformat(text_value.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        return None


def _format_allow_method_value(value):
    raw_value = _normalize_optional_text(value)
    if not raw_value:
        return {"raw": None, "methods": [], "display": None}

    tokens = re.split(r"[\s,;|/]+", raw_value)
    methods = []
    seen = set()
    for token in tokens:
        normalized = token.strip().strip("[](){}\"'").upper()
        if not normalized:
            continue
        if normalized not in seen:
            seen.add(normalized)
            methods.append(normalized)

    if not methods:
        return {"raw": raw_value, "methods": [], "display": raw_value}
    if len(methods) == 1 and methods[0] in {"ALL", "ANY", "*"}:
        return {"raw": raw_value, "methods": methods, "display": "All methods"}

    return {"raw": raw_value, "methods": methods, "display": ", ".join(methods)}


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
    def collect_names(node, acc: list[str]):
        if isinstance(node, dict):
            direct_name = _normalize_optional_text(
                node.get("name")
                or node.get("rule_name")
                or node.get("rule-name")
                or node.get("custom_access_rules")
                or node.get("custom-access-rules")
            )
            if direct_name:
                acc.append(direct_name)
            for value in node.values():
                collect_names(value, acc)
        elif isinstance(node, list):
            for item in node:
                collect_names(item, acc)

    collected = []
    collect_names(payload, collected)
    deduped = []
    seen = set()
    for name in collected:
        if name not in seen:
            seen.add(name)
            deduped.append(name)
    return deduped


def _extract_custom_access_policy_row(payload: dict, custom_access_policy_name: str) -> dict:
    rule_names = _extract_custom_access_rule_names(payload)
    return {
        "custom_access_policy_name": custom_access_policy_name,
        "rule_names": rule_names,
        "raw_json": payload if isinstance(payload, dict) else {},
    }


def _fetch_json_with_fallback_endpoints(device: ManagedDevice, headers: dict, endpoints: list[str]) -> dict:
    last_error = None
    for endpoint in endpoints:
        try:
            url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
            response = requests.get(
                url,
                headers=headers,
                timeout=30,
                verify=settings.fortiweb_verify_ssl,
            )
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            last_error = exc
    if last_error:
        raise last_error
    return {}


def _upsert_custom_access_policy_row(db: Session, device_id: int, row: dict):
    db.execute(
        text(
            """
            INSERT INTO "custom-access-policy" (
                device_id,
                custom_access_policy_name,
                rule_names,
                raw_json
            )
            VALUES (
                :device_id,
                :custom_access_policy_name,
                :rule_names,
                CAST(:raw_json AS jsonb)
            )
            ON CONFLICT (device_id, custom_access_policy_name) DO UPDATE SET
                rule_names = EXCLUDED.rule_names,
                raw_json = EXCLUDED.raw_json,
                updated_at = now()
            """
        ),
        {"device_id": device_id, **row, "raw_json": json.dumps(row["raw_json"])},
    )


def _extract_custom_access_rule_row(rule_name: str, payload: dict, custom_rule_payload: dict) -> dict:
    rows = _extract_results(payload)
    result = rows[0] if rows else {}
    return {
        "name": rule_name,
        "action": _normalize_optional_text(result.get("action")),
        "bot_confirmation": _normalize_optional_text(result.get("bot-confirmation") or result.get("bot_confirmation")),
        "bot_recognition": _normalize_optional_text(result.get("bot-recognition") or result.get("bot_recognition")),
        "raw_json": payload if isinstance(payload, dict) else {},
        "raw_json_custom_rule": custom_rule_payload if isinstance(custom_rule_payload, dict) else {},
    }


def _upsert_custom_access_rule_row(db: Session, device_id: int, row: dict):
    db.execute(
        text(
            """
            INSERT INTO "custom-access-rule" (
                device_id,
                name,
                action,
                "bot-confirmation",
                "bot-recognition",
                raw_json,
                raw_json_custom_rule
            )
            VALUES (
                :device_id,
                :name,
                :action,
                :bot_confirmation,
                :bot_recognition,
                CAST(:raw_json AS jsonb),
                CAST(:raw_json_custom_rule AS jsonb)
            )
            ON CONFLICT (device_id, name) DO UPDATE SET
                action = EXCLUDED.action,
                "bot-confirmation" = EXCLUDED."bot-confirmation",
                "bot-recognition" = EXCLUDED."bot-recognition",
                raw_json = EXCLUDED.raw_json,
                raw_json_custom_rule = EXCLUDED.raw_json_custom_rule,
                updated_at = now()
            """
        ),
        {
            "device_id": device_id,
            **row,
            "raw_json": json.dumps(row["raw_json"]),
            "raw_json_custom_rule": json.dumps(row["raw_json_custom_rule"]),
        },
    )


def _extract_allow_method_policy_rows(payload: dict) -> list[dict]:
    rows = _extract_results(payload)
    parsed_rows = []
    for row in rows:
        policy_name = _normalize_optional_text(row.get("name") or row.get("allow-method-policy-name") or row.get("allow_method_policy_name"))
        if not policy_name:
            continue
        allow_method = _normalize_optional_text(row.get("allow-method") or row.get("allow_method"))
        parsed_rows.append(
            {
                "allow_method_policy_name": policy_name,
                "allow_method": allow_method,
                "raw_json": row,
            }
        )
    return parsed_rows


def _upsert_allow_method_policy_rows(db: Session, device_id: int, rows: list[dict]):
    for row in rows:
        db.execute(
            text(
                """
                INSERT INTO "allow-method-policy" (
                    device_id,
                    allow_method_policy_name,
                    allow_method,
                    raw_json
                )
                VALUES (
                    :device_id,
                    :allow_method_policy_name,
                    :allow_method,
                    CAST(:raw_json AS jsonb)
                )
                ON CONFLICT (device_id, allow_method_policy_name) DO UPDATE SET
                    allow_method = EXCLUDED.allow_method,
                    raw_json = EXCLUDED.raw_json,
                    updated_at = now()
                """
            ),
            {"device_id": device_id, **row, "raw_json": json.dumps(row["raw_json"])},
        )


def _extract_xml_validation_policy_rows(payload: dict) -> list[dict]:
    rows = _extract_results(payload)
    parsed_rows = []
    for row in rows:
        xml_validation_name = _normalize_optional_text(row.get("name") or row.get("xml-validation-name") or row.get("xml_validation_name"))
        if not xml_validation_name:
            continue
        enable_signature_detection = _normalize_optional_text(
            row.get("enable-signature-detection") or row.get("enable_signature_detection")
        )
        parsed_rows.append(
            {
                "xml_validation_name": xml_validation_name,
                "enable_signature_detection": enable_signature_detection,
                "raw_json": row,
            }
        )
    return parsed_rows


def _upsert_xml_validation_policy_rows(db: Session, device_id: int, rows: list[dict]):
    for row in rows:
        db.execute(
            text(
                """
                INSERT INTO "xml-validation-policy" (
                    device_id,
                    xml_validation_name,
                    enable_signature_detection,
                    raw_json
                )
                VALUES (
                    :device_id,
                    :xml_validation_name,
                    :enable_signature_detection,
                    CAST(:raw_json AS jsonb)
                )
                ON CONFLICT (device_id, xml_validation_name) DO UPDATE SET
                    enable_signature_detection = EXCLUDED.enable_signature_detection,
                    raw_json = EXCLUDED.raw_json,
                    updated_at = now()
                """
            ),
            {"device_id": device_id, **row, "raw_json": json.dumps(row["raw_json"])},
        )


def _extract_json_validation_policy_rows(payload: dict) -> list[dict]:
    rows = _extract_results(payload)
    parsed_rows = []
    for row in rows:
        json_validation_name = _normalize_optional_text(row.get("name") or row.get("json-validation-name") or row.get("json_validation_name"))
        if not json_validation_name:
            continue
        enable_attack_signatures = _normalize_optional_text(
            row.get("enable-attack-signatures") or row.get("enable_attack_signatures")
        )
        parsed_rows.append(
            {
                "json_validation_name": json_validation_name,
                "enable_attack_signatures": enable_attack_signatures,
                "raw_json": row,
            }
        )
    return parsed_rows


def _upsert_json_validation_policy_rows(db: Session, device_id: int, rows: list[dict]):
    for row in rows:
        db.execute(
            text(
                """
                INSERT INTO "json-validation-policy" (
                    device_id,
                    json_validation_name,
                    enable_attack_signatures,
                    raw_json
                )
                VALUES (
                    :device_id,
                    :json_validation_name,
                    :enable_attack_signatures,
                    CAST(:raw_json AS jsonb)
                )
                ON CONFLICT (device_id, json_validation_name) DO UPDATE SET
                    enable_attack_signatures = EXCLUDED.enable_attack_signatures,
                    raw_json = EXCLUDED.raw_json,
                    updated_at = now()
                """
            ),
            {"device_id": device_id, **row, "raw_json": json.dumps(row["raw_json"])},
        )


def _extract_geo_ip_row(payload: dict, geo_ip_name: str) -> dict:
    rows = _extract_results(payload)
    result = rows[0] if rows else {}
    return {
        "name": geo_ip_name,
        "action": _normalize_optional_text(result.get("action")),
        "block_period": _normalize_optional_text(result.get("block-period") or result.get("block_period")),
    }


def _extract_geo_ip_country_names(payload: dict) -> list[str]:
    rows = _extract_results(payload)
    country_names = []
    for row in rows:
        country_name = _normalize_optional_text(row.get("country-name") or row.get("country_name") or row.get("name"))
        if country_name:
            country_names.append(country_name)
    deduped_country_names = []
    seen = set()
    for country_name in country_names:
        if country_name in seen:
            continue
        seen.add(country_name)
        deduped_country_names.append(country_name)
    return deduped_country_names


def _upsert_geo_ip_row(db: Session, device_id: int, row: dict):
    db.execute(
        text(
            """
            INSERT INTO geo_ip (
                device_id,
                name,
                action,
                block_period,
                country_name
            )
            VALUES (
                :device_id,
                :name,
                :action,
                :block_period,
                CAST(:country_name AS jsonb)
            )
            ON CONFLICT (device_id, name) DO UPDATE SET
                action = EXCLUDED.action,
                block_period = EXCLUDED.block_period,
                country_name = EXCLUDED.country_name,
                updated_at = now()
            """
        ),
        {"device_id": device_id, **row, "country_name": json.dumps(row["country_name"])},
    )


def _extract_ip_list_policy_rows(payload: dict, ip_list_policy_name: str) -> list[dict]:
    rows = _extract_results(payload)
    parsed_rows = []
    for row in rows:
        seq_value = row.get("seq")
        try:
            seq = int(seq_value) if seq_value is not None else None
        except (TypeError, ValueError):
            seq = None
        if seq is None:
            continue
        parsed_rows.append(
            {
                "name": ip_list_policy_name,
                "seq": seq,
                "type": _normalize_optional_text(row.get("type")),
                "group_type": _normalize_optional_text(row.get("group-type") or row.get("group_type")),
                "ip": _normalize_optional_text(row.get("ip")),
                "ip_group": _normalize_optional_text(row.get("ip-group") or row.get("ip_group")),
                "ip_external": _normalize_optional_text(row.get("ip-external") or row.get("ip_external")),
                "raw_json": row,
            }
        )
    return parsed_rows


def _upsert_ip_list_policy_rows(db: Session, device_id: int, rows: list[dict]):
    for row in rows:
        db.execute(
            text(
                """
                INSERT INTO ip_list_policy (
                    device_id,
                    name,
                    seq,
                    type,
                    group_type,
                    ip,
                    ip_group,
                    ip_external,
                    raw_json
                )
                VALUES (
                    :device_id,
                    :name,
                    :seq,
                    :type,
                    :group_type,
                    :ip,
                    :ip_group,
                    :ip_external,
                    CAST(:raw_json AS jsonb)
                )
                ON CONFLICT (device_id, name, seq) DO UPDATE SET
                    type = EXCLUDED.type,
                    group_type = EXCLUDED.group_type,
                    ip = EXCLUDED.ip,
                    ip_group = EXCLUDED.ip_group,
                    ip_external = EXCLUDED.ip_external,
                    raw_json = EXCLUDED.raw_json,
                    updated_at = now()
                """
            ),
            {"device_id": device_id, **row, "raw_json": json.dumps(row["raw_json"])},
        )


def _extract_application_layer_dos_prevention_row(payload: dict, policy_name: str) -> dict:
    rows = _extract_results(payload)
    result = rows[0] if rows else {}
    return {
        "name": policy_name,
        "http_request_flood_prevention_rule": _normalize_optional_text(
            result.get("http-request-flood-prevention-rule") or result.get("http_request_flood_prevention_rule")
        ),
        "enable_layer4_dos_prevention": _normalize_optional_text(
            result.get("enable-layer4-dos-prevention") or result.get("enable_layer4_dos_prevention")
        ),
        "layer4_access_limit_rule": _normalize_optional_text(
            result.get("layer4-access-limit-rule") or result.get("layer4_access_limit_rule")
        ),
        "layer4_connection_flood_check_rule": _normalize_optional_text(
            result.get("layer4-connection-flood-check-rule") or result.get("layer4_connection_flood_check_rule")
        ),
        "raw_json": payload if isinstance(payload, dict) else {"results": result},
    }


def _upsert_application_layer_dos_prevention_row(db: Session, device_id: int, row: dict):
    db.execute(
        text(
            """
            INSERT INTO "application-layer-dos-prevention" (
                device_id,
                name,
                http_request_flood_prevention_rule,
                enable_layer4_dos_prevention,
                layer4_access_limit_rule,
                layer4_connection_flood_check_rule,
                raw_json
            )
            VALUES (
                :device_id,
                :name,
                :http_request_flood_prevention_rule,
                :enable_layer4_dos_prevention,
                :layer4_access_limit_rule,
                :layer4_connection_flood_check_rule,
                CAST(:raw_json AS jsonb)
            )
            ON CONFLICT (device_id, name) DO UPDATE SET
                http_request_flood_prevention_rule = EXCLUDED.http_request_flood_prevention_rule,
                enable_layer4_dos_prevention = EXCLUDED.enable_layer4_dos_prevention,
                layer4_access_limit_rule = EXCLUDED.layer4_access_limit_rule,
                layer4_connection_flood_check_rule = EXCLUDED.layer4_connection_flood_check_rule,
                raw_json = EXCLUDED.raw_json,
                updated_at = now()
            """
        ),
        {"device_id": device_id, **row, "raw_json": json.dumps(row["raw_json"])},
    )


def _extract_http_request_flood_prevention_rule_row(payload: dict, rule_name: str) -> dict:
    rows = _extract_results(payload)
    result = rows[0] if rows else {}
    return {
        "name": rule_name,
        "access_limit_in_http_session": _normalize_optional_text(
            result.get("access-limit-in-http-session") or result.get("access_limit_in_http_session")
        ),
        "action": _normalize_optional_text(result.get("action")),
        "bot_confirmation": _normalize_optional_text(
            result.get("bot-confirmation") or result.get("bot_confirmation")
        ),
        "bot_recognition": _normalize_optional_text(
            result.get("bot-recognition") or result.get("bot_recognition")
        ),
        "raw_json_http_connection": payload if isinstance(payload, dict) else {"results": result},
    }


def _upsert_http_request_flood_prevention_rule_row(db: Session, device_id: int, row: dict):
    db.execute(
        text(
            """
            INSERT INTO "http-request-flood-prevention-rule" (
                device_id,
                name,
                access_limit_in_http_session,
                action,
                bot_confirmation,
                bot_recognition,
                raw_json_http_connection
            )
            VALUES (
                :device_id,
                :name,
                :access_limit_in_http_session,
                :action,
                :bot_confirmation,
                :bot_recognition,
                CAST(:raw_json_http_connection AS jsonb)
            )
            ON CONFLICT (device_id, name) DO UPDATE SET
                access_limit_in_http_session = EXCLUDED.access_limit_in_http_session,
                action = EXCLUDED.action,
                bot_confirmation = EXCLUDED.bot_confirmation,
                bot_recognition = EXCLUDED.bot_recognition,
                raw_json_http_connection = EXCLUDED.raw_json_http_connection,
                updated_at = now()
            """
        ),
        {"device_id": device_id, **row, "raw_json_http_connection": json.dumps(row["raw_json_http_connection"])},
    )


def _extract_layer4_access_limit_rule_row(payload: dict, rule_name: str) -> dict:
    rows = _extract_results(payload)
    result = rows[0] if rows else {}
    return {
        "name": rule_name,
        "access_limit_standalone_ip": _normalize_optional_text(
            result.get("access-limit-standalone-ip") or result.get("access_limit_standalone_ip")
        ),
        "access_limit_share_ip": _normalize_optional_text(
            result.get("access-limit-share-ip") or result.get("access_limit_share_ip")
        ),
        "bot_confirmation": _normalize_optional_text(
            result.get("bot-confirmation") or result.get("bot_confirmation")
        ),
        "bot_recognition": _normalize_optional_text(
            result.get("bot-recognition") or result.get("bot_recognition")
        ),
        "action": _normalize_optional_text(result.get("action")),
    }


def _upsert_layer4_access_limit_rule_row(db: Session, device_id: int, row: dict):
    db.execute(
        text(
            """
            INSERT INTO "/layer4-access-limit-rule" (
                device_id,
                name,
                access_limit_standalone_ip,
                access_limit_share_ip,
                bot_confirmation,
                bot_recognition,
                action
            )
            VALUES (
                :device_id,
                :name,
                :access_limit_standalone_ip,
                :access_limit_share_ip,
                :bot_confirmation,
                :bot_recognition,
                :action
            )
            ON CONFLICT (device_id, name) DO UPDATE SET
                access_limit_standalone_ip = EXCLUDED.access_limit_standalone_ip,
                access_limit_share_ip = EXCLUDED.access_limit_share_ip,
                bot_confirmation = EXCLUDED.bot_confirmation,
                bot_recognition = EXCLUDED.bot_recognition,
                action = EXCLUDED.action,
                updated_at = now()
            """
        ),
        {"device_id": device_id, **row},
    )


def _extract_tcp_flood_prevention_row(payload: dict, rule_name: str) -> dict:
    rows = _extract_results(payload)
    result = rows[0] if rows else {}
    return {
        "name": rule_name,
        "layer4_connection_threshold": _normalize_optional_text(
            result.get("layer4-connection-threshold") or result.get("layer4_connection_threshold")
        ),
        "action": _normalize_optional_text(result.get("action")),
    }


def _upsert_tcp_flood_prevention_row(db: Session, device_id: int, row: dict):
    db.execute(
        text(
            """
            INSERT INTO tcp_flood_prevention (
                device_id,
                name,
                layer4_connection_threshold,
                action
            )
            VALUES (
                :device_id,
                :name,
                :layer4_connection_threshold,
                :action
            )
            ON CONFLICT (device_id, name) DO UPDATE SET
                layer4_connection_threshold = EXCLUDED.layer4_connection_threshold,
                action = EXCLUDED.action,
                updated_at = now()
            """
        ),
        {"device_id": device_id, **row},
    )


def _extract_bot_mitigate_policy_row(payload: dict, policy_name: str) -> dict:
    rows = _extract_results(payload)
    result = rows[0] if rows else {}
    return {
        "name": policy_name,
        "biometrics_based_detection": _normalize_optional_text(
            result.get("biometrics-based-detection") or result.get("biometrics_based_detection")
        ),
        "threshold_based_detection": _normalize_optional_text(
            result.get("threshold-based-detection") or result.get("threshold_based_detection")
        ),
        "known_bots": _normalize_optional_text(result.get("known-bots") or result.get("known_bots")),
        "raw_json": payload if isinstance(payload, dict) else {"results": result},
    }


def _upsert_bot_mitigate_policy_row(db: Session, device_id: int, row: dict):
    db.execute(
        text(
            """
            INSERT INTO "bot-mitigate-policy" (
                device_id,
                name,
                biometrics_based_detection,
                threshold_based_detection,
                known_bots,
                raw_json
            )
            VALUES (
                :device_id,
                :name,
                :biometrics_based_detection,
                :threshold_based_detection,
                :known_bots,
                CAST(:raw_json AS jsonb)
            )
            ON CONFLICT (device_id, name) DO UPDATE SET
                biometrics_based_detection = EXCLUDED.biometrics_based_detection,
                threshold_based_detection = EXCLUDED.threshold_based_detection,
                known_bots = EXCLUDED.known_bots,
                raw_json = EXCLUDED.raw_json,
                updated_at = now()
            """
        ),
        {"device_id": device_id, **row, "raw_json": json.dumps(row["raw_json"])},
    )


def _extract_biometric_based_detection_row(payload: dict, policy_name: str) -> dict:
    rows = _extract_results(payload)
    row = rows[0] if rows else {}
    return {
        "name": policy_name,
        "mouse_movement": _normalize_optional_text(row.get("mouse-movement") or row.get("mouse_movement")),
        "page_focus": _normalize_optional_text(row.get("page-focus") or row.get("page_focus")),
        "keyboard": _normalize_optional_text(row.get("keyboard")),
        "screen_touch": _normalize_optional_text(row.get("screen-touch") or row.get("screen_touch")),
        "scroll": _normalize_optional_text(row.get("scroll")),
        "bot_traits": _normalize_optional_text(row.get("bot-traits") or row.get("bot_traits")),
        "bot_traits_num": _normalize_optional_text(row.get("bot-traits-num") or row.get("bot_traits_num")),
        "action": _normalize_optional_text(row.get("action")),
        "host": None,
        "raw_json": payload if isinstance(payload, dict) else {"results": row},
        "raw_json_url_list": None,
    }


def _extract_biometric_hosts(payload: dict) -> str | None:
    rows = _extract_results(payload)
    hosts = []
    for row in rows:
        host = _normalize_optional_text(row.get("host") or row.get("url") or row.get("name"))
        if host and host not in hosts:
            hosts.append(host)
    if not hosts:
        return None
    return ", ".join(hosts)


def _upsert_biometric_based_detection_row(db: Session, device_id: int, row: dict):
    db.execute(
        text(
            """
            INSERT INTO biometric_based_detection (
                device_id,
                name,
                mouse_movement,
                page_focus,
                keyboard,
                screen_touch,
                scroll,
                bot_traits,
                bot_traits_num,
                action,
                host,
                raw_json,
                raw_json_url_list
            )
            VALUES (
                :device_id,
                :name,
                :mouse_movement,
                :page_focus,
                :keyboard,
                :screen_touch,
                :scroll,
                :bot_traits,
                :bot_traits_num,
                :action,
                :host,
                CAST(:raw_json AS jsonb),
                CAST(:raw_json_url_list AS jsonb)
            )
            ON CONFLICT (device_id, name) DO UPDATE SET
                mouse_movement = EXCLUDED.mouse_movement,
                page_focus = EXCLUDED.page_focus,
                keyboard = EXCLUDED.keyboard,
                screen_touch = EXCLUDED.screen_touch,
                scroll = EXCLUDED.scroll,
                bot_traits = EXCLUDED.bot_traits,
                bot_traits_num = EXCLUDED.bot_traits_num,
                action = EXCLUDED.action,
                host = EXCLUDED.host,
                raw_json = EXCLUDED.raw_json,
                raw_json_url_list = EXCLUDED.raw_json_url_list,
                updated_at = now()
            """
        ),
        {
            "device_id": device_id,
            **row,
            "raw_json": json.dumps(row["raw_json"]),
            "raw_json_url_list": json.dumps(row["raw_json_url_list"]) if row.get("raw_json_url_list") is not None else "null",
        },
    )


def _extract_threshold_based_detection_row(payload: dict, policy_name: str) -> dict:
    rows = _extract_results(payload)
    row = rows[0] if rows else {}
    return {
        "name": policy_name,
        "bot_confirmation": _normalize_optional_text(row.get("bot-confirmation") or row.get("bot_confirmation")),
        "bot_recognition": _normalize_optional_text(row.get("bot-recognition") or row.get("bot_recognition")),
        "crawler_detection": _normalize_optional_text(row.get("crawler-detection") or row.get("crawler_detection")),
        "crawler_action": _normalize_optional_text(row.get("crawler-action") or row.get("crawler_action")),
        "crawler_occurrence_num": _normalize_optional_text(row.get("crawler-occurrence-num") or row.get("crawler_occurrence_num")),
        "crawler_within": _normalize_optional_text(row.get("crawler-within") or row.get("crawler_within")),
        "slow_attack_detection": _normalize_optional_text(row.get("slow-attack-detection") or row.get("slow_attack_detection")),
        "slow_attack_action": _normalize_optional_text(row.get("slow-attack-action") or row.get("slow_attack_action")),
        "slow_attack_occurrence_num": _normalize_optional_text(
            row.get("slow-attack-occurrence-num") or row.get("slow_attack_occurrence_num")
        ),
        "slow_attack_within": _normalize_optional_text(row.get("slow-attack-within") or row.get("slow_attack_within")),
        "raw_json": payload if isinstance(payload, dict) else {"results": row},
    }


def _upsert_threshold_based_detection_row(db: Session, device_id: int, row: dict):
    db.execute(
        text(
            """
            INSERT INTO threshold_based_detection (
                device_id,
                name,
                bot_confirmation,
                bot_recognition,
                crawler_detection,
                crawler_action,
                crawler_occurrence_num,
                crawler_within,
                slow_attack_detection,
                slow_attack_action,
                slow_attack_occurrence_num,
                slow_attack_within,
                raw_json
            )
            VALUES (
                :device_id,
                :name,
                :bot_confirmation,
                :bot_recognition,
                :crawler_detection,
                :crawler_action,
                :crawler_occurrence_num,
                :crawler_within,
                :slow_attack_detection,
                :slow_attack_action,
                :slow_attack_occurrence_num,
                :slow_attack_within,
                CAST(:raw_json AS jsonb)
            )
            ON CONFLICT (device_id, name) DO UPDATE SET
                bot_confirmation = EXCLUDED.bot_confirmation,
                bot_recognition = EXCLUDED.bot_recognition,
                crawler_detection = EXCLUDED.crawler_detection,
                crawler_action = EXCLUDED.crawler_action,
                crawler_occurrence_num = EXCLUDED.crawler_occurrence_num,
                crawler_within = EXCLUDED.crawler_within,
                slow_attack_detection = EXCLUDED.slow_attack_detection,
                slow_attack_action = EXCLUDED.slow_attack_action,
                slow_attack_occurrence_num = EXCLUDED.slow_attack_occurrence_num,
                slow_attack_within = EXCLUDED.slow_attack_within,
                raw_json = EXCLUDED.raw_json,
                updated_at = now()
            """
        ),
        {"device_id": device_id, **row, "raw_json": json.dumps(row["raw_json"])},
    )


def _extract_known_bots_row(payload: dict, known_bots_name: str) -> dict:
    rows = _extract_results(payload)
    row = rows[0] if rows else {}
    return {
        "known_bots_name": known_bots_name,
        "dos_status": _normalize_optional_text(row.get("dos-status") or row.get("dos_status")),
        "dos_action": _normalize_optional_text(row.get("dos-action") or row.get("dos_action")),
        "spam_status": _normalize_optional_text(row.get("spam-status") or row.get("spam_status")),
        "spam_action": _normalize_optional_text(row.get("spam-action") or row.get("spam_action")),
        "trojan_status": _normalize_optional_text(row.get("trojan-status") or row.get("trojan_status")),
        "trojan_action": _normalize_optional_text(row.get("trojan-action") or row.get("trojan_action")),
        "scanner_status": _normalize_optional_text(row.get("scanner-status") or row.get("scanner_status")),
        "scanner_action": _normalize_optional_text(row.get("scanner-action") or row.get("scanner_action")),
        "crawler_status": _normalize_optional_text(row.get("crawler-status") or row.get("crawler_status")),
        "crawler_action": _normalize_optional_text(row.get("crawler-action") or row.get("crawler_action")),
        "known_engines_status": _normalize_optional_text(row.get("known-engines-status") or row.get("known_engines_status")),
        "known_engines_action": _normalize_optional_text(row.get("known-engines-action") or row.get("known_engines_action")),
        "raw_json": payload if isinstance(payload, dict) else {"results": row},
    }


def _upsert_known_bots_row(db: Session, device_id: int, row: dict):
    db.execute(
        text(
            """
            INSERT INTO "Known-bots" (
                device_id,
                known_bots_name,
                dos_status,
                dos_action,
                spam_status,
                spam_action,
                trojan_status,
                trojan_action,
                scanner_status,
                scanner_action,
                crawler_status,
                crawler_action,
                known_engines_status,
                known_engines_action,
                raw_json
            )
            VALUES (
                :device_id,
                :known_bots_name,
                :dos_status,
                :dos_action,
                :spam_status,
                :spam_action,
                :trojan_status,
                :trojan_action,
                :scanner_status,
                :scanner_action,
                :crawler_status,
                :crawler_action,
                :known_engines_status,
                :known_engines_action,
                CAST(:raw_json AS jsonb)
            )
            ON CONFLICT (device_id, known_bots_name) DO UPDATE SET
                dos_status = EXCLUDED.dos_status,
                dos_action = EXCLUDED.dos_action,
                spam_status = EXCLUDED.spam_status,
                spam_action = EXCLUDED.spam_action,
                trojan_status = EXCLUDED.trojan_status,
                trojan_action = EXCLUDED.trojan_action,
                scanner_status = EXCLUDED.scanner_status,
                scanner_action = EXCLUDED.scanner_action,
                crawler_status = EXCLUDED.crawler_status,
                crawler_action = EXCLUDED.crawler_action,
                known_engines_status = EXCLUDED.known_engines_status,
                known_engines_action = EXCLUDED.known_engines_action,
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
            _extract_by_aliases(item, ["web_protection_profile_name", "web_protection_profile", "web-protection-profile"])
        )
        server_pool_name = _normalize_optional_text(_extract_by_aliases(item, ["server_pool_name", "server_pool", "server-pool"]))
        allow_hosts = _normalize_optional_text(_extract_by_aliases(item, ["allow_hosts", "allow-hosts", "allowhosts"]))
        rows.append(
            {
                "server_policy_name": policy_name,
                "web_protection_profile_name": web_protection_profile_name,
                "server_pool_name": server_pool_name,
                "allow_hosts": allow_hosts,
                "traffic_mirror": _as_enable_disable(
                    _extract_by_aliases(item, ["traffic_mirror", "traffic-mirror", "traffic_mirror_val", "traffic-mirror_val"])
                ),
                "monitor_mode": _as_enable_disable(
                    _extract_by_aliases(item, ["monitor_mode", "monitor-mode", "monitor_mode_val", "monitor-mode_val"])
                ),
                "raw_json": item,
            }
        )
    return rows


HTTP2_RFC_CONTROL_FIELDS = [
    field
    for field in HTTP_PROTOCOL_PARAMETER_RESTRICTION_FIELDS
    if (field.startswith("h2") or field.startswith("http2")) and not field.endswith("_action")
]

HTTP_RFC_CONTROL_FIELDS = [
    field
    for field in HTTP_PROTOCOL_PARAMETER_RESTRICTION_FIELDS
    if not (field.startswith("h2") or field.startswith("http2")) and not field.endswith("_action")
]


SIGNATURE_SELECTION_FIELDS = [
    "cross_site_scripting",
    "cross_site_scripting_extended",
    "sql_injection",
    "sql_injection_extended",
    "generic_attacks",
    "generic_attacks_extended",
    "known_exploits",
    "trojans",
    "information_disclosure",
    "personally_identifiable_information",
]


def _is_signature_attribute_selected(value) -> bool:
    normalized = _as_enable_disable(value)
    return normalized is not None and normalized != "disable"


def _build_signature_set_status(row: dict) -> dict:
    selected_count = sum(1 for field in SIGNATURE_SELECTION_FIELDS if _is_signature_attribute_selected(row.get(field)))
    is_enabled = selected_count >= 2
    return {
        "selected_count": selected_count,
        "status": "enabled" if is_enabled else "disabled",
    }


def _build_http2_rfc_control_status(row: dict) -> dict:
    if not _as_bool(row.get("http2")):
        return {
            "selected_count": 0,
            "status": "disabled",
        }

    selected_count = sum(1 for field in HTTP2_RFC_CONTROL_FIELDS if _is_signature_attribute_selected(row.get(field)))
    is_enabled = selected_count >= 2
    return {
        "selected_count": selected_count,
        "status": "enabled" if is_enabled else "disabled",
    }


def _build_http_rfc_control_status(row: dict) -> dict:
    selected_count = sum(1 for field in HTTP_RFC_CONTROL_FIELDS if _is_signature_attribute_selected(row.get(field)))
    is_enabled = selected_count >= 1
    return {
        "selected_count": selected_count,
        "status": "enabled" if is_enabled else "disabled",
    }


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
                    monitor_mode,
                    raw_json
                )
                VALUES (
                    :device_id,
                    :server_policy_name,
                    :web_protection_profile_name,
                    :server_pool_name,
                    :allow_hosts,
                    :traffic_mirror,
                    :monitor_mode,
                    CAST(:raw_json AS jsonb)
                )
                ON CONFLICT (device_id, server_policy_name) DO UPDATE SET
                    web_protection_profile_name = EXCLUDED.web_protection_profile_name,
                    server_pool_name = EXCLUDED.server_pool_name,
                    allow_hosts = EXCLUDED.allow_hosts,
                    traffic_mirror = EXCLUDED.traffic_mirror,
                    monitor_mode = EXCLUDED.monitor_mode,
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
                "monitor_mode": row["monitor_mode"],
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
        "sni": _normalize_optional_text(result.get("sni")),
        "sni_certificate": _normalize_optional_text(result.get("sni-certificate") or result.get("sni_certificate")),
        "client_certificate": _normalize_optional_text(result.get("client-certificate") or result.get("client_certificate")),
        "certificate_name": _normalize_optional_text(result.get("certificate_name") or result.get("certificate")),
        "sni_certificate_name": _normalize_optional_text(
            result.get("sni_certificate_name") or result.get("sni_name") or result.get("sni-certificate") or result.get("sni_certificate")
        ),
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


def _extract_certificate_local_row(payload: dict, certificate_name: str) -> dict:
    results = payload.get("results", []) if isinstance(payload, dict) else []
    result = results[0] if isinstance(results, list) and results and isinstance(results[0], dict) else {}
    return {
        "certificate_name": certificate_name,
        "subject": _normalize_optional_text(result.get("subject") or result.get("subject_name")),
        "issuer": _normalize_optional_text(result.get("issuer") or result.get("issuer_name")),
        "valid_from": _normalize_optional_text(
            result.get("valid_from") or result.get("valid-from") or result.get("not_before") or result.get("not-before")
        ),
        "valid_to": _normalize_optional_date(
            result.get("valid_to")
            or result.get("valid-to")
            or result.get("validTo")
            or result.get("not_after")
            or result.get("not-after")
        ),
        "serial_number": _normalize_optional_text(
            result.get("serial_number") or result.get("serial-number") or result.get("serialNumber") or result.get("serial")
        ),
        "raw_json": result or {"certificate_name": certificate_name},
    }


def _upsert_certificate_local_row(db: Session, device_id: int, row: dict):
    db.execute(
        text(
            """
            INSERT INTO certificate_local (
                device_id,
                certificate_name,
                subject,
                issuer,
                valid_from,
                valid_to,
                days_left,
                serial_number,
                raw_json
            )
            VALUES (
                :device_id,
                :certificate_name,
                :subject,
                :issuer,
                :valid_from,
                CAST(:valid_to AS date),
                CASE WHEN :valid_to IS NULL THEN NULL ELSE CURRENT_DATE - CAST(:valid_to AS date) END,
                :serial_number,
                CAST(:raw_json AS jsonb)
            )
            ON CONFLICT (device_id, certificate_name) DO UPDATE SET
                subject = EXCLUDED.subject,
                issuer = EXCLUDED.issuer,
                valid_from = EXCLUDED.valid_from,
                valid_to = EXCLUDED.valid_to,
                days_left = EXCLUDED.days_left,
                serial_number = EXCLUDED.serial_number,
                raw_json = EXCLUDED.raw_json
            """
        ),
        {
            "device_id": device_id,
            "certificate_name": row["certificate_name"],
            "subject": row["subject"],
            "issuer": row["issuer"],
            "valid_from": row["valid_from"],
            "valid_to": row["valid_to"],
            "serial_number": row["serial_number"],
            "raw_json": json.dumps(row["raw_json"]),
        },
    )


def _extract_certificate_sni_member_rows(payload: dict, sni_name: str) -> list[dict]:
    results = payload.get("results", []) if isinstance(payload, dict) else []
    if not isinstance(results, list):
        return []
    rows = []
    for result in results:
        if not isinstance(result, dict):
            continue
        rows.append(
            {
                "sni_name": sni_name,
                "seq": result.get("seq"),
                "domain": _normalize_optional_text(result.get("domain")),
                "domain_type": _normalize_optional_text(result.get("domain-type") or result.get("domain_type")),
                "local_cert": _normalize_optional_text(result.get("local-cert") or result.get("local_cert")),
                "inter_group": _normalize_optional_text(result.get("inter-group") or result.get("inter_group")),
                "verify": _normalize_optional_text(result.get("verify")),
                "raw_json": result,
            }
        )
    return rows


def _upsert_certificate_sni_member_rows(db: Session, device_id: int, sni_name: str, rows: list[dict]):
    db.execute(
        text(
            """
            INSERT INTO certificate_sni (device_id, sni_name)
            VALUES (:device_id, :sni_name)
            ON CONFLICT (device_id, sni_name) DO NOTHING
            """
        ),
        {"device_id": device_id, "sni_name": sni_name},
    )

    db.execute(
        text(
            """
            DELETE FROM certificate_sni_members
            WHERE device_id = :device_id
              AND sni_name = :sni_name
            """
        ),
        {"device_id": device_id, "sni_name": sni_name},
    )
    for row in rows:
        db.execute(
            text(
                """
                INSERT INTO certificate_sni_members (
                    device_id,
                    sni_name,
                    seq,
                    domain,
                    domain_type,
                    local_cert,
                    inter_group,
                    verify,
                    raw_json
                )
                VALUES (
                    :device_id,
                    :sni_name,
                    :seq,
                    :domain,
                    :domain_type,
                    :local_cert,
                    :inter_group,
                    :verify,
                    CAST(:raw_json AS jsonb)
                )
                """
            ),
            {
                "device_id": device_id,
                "sni_name": row["sni_name"],
                "seq": row["seq"],
                "domain": row["domain"],
                "domain_type": row["domain_type"],
                "local_cert": row["local_cert"],
                "inter_group": row["inter_group"],
                "verify": row["verify"],
                "raw_json": json.dumps(row["raw_json"]),
            },
        )


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
    if row["client_certificate"]:
        db.execute(
            text(
                """
                INSERT INTO certificate_local (device_id, certificate_name)
                VALUES (:device_id, :certificate_name)
                ON CONFLICT (device_id, certificate_name) DO NOTHING
                """
            ),
            {"device_id": device_id, "certificate_name": row["client_certificate"]},
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
                sni,
                sni_certificate,
                client_certificate,
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
                :sni,
                :sni_certificate,
                :client_certificate,
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
                sni = EXCLUDED.sni,
                sni_certificate = EXCLUDED.sni_certificate,
                client_certificate = EXCLUDED.client_certificate,
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
            "sni": row["sni"],
            "sni_certificate": row["sni_certificate"],
            "client_certificate": row["client_certificate"],
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
    return server_pool_row


def _fetch_and_upsert_certificate_local(
    db: Session,
    device: ManagedDevice,
    certificate_name: str,
    headers: dict,
):
    encoded_name = quote(certificate_name, safe="")
    endpoint = f"/api/v2.0/system/certificate.local?mkey={encoded_name}"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    certificate_row = _extract_certificate_local_row(payload, certificate_name)
    _upsert_certificate_local_row(db, device.id, certificate_row)


def _fetch_and_upsert_certificate_sni_members(
    db: Session,
    device: ManagedDevice,
    sni_name: str,
    headers: dict,
):
    encoded_name = quote(sni_name, safe="")
    endpoint = f"/api/v2.0/cmdb/system/certificate.sni/members?mkey={encoded_name}"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    rows = _extract_certificate_sni_member_rows(payload, sni_name)
    _upsert_certificate_sni_member_rows(db, device.id, sni_name, rows)


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
    rules_payload = _fetch_json_with_fallback_endpoints(
        device,
        headers,
        [f"/api/v2.0/cmdb/waf/custom-access.policy/rule?mkey={encoded_policy_name}"],
    )
    row = _extract_custom_access_policy_row(rules_payload, custom_access_policy_name)
    _upsert_custom_access_policy_row(db, device.id, row)
    return row


def _fetch_and_upsert_custom_access_rule(
    db: Session,
    device: ManagedDevice,
    custom_access_rule_name: str,
    headers: dict,
):
    encoded_rule_name = quote(custom_access_rule_name, safe="")

    policy_rule_payload = _fetch_json_with_fallback_endpoints(
        device,
        headers,
        [f"/api/v2.0/cmdb/waf/custom-access.rule?mkey={encoded_rule_name}"],
    )
    custom_rule_payload = _fetch_json_with_fallback_endpoints(
        device,
        headers,
        [f"/api/v2.0/waf/webprotection.advancedprotection.customrule.newcustomaccessrule?name={encoded_rule_name}"],
    )

    row = _extract_custom_access_rule_row(custom_access_rule_name, policy_rule_payload, custom_rule_payload)
    _upsert_custom_access_rule_row(db, device.id, row)


def _fetch_and_upsert_allow_method_policy(
    db: Session,
    device: ManagedDevice,
    headers: dict,
):
    endpoint = "/api/v2.0/cmdb/waf/allow-method-policy"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    rows = _extract_allow_method_policy_rows(payload)
    _upsert_allow_method_policy_rows(db, device.id, rows)


def _fetch_and_upsert_xml_validation_policy(
    db: Session,
    device: ManagedDevice,
    headers: dict,
):
    endpoint = "/api/v2.0/cmdb/waf/xml-validation.policy"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    rows = _extract_xml_validation_policy_rows(payload)
    _upsert_xml_validation_policy_rows(db, device.id, rows)


def _fetch_and_upsert_json_validation_policy(
    db: Session,
    device: ManagedDevice,
    headers: dict,
):
    endpoint = "/api/v2.0/cmdb/waf/json-validation.policy"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    rows = _extract_json_validation_policy_rows(payload)
    _upsert_json_validation_policy_rows(db, device.id, rows)


def _fetch_and_upsert_application_layer_dos_prevention(
    db: Session,
    device: ManagedDevice,
    application_layer_dos_prevention_name: str,
    headers: dict,
):
    encoded_name = quote(application_layer_dos_prevention_name, safe="")
    endpoint = f"/api/v2.0/cmdb/waf/application-layer-dos-prevention?mkey={encoded_name}"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    row = _extract_application_layer_dos_prevention_row(payload, application_layer_dos_prevention_name)
    _upsert_application_layer_dos_prevention_row(db, device.id, row)
    return row


def _fetch_and_upsert_geo_ip(
    db: Session,
    device: ManagedDevice,
    geo_ip_name: str,
    headers: dict,
):
    encoded_name = quote(geo_ip_name, safe="")
    endpoint = f"/api/v2.0/cmdb/waf/geo-block-list?mkey={encoded_name}"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    geo_ip_row = _extract_geo_ip_row(response.json(), geo_ip_name)

    countries_endpoint = f"/api/v2.0/cmdb/waf/geo-block-list/country-list?mkey={encoded_name}"
    countries_url = f"{_build_device_base_url(device.ip).rstrip('/')}{countries_endpoint}"
    countries_response = requests.get(
        countries_url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    countries_response.raise_for_status()
    country_names = _extract_geo_ip_country_names(countries_response.json())

    row = {
        **geo_ip_row,
        "country_name": country_names,
    }
    _upsert_geo_ip_row(db, device.id, row)


def _fetch_and_upsert_ip_list_policy(
    db: Session,
    device: ManagedDevice,
    ip_list_policy_name: str,
    headers: dict,
):
    encoded_name = quote(ip_list_policy_name, safe="")
    endpoint = f"/api/v2.0/cmdb/waf/ip-list/members?mkey={encoded_name}"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    rows = _extract_ip_list_policy_rows(payload, ip_list_policy_name)
    _upsert_ip_list_policy_rows(db, device.id, rows)


def _fetch_and_upsert_http_request_flood_prevention_rule(
    db: Session,
    device: ManagedDevice,
    http_request_flood_prevention_rule_name: str,
    headers: dict,
):
    encoded_name = quote(http_request_flood_prevention_rule_name, safe="")
    endpoint = f"/api/v2.0/cmdb/waf/http-request-flood-prevention-rule?mkey={encoded_name}"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    row = _extract_http_request_flood_prevention_rule_row(payload, http_request_flood_prevention_rule_name)
    _upsert_http_request_flood_prevention_rule_row(db, device.id, row)


def _fetch_and_upsert_layer4_access_limit_rule(
    db: Session,
    device: ManagedDevice,
    layer4_access_limit_rule_name: str,
    headers: dict,
):
    encoded_name = quote(layer4_access_limit_rule_name, safe="")
    endpoint = f"/api/v2.0/cmdb/waf/layer4-access-limit-rule?mkey={encoded_name}"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    row = _extract_layer4_access_limit_rule_row(payload, layer4_access_limit_rule_name)
    _upsert_layer4_access_limit_rule_row(db, device.id, row)


def _fetch_and_upsert_tcp_flood_prevention(
    db: Session,
    device: ManagedDevice,
    layer4_connection_flood_check_rule_name: str,
    headers: dict,
):
    encoded_name = quote(layer4_connection_flood_check_rule_name, safe="")
    endpoint = f"/api/v2.0/cmdb/waf/layer4-connection-flood-check-rule?mkey={encoded_name}"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    row = _extract_tcp_flood_prevention_row(payload, layer4_connection_flood_check_rule_name)
    _upsert_tcp_flood_prevention_row(db, device.id, row)


def _fetch_and_upsert_bot_mitigate_policy(
    db: Session,
    device: ManagedDevice,
    bot_mitigate_policy_name: str,
    headers: dict,
):
    encoded_name = quote(bot_mitigate_policy_name, safe="")
    endpoint = f"/api/v2.0/cmdb/waf/bot-mitigate-policy?mkey={encoded_name}"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    row = _extract_bot_mitigate_policy_row(payload, bot_mitigate_policy_name)
    _upsert_bot_mitigate_policy_row(db, device.id, row)
    return row


def _fetch_and_upsert_biometric_based_detection(
    db: Session,
    device: ManagedDevice,
    biometric_policy_names: set[str],
    headers: dict,
):
    if not biometric_policy_names:
        return
    for policy_name in biometric_policy_names:
        encoded_name = quote(policy_name, safe="")
        endpoint = f"/api/v2.0/cmdb/waf/biometrics-based-detection?mkey={encoded_name}"
        url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
        response = requests.get(
            url,
            headers=headers,
            timeout=30,
            verify=settings.fortiweb_verify_ssl,
        )
        response.raise_for_status()
        row = _extract_biometric_based_detection_row(response.json(), policy_name)
        url_list_endpoint = f"/api/v2.0/cmdb/waf/biometrics-based-detection/url-list?mkey={encoded_name}"
        url_list_url = f"{_build_device_base_url(device.ip).rstrip('/')}{url_list_endpoint}"
        url_list_response = requests.get(
            url_list_url,
            headers=headers,
            timeout=30,
            verify=settings.fortiweb_verify_ssl,
        )
        url_list_response.raise_for_status()
        url_list_payload = url_list_response.json()
        row["host"] = _extract_biometric_hosts(url_list_payload)
        row["raw_json_url_list"] = url_list_payload
        _upsert_biometric_based_detection_row(db, device.id, row)


def _fetch_and_upsert_threshold_based_detection(
    db: Session,
    device: ManagedDevice,
    threshold_based_detection_name: str,
    headers: dict,
):
    encoded_name = quote(threshold_based_detection_name, safe="")
    endpoint = f"/api/v2.0/cmdb/waf/threshold-based-detection.policy?mkey={encoded_name}"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    row = _extract_threshold_based_detection_row(payload, threshold_based_detection_name)
    _upsert_threshold_based_detection_row(db, device.id, row)


def _fetch_and_upsert_known_bots(
    db: Session,
    device: ManagedDevice,
    known_bots_name: str,
    headers: dict,
):
    encoded_name = quote(known_bots_name, safe="")
    endpoint = f"/api/v2.0/cmdb/waf/known-bots?mkey={encoded_name}"
    url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=settings.fortiweb_verify_ssl,
    )
    response.raise_for_status()
    payload = response.json()
    row = _extract_known_bots_row(payload, known_bots_name)
    _upsert_known_bots_row(db, device.id, row)


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
                db.rollback()
                web_protection_profile_rows = []

            try:
                _fetch_and_upsert_http_protocol_parameter_restrictions(db, device, headers)
            except Exception:
                db.rollback()

            try:
                _fetch_and_upsert_syntax_based_attack_detection(db, device, headers)
            except Exception:
                db.rollback()

            try:
                _fetch_and_upsert_allow_method_policy(db, device, headers)
            except Exception:
                db.rollback()

            try:
                _fetch_and_upsert_xml_validation_policy(db, device, headers)
            except Exception:
                db.rollback()

            try:
                _fetch_and_upsert_json_validation_policy(db, device, headers)
            except Exception:
                db.rollback()

            unique_custom_access_policies = {row["custom_access_policy"] for row in web_protection_profile_rows if row.get("custom_access_policy")}
            unique_custom_access_rules = set()
            for custom_access_policy_name in unique_custom_access_policies:
                try:
                    custom_access_policy_row = _fetch_and_upsert_custom_access_policy(db, device, custom_access_policy_name, headers)
                    unique_custom_access_rules.update(custom_access_policy_row.get("rule_names") or [])
                except Exception:
                    db.rollback()
            for custom_access_rule_name in unique_custom_access_rules:
                try:
                    _fetch_and_upsert_custom_access_rule(db, device, custom_access_rule_name, headers)
                except Exception:
                    db.rollback()

            unique_cookie_security_policies = {row["cookie_security_policy"] for row in web_protection_profile_rows if row.get("cookie_security_policy")}
            for cookie_security_name in unique_cookie_security_policies:
                try:
                    _fetch_and_upsert_cookie_security_policy(db, device, cookie_security_name, headers)
                except Exception:
                    db.rollback()
            unique_geo_ip_policies = {row["geo_block_list_policy"] for row in web_protection_profile_rows if row.get("geo_block_list_policy")}
            for geo_ip_name in unique_geo_ip_policies:
                try:
                    _fetch_and_upsert_geo_ip(db, device, geo_ip_name, headers)
                except Exception:
                    db.rollback()
            unique_bot_mitigate_policies = {row["bot_mitigate_policy"] for row in web_protection_profile_rows if row.get("bot_mitigate_policy")}
            fetched_bot_mitigate_rows = []
            for bot_mitigate_policy_name in unique_bot_mitigate_policies:
                try:
                    fetched_row = _fetch_and_upsert_bot_mitigate_policy(db, device, bot_mitigate_policy_name, headers)
                    fetched_bot_mitigate_rows.append(fetched_row)
                except Exception:
                    db.rollback()
            biometric_policy_names = {
                row["biometrics_based_detection"]
                for row in fetched_bot_mitigate_rows
                if row.get("biometrics_based_detection")
            }
            try:
                _fetch_and_upsert_biometric_based_detection(db, device, biometric_policy_names, headers)
            except Exception:
                db.rollback()
            threshold_based_detection_names = {
                row["threshold_based_detection"]
                for row in fetched_bot_mitigate_rows
                if row.get("threshold_based_detection")
            }
            for threshold_based_detection_name in threshold_based_detection_names:
                try:
                    _fetch_and_upsert_threshold_based_detection(
                        db,
                        device,
                        threshold_based_detection_name,
                        headers,
                    )
                except Exception:
                    db.rollback()
            known_bots_names = {
                row["known_bots"]
                for row in fetched_bot_mitigate_rows
                if row.get("known_bots")
            }
            for known_bots_name in known_bots_names:
                try:
                    _fetch_and_upsert_known_bots(
                        db,
                        device,
                        known_bots_name,
                        headers,
                    )
                except Exception:
                    db.rollback()

            unique_signature_rules = {row["signature_rule"] for row in web_protection_profile_rows if row.get("signature_rule")}
            for signature_rule in unique_signature_rules:
                try:
                    _fetch_and_upsert_signature(db, device, signature_rule, headers)
                except Exception:
                    db.rollback()
            unique_application_layer_dos_prevention_policies = {
                row["application_layer_dos_prevention"] for row in web_protection_profile_rows if row.get("application_layer_dos_prevention")
            }
            fetched_application_layer_dos_rows = []
            unique_ip_list_policies = {row["ip_list_policy"] for row in web_protection_profile_rows if row.get("ip_list_policy")}
            for ip_list_policy_name in unique_ip_list_policies:
                try:
                    _fetch_and_upsert_ip_list_policy(db, device, ip_list_policy_name, headers)
                except Exception:
                    db.rollback()
            for application_layer_dos_prevention_name in unique_application_layer_dos_prevention_policies:
                try:
                    fetched_row = _fetch_and_upsert_application_layer_dos_prevention(
                        db,
                        device,
                        application_layer_dos_prevention_name,
                        headers,
                    )
                    fetched_application_layer_dos_rows.append(fetched_row)
                except Exception:
                    db.rollback()
            unique_http_request_flood_prevention_rules = {
                row["http_request_flood_prevention_rule"]
                for row in fetched_application_layer_dos_rows
                if row.get("http_request_flood_prevention_rule")
            }
            for http_request_flood_prevention_rule_name in unique_http_request_flood_prevention_rules:
                try:
                    _fetch_and_upsert_http_request_flood_prevention_rule(
                        db,
                        device,
                        http_request_flood_prevention_rule_name,
                        headers,
                    )
                except Exception:
                    db.rollback()
            unique_layer4_access_limit_rules = {
                row["layer4_access_limit_rule"] for row in fetched_application_layer_dos_rows if row.get("layer4_access_limit_rule")
            }
            for layer4_access_limit_rule_name in unique_layer4_access_limit_rules:
                try:
                    _fetch_and_upsert_layer4_access_limit_rule(
                        db,
                        device,
                        layer4_access_limit_rule_name,
                        headers,
                    )
                except Exception:
                    db.rollback()
            unique_layer4_connection_flood_check_rules = {
                row["layer4_connection_flood_check_rule"]
                for row in fetched_application_layer_dos_rows
                if row.get("layer4_connection_flood_check_rule")
            }
            for layer4_connection_flood_check_rule_name in unique_layer4_connection_flood_check_rules:
                try:
                    _fetch_and_upsert_tcp_flood_prevention(
                        db,
                        device,
                        layer4_connection_flood_check_rule_name,
                        headers,
                    )
                except Exception:
                    db.rollback()

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
            fetched_server_pool_rows = []
            for server_pool_name in unique_server_pools:
                fetched_server_pool_rows.append(_fetch_and_upsert_server_pool(db, device, server_pool_name, headers))
            certificate_local_names = {
                certificate_name
                for row in fetched_server_pool_rows
                for certificate_name in [row.get("certificate_name"), row.get("client_certificate")]
                if certificate_name
            }
            for certificate_name in certificate_local_names:
                try:
                    _fetch_and_upsert_certificate_local(db, device, certificate_name, headers)
                except Exception:
                    db.rollback()
            certificate_sni_names = {
                sni_name
                for row in fetched_server_pool_rows
                for sni_name in [row.get("sni_certificate")]
                if sni_name
            }
            for sni_name in certificate_sni_names:
                try:
                    _fetch_and_upsert_certificate_sni_members(db, device, sni_name, headers)
                except Exception:
                    db.rollback()
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
    def _normalize_policy_lookup_key(value):
        if value is None:
            return ""
        return str(value).strip().lower()

    http_rfc_columns_sql = ",\n                ".join(f"hpr.{field}" for field in HTTP_RFC_CONTROL_FIELDS)
    rows = db.execute(
        text(
            f"""
            SELECT
                d.id AS device_id,
                d.name AS device_name,
                d.ip AS device_ip,
                sp.server_policy_name,
                sp.web_protection_profile_name,
                sp.server_pool_name,
                sp.allow_hosts,
                sp.traffic_mirror,
                sp.monitor_mode,
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
                sbad.xss_html_tag_based_status,
                sbad.xss_html_attribute_based_status,
                sbad.xss_javascript_function_based_status,
                sbad.xss_javascript_variable_based_status,
                sbad.sql_stacked_queries_status,
                sbad.sql_embeded_queries_status,
                sbad.sql_condition_based_status,
                sbad.sql_arithmetic_operation_status,
                sbad.sql_line_comments_status,
                sbad.sql_function_based_status,
                sig.cross_site_scripting,
                sig.cross_site_scripting_extended,
                sig.sql_injection,
                sig.sql_injection_extended,
                sig.generic_attacks,
                sig.generic_attacks_extended,
                sig.known_exploits,
                sig.trojans,
                sig.information_disclosure,
                sig.personally_identifiable_information,
                {http_rfc_columns_sql},
                hpr.http2_max_requests_check,
                hpr.h2_rst_stream_check,
                aldp.http_request_flood_prevention_rule,
                aldp.enable_layer4_dos_prevention,
                aldp.layer4_access_limit_rule,
                aldp.layer4_connection_flood_check_rule,
                hrfpr.access_limit_in_http_session,
                hrfpr.action AS http_request_flood_prevention_action,
                hrfpr.bot_confirmation,
                hrfpr.bot_recognition,
                l4alr.access_limit_standalone_ip,
                l4alr.access_limit_share_ip,
                l4alr.bot_confirmation AS layer4_access_limit_bot_confirmation,
                l4alr.bot_recognition AS layer4_access_limit_bot_recognition,
                l4alr.action AS layer4_access_limit_action,
                tcp.layer4_connection_threshold,
                tcp.action AS tcp_flood_prevention_action,
                amp.allow_method AS allow_method_value,
                bmp.name AS bot_mitigate_policy_name,
                bmp.biometrics_based_detection,
                bmp.threshold_based_detection,
                bmp.known_bots,
                bbd.name AS biometric_based_detection_name,
                bbd.mouse_movement AS biometric_mouse_movement,
                bbd.page_focus AS biometric_page_focus,
                bbd.keyboard AS biometric_keyboard,
                bbd.screen_touch AS biometric_screen_touch,
                bbd.scroll AS biometric_scroll,
                bbd.bot_traits AS biometric_bot_traits,
                bbd.bot_traits_num AS biometric_bot_traits_num,
                bbd.action AS biometric_action,
                bbd.host AS biometric_host,
                tbd.name AS threshold_based_detection_name,
                tbd.bot_confirmation AS threshold_bot_confirmation,
                tbd.bot_recognition AS threshold_bot_recognition,
                tbd.crawler_detection AS threshold_crawler_detection,
                tbd.crawler_action AS threshold_crawler_action,
                tbd.crawler_occurrence_num AS threshold_crawler_occurrence_num,
                tbd.crawler_within AS threshold_crawler_within,
                tbd.slow_attack_detection AS threshold_slow_attack_detection,
                tbd.slow_attack_action AS threshold_slow_attack_action,
                tbd.slow_attack_occurrence_num AS threshold_slow_attack_occurrence_num,
                tbd.slow_attack_within AS threshold_slow_attack_within,
                kb.known_bots_name,
                kb.dos_status AS known_bots_dos_status,
                kb.dos_action AS known_bots_dos_action,
                kb.spam_status AS known_bots_spam_status,
                kb.spam_action AS known_bots_spam_action,
                kb.trojan_status AS known_bots_trojan_status,
                kb.trojan_action AS known_bots_trojan_action,
                kb.scanner_status AS known_bots_scanner_status,
                kb.scanner_action AS known_bots_scanner_action,
                kb.crawler_status AS known_bots_crawler_status,
                kb.crawler_action AS known_bots_crawler_action,
                kb.known_engines_status AS known_bots_known_engines_status,
                kb.known_engines_action AS known_bots_known_engines_action,
                pool.ip AS server_pool_ip,
                pool.sni,
                pool.sni_certificate,
                pool.client_certificate,
                cl.subject AS client_certificate_subject,
                cl.issuer AS client_certificate_issuer,
                cl.valid_from AS client_certificate_valid_from,
                cl.valid_to AS client_certificate_valid_to,
                cl.days_left AS client_certificate_days_left,
                cl.serial_number AS client_certificate_serial_number,
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
            LEFT JOIN certificate_local cl
                ON cl.device_id = pool.device_id
                AND cl.certificate_name = COALESCE(pool.client_certificate, pool.certificate_name)
            LEFT JOIN web_protection_profiles wpp
                ON wpp.device_id = sp.device_id
                AND wpp.web_protection_profile_name = sp.web_protection_profile_name
            LEFT JOIN "syntax-based-attack-detection" sbad
                ON sbad.device_id = wpp.device_id
                AND sbad.name = wpp.syntax_based_attack_detection
            LEFT JOIN signature sig
                ON sig.device_id = wpp.device_id
                AND sig.signature_set_name = wpp.signature_rule
            LEFT JOIN http_protocol_parameter_restriction hpr
                ON hpr.device_id = wpp.device_id
                AND hpr.name = wpp.http_protocol_parameter_restriction
            LEFT JOIN "application-layer-dos-prevention" aldp
                ON aldp.device_id = wpp.device_id
                AND aldp.name = wpp.application_layer_dos_prevention
            LEFT JOIN "http-request-flood-prevention-rule" hrfpr
                ON hrfpr.device_id = aldp.device_id
                AND hrfpr.name = aldp.http_request_flood_prevention_rule
            LEFT JOIN "/layer4-access-limit-rule" l4alr
                ON l4alr.device_id = aldp.device_id
                AND l4alr.name = aldp.layer4_access_limit_rule
            LEFT JOIN tcp_flood_prevention tcp
                ON tcp.device_id = aldp.device_id
                AND tcp.name = aldp.layer4_connection_flood_check_rule
            LEFT JOIN "allow-method-policy" amp
                ON amp.device_id = wpp.device_id
                AND amp.allow_method_policy_name = wpp.allow_method_policy
            LEFT JOIN "bot-mitigate-policy" bmp
                ON bmp.device_id = wpp.device_id
                AND bmp.name = wpp.bot_mitigate_policy
            LEFT JOIN biometric_based_detection bbd
                ON bbd.device_id = bmp.device_id
                AND bbd.name = bmp.biometrics_based_detection
            LEFT JOIN threshold_based_detection tbd
                ON tbd.device_id = bmp.device_id
                AND tbd.name = bmp.threshold_based_detection
            LEFT JOIN "Known-bots" kb
                ON kb.device_id = bmp.device_id
                AND kb.known_bots_name = bmp.known_bots
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

    sni_member_rows = db.execute(
        text(
            """
            SELECT
                device_id,
                sni_name,
                seq,
                domain,
                domain_type,
                local_cert,
                inter_group,
                verify,
                raw_json
            FROM certificate_sni_members
            ORDER BY seq ASC
            """
        )
    ).mappings().all()
    sni_members_by_name = {}
    for row in sni_member_rows:
        key = (row["device_id"], row["sni_name"])
        sni_members_by_name.setdefault(key, []).append(
            {
                "seq": row["seq"],
                "domain": row["domain"],
                "domain_type": row["domain_type"],
                "local_cert": row["local_cert"],
                "inter_group": row["inter_group"],
                "verify": row["verify"],
                "raw_json": row["raw_json"],
            }
        )

    ip_list_policy_rows = db.execute(
        text(
            """
            SELECT
                device_id,
                name,
                seq,
                type,
                group_type,
                ip,
                ip_group,
                ip_external,
                raw_json
            FROM ip_list_policy
            ORDER BY seq ASC
            """
        )
    ).mappings().all()

    ip_list_policy_by_name = {}
    for row in ip_list_policy_rows:
        key = (row["device_id"], row["name"])
        ip_list_policy_by_name.setdefault(key, []).append(
            {
                "name": row["name"],
                "seq": row["seq"],
                "type": row["type"],
                "group_type": row["group_type"],
                "ip": row["ip"],
                "ip_group": row["ip_group"],
                "ip_external": row["ip_external"],
                "raw_json": row["raw_json"],
            }
        )

    geo_ip_rows = db.execute(
        text(
            """
            SELECT
                device_id,
                name,
                action,
                block_period,
                country_name
            FROM geo_ip
            ORDER BY device_id DESC, name ASC
            """
        )
    ).mappings().all()

    geo_ip_by_name = {}
    for row in geo_ip_rows:
        key = (row["device_id"], row["name"])
        country_name = row["country_name"]
        if isinstance(country_name, list):
            country_name_value = ", ".join(country_name) if country_name else ""
        elif country_name is None:
            country_name_value = ""
        else:
            country_name_value = str(country_name)
        geo_ip_by_name.setdefault(key, []).append(
            {
                "name": row["name"],
                "action": row["action"],
                "block_period": row["block_period"],
                "country_name": country_name_value,
            }
        )

    xml_validation_policy_rows = db.execute(
        text(
            """
            SELECT
                device_id,
                xml_validation_name,
                enable_signature_detection
            FROM "xml-validation-policy"
            """
        )
    ).mappings().all()
    xml_validation_policy_by_name = {}
    for row in xml_validation_policy_rows:
        lookup_key = (row["device_id"], _normalize_policy_lookup_key(row["xml_validation_name"]))
        xml_validation_policy_by_name[lookup_key] = {
            "xml_validation_name": row["xml_validation_name"],
            "enable_signature_detection": row["enable_signature_detection"],
        }
    json_validation_policy_rows = db.execute(
        text(
            """
            SELECT
                device_id,
                json_validation_name,
                enable_attack_signatures
            FROM "json-validation-policy"
            """
        )
    ).mappings().all()
    json_validation_policy_by_name = {}
    for row in json_validation_policy_rows:
        lookup_key = (row["device_id"], _normalize_policy_lookup_key(row["json_validation_name"]))
        json_validation_policy_by_name[lookup_key] = {
            "json_validation_name": row["json_validation_name"],
            "enable_attack_signatures": row["enable_attack_signatures"],
        }

    custom_access_policy_rows = db.execute(
        text(
            """
            SELECT
                device_id,
                custom_access_policy_name,
                rule_names
            FROM "custom-access-policy"
            """
        )
    ).mappings().all()
    custom_access_policy_rules_by_name = {}
    for row in custom_access_policy_rows:
        key = (row["device_id"], row["custom_access_policy_name"])
        custom_access_policy_rules_by_name[key] = row.get("rule_names") or []

    custom_access_rule_rows = db.execute(
        text(
            """
            SELECT
                device_id,
                name,
                action,
                "bot-confirmation" AS bot_confirmation,
                "bot-recognition" AS bot_recognition,
                raw_json_custom_rule
            FROM "custom-access-rule"
            """
        )
    ).mappings().all()
    custom_access_rules_by_name = {}
    for row in custom_access_rule_rows:
        custom_access_rules_by_name[(row["device_id"], row["name"])] = {
            "name": row["name"],
            "action": row["action"],
            "bot_confirmation": row["bot_confirmation"],
            "bot_recognition": row["bot_recognition"],
            "raw_json_custom_rule": row["raw_json_custom_rule"],
        }

    biometric_detection_rows = db.execute(
        text(
            """
            SELECT
                device_id,
                name,
                mouse_movement,
                page_focus,
                keyboard,
                screen_touch,
                scroll,
                bot_traits,
                bot_traits_num,
                action,
                host
            FROM biometric_based_detection
            """
        )
    ).mappings().all()
    biometric_detection_by_name = {}
    for row in biometric_detection_rows:
        lookup_key = (row["device_id"], _normalize_policy_lookup_key(row["name"]))
        biometric_detection_by_name[lookup_key] = {
            "name": row["name"],
            "mouse_movement": row["mouse_movement"],
            "page_focus": row["page_focus"],
            "keyboard": row["keyboard"],
            "screen_touch": row["screen_touch"],
            "scroll": row["scroll"],
            "bot_traits": row["bot_traits"],
            "bot_traits_num": row["bot_traits_num"],
            "action": row["action"],
            "host": row["host"],
        }

    threshold_detection_rows = db.execute(
        text(
            """
            SELECT
                device_id,
                name,
                bot_confirmation,
                bot_recognition,
                crawler_detection,
                crawler_action,
                crawler_occurrence_num,
                crawler_within,
                slow_attack_detection,
                slow_attack_action,
                slow_attack_occurrence_num,
                slow_attack_within
            FROM threshold_based_detection
            """
        )
    ).mappings().all()
    threshold_detection_by_name = {}
    for row in threshold_detection_rows:
        lookup_key = (row["device_id"], _normalize_policy_lookup_key(row["name"]))
        threshold_detection_by_name[lookup_key] = {
            "name": row["name"],
            "bot_confirmation": row["bot_confirmation"],
            "bot_recognition": row["bot_recognition"],
            "crawler_detection": row["crawler_detection"],
            "crawler_action": row["crawler_action"],
            "crawler_occurrence_num": row["crawler_occurrence_num"],
            "crawler_within": row["crawler_within"],
            "slow_attack_detection": row["slow_attack_detection"],
            "slow_attack_action": row["slow_attack_action"],
            "slow_attack_occurrence_num": row["slow_attack_occurrence_num"],
            "slow_attack_within": row["slow_attack_within"],
        }

    known_bots_rows = db.execute(
        text(
            """
            SELECT
                device_id,
                known_bots_name,
                dos_status,
                dos_action,
                spam_status,
                spam_action,
                trojan_status,
                trojan_action,
                scanner_status,
                scanner_action,
                crawler_status,
                crawler_action,
                known_engines_status,
                known_engines_action
            FROM "Known-bots"
            """
        )
    ).mappings().all()
    known_bots_by_name = {}
    for row in known_bots_rows:
        lookup_key = (row["device_id"], _normalize_policy_lookup_key(row["known_bots_name"]))
        known_bots_by_name[lookup_key] = {
            "known_bots_name": row["known_bots_name"],
            "dos_status": row["dos_status"],
            "dos_action": row["dos_action"],
            "spam_status": row["spam_status"],
            "spam_action": row["spam_action"],
            "trojan_status": row["trojan_status"],
            "trojan_action": row["trojan_action"],
            "scanner_status": row["scanner_status"],
            "scanner_action": row["scanner_action"],
            "crawler_status": row["crawler_status"],
            "crawler_action": row["crawler_action"],
            "known_engines_status": row["known_engines_status"],
            "known_engines_action": row["known_engines_action"],
        }

    backup_states_by_policy = _load_server_policy_state_from_backups(days=7)
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
            xml_validation_lookup = xml_validation_policy_by_name.get(
                (device_id, _normalize_policy_lookup_key(row["xml_validation_policy"])),
                {},
            )
            xml_enable_signature_detection = xml_validation_lookup.get("enable_signature_detection")
            json_validation_lookup = json_validation_policy_by_name.get(
                (device_id, _normalize_policy_lookup_key(row["json_validation_policy"])),
                {},
            )
            json_enable_attack_signatures = json_validation_lookup.get("enable_attack_signatures")
            biometric_policy_name = row["biometric_based_detection_name"] or row["biometrics_based_detection"]
            biometric_lookup = biometric_detection_by_name.get(
                (device_id, _normalize_policy_lookup_key(biometric_policy_name)),
                {},
            )
            threshold_policy_name = row["threshold_based_detection_name"] or row["threshold_based_detection"]
            threshold_lookup = threshold_detection_by_name.get(
                (device_id, _normalize_policy_lookup_key(threshold_policy_name)),
                {},
            )
            known_bots_policy_name = row["known_bots_name"] or row["known_bots"]
            known_bots_lookup = known_bots_by_name.get(
                (device_id, _normalize_policy_lookup_key(known_bots_policy_name)),
                {},
            )
            allow_method_info = _format_allow_method_value(row.get("allow_method_value"))
            signature_set_status = _build_signature_set_status(row)
            http_rfc_control_status = _build_http_rfc_control_status(row)
            http2_rfc_control_status = _build_http2_rfc_control_status(row)
            custom_access_policy_name = row["custom_access_policy"]
            custom_access_rule_names = custom_access_policy_rules_by_name.get((device_id, custom_access_policy_name), [])
            custom_access_rule_details = []
            for rule_name in custom_access_rule_names:
                custom_access_rule_details.append(
                    custom_access_rules_by_name.get(
                        (device_id, rule_name),
                        {
                            "name": rule_name,
                            "action": "",
                            "bot_confirmation": "",
                            "bot_recognition": "",
                            "raw_json_custom_rule": {},
                        },
                    )
                )
            by_device[device_id]["server_policies"].append(
                {
                    "server_policy_name": row["server_policy_name"],
                    "web_protection_profile_name": row["web_protection_profile_name"],
                    "server_pool_name": row["server_pool_name"],
                    "allow_hosts": row["allow_hosts"],
                    "traffic_mirror": row["traffic_mirror"],
                    "traffic-mirror": row["traffic_mirror"],
                    "monitor_mode": row["monitor_mode"],
                    "monitor-mode": row["monitor_mode"],
                    "ip": row["server_pool_ip"],
                    "sni": row["sni"],
                    "sni-certificate": row["sni_certificate"],
                    "sni_certificate": row["sni_certificate"],
                    "sni_entries": sni_members_by_name.get((device_id, row["sni_certificate"]), []),
                    "client-certificate": row["client_certificate"],
                    "client_certificate": row["client_certificate"],
                    "client_certificate_details": {
                        "subject": row["client_certificate_subject"],
                        "issuer": row["client_certificate_issuer"],
                        "valid_from": row["client_certificate_valid_from"],
                        "valid_to": row["client_certificate_valid_to"],
                        "days_left": row["client_certificate_days_left"],
                        "serial_number": row["client_certificate_serial_number"],
                    },
                    "tls13_custom_cipher": row["tls13_custom_cipher"],
                    "tls_v10": row["tls_v10"],
                    "tls_v11": row["tls_v11"],
                    "tls_v12": row["tls_v12"],
                    "tls_v13": row["tls_v13"],
                    "http2": row["http2"],
                    "http_rfc": http_rfc_control_status["status"],
                    "http_rfc_selected_count": http_rfc_control_status["selected_count"],
                    "http2_rfc_control": http2_rfc_control_status["status"],
                    "http2_rfc_selected_count": http2_rfc_control_status["selected_count"],
                    "signature": signature_set_status["status"],
                    "signature_selected_count": signature_set_status["selected_count"],
                    "allow_method": allow_method_info["display"],
                    "allow_method_raw": allow_method_info["raw"],
                    "allow_method_list": allow_method_info["methods"],
                    "xml_validation_enable_signature_detection": xml_enable_signature_detection,
                    "xml-validation-enable-signature-detection": xml_enable_signature_detection,
                    "json_validation_enable_attack_signatures": json_enable_attack_signatures,
                    "json-validation-enable-attack-signatures": json_enable_attack_signatures,
                    "recent_changes": [],
                    "syntax_based_attack_detection_details": {
                        "xss_html_tag_based_status": row["xss_html_tag_based_status"],
                        "xss_html_attribute_based_status": row["xss_html_attribute_based_status"],
                        "xss_javascript_function_based_status": row["xss_javascript_function_based_status"],
                        "xss_javascript_variable_based_status": row["xss_javascript_variable_based_status"],
                        "sql_stacked_queries_status": row["sql_stacked_queries_status"],
                        "sql_embeded_queries_status": row["sql_embeded_queries_status"],
                        "sql_condition_based_status": row["sql_condition_based_status"],
                        "sql_arithmetic_operation_status": row["sql_arithmetic_operation_status"],
                        "sql_line_comments_status": row["sql_line_comments_status"],
                        "sql_function_based_status": row["sql_function_based_status"],
                    },
                    "allow_hosts_entries": allow_hosts_by_policy.get((device_id, row["allow_hosts"]), []),
                    "web_protection_profile_details": {
                        "signature_rule": row["signature_rule"],
                        "signature_set_status": signature_set_status["status"],
                        "signature_selected_count": signature_set_status["selected_count"],
                        "http_rfc": http_rfc_control_status["status"],
                        "http_rfc_selected_count": http_rfc_control_status["selected_count"],
                        "http2_rfc_control": http2_rfc_control_status["status"],
                        "http2_rfc_selected_count": http2_rfc_control_status["selected_count"],
                        "cross_site_scripting": row["cross_site_scripting"],
                        "cross_site_scripting_extended": row["cross_site_scripting_extended"],
                        "sql_injection": row["sql_injection"],
                        "sql_injection_extended": row["sql_injection_extended"],
                        "generic_attacks": row["generic_attacks"],
                        "generic_attacks_extended": row["generic_attacks_extended"],
                        "known_exploits": row["known_exploits"],
                        "trojans": row["trojans"],
                        "information_disclosure": row["information_disclosure"],
                        "personally_identifiable_information": row["personally_identifiable_information"],
                        "http_protocol_parameter_restriction": row["http_protocol_parameter_restriction"],
                        "cookie_security_policy": row["cookie_security_policy"],
                        "custom_access_policy": row["custom_access_policy"],
                        "custom_access_rules": custom_access_rule_details,
                        "csrf_protection": row["csrf_protection"],
                        "syntax_based_attack_detection": row["syntax_based_attack_detection"],
                        "parameter_validation_rule": row["parameter_validation_rule"],
                        "hidden_fields_protection": row["hidden_fields_protection"],
                        "file_upload_policy": row["file_upload_policy"],
                        "webshell_detection_policy": row["webshell_detection_policy"],
                        "allow_method_policy": row["allow_method_policy"],
                        "allow_method": allow_method_info["display"],
                        "allow_method_raw": allow_method_info["raw"],
                        "allow_method_list": allow_method_info["methods"],
                        "bot_mitigate_policy": row["bot_mitigate_policy"],
                        "xml_validation_policy": row["xml_validation_policy"],
                        "xml_validation_enable_signature_detection": xml_enable_signature_detection,
                        "xml-validation-enable-signature-detection": xml_enable_signature_detection,
                        "json_validation_policy": row["json_validation_policy"],
                        "json_validation_enable_attack_signatures": json_enable_attack_signatures,
                        "json-validation-enable-attack-signatures": json_enable_attack_signatures,
                        "graphql_validation_policy": row["graphql_validation_policy"],
                        "openapi_validation_policy": row["openapi_validation_policy"],
                        "application_layer_dos_prevention": row["application_layer_dos_prevention"],
                        "ip_list_policy": row["ip_list_policy"],
                        "ip_list_policy_entries": ip_list_policy_by_name.get((device_id, row["ip_list_policy"]), []),
                        "ip_intelligence": row["ip_intelligence"],
                        "geo_block_list_policy": row["geo_block_list_policy"],
                        "geo_ip_entries": geo_ip_by_name.get((device_id, row["geo_block_list_policy"]), []),
                        "waiting_room_policy": row["waiting_room_policy"],
                        "user_tracking_policy": row["user_tracking_policy"],
                        "websocket_security_policy": row["websocket_security_policy"],
                        "cors_protection_policy": row["cors_protection_policy"],
                        "syntax_based_attack_detection_details": {
                            "xss_html_tag_based_status": row["xss_html_tag_based_status"],
                            "xss_html_attribute_based_status": row["xss_html_attribute_based_status"],
                            "xss_javascript_function_based_status": row["xss_javascript_function_based_status"],
                            "xss_javascript_variable_based_status": row["xss_javascript_variable_based_status"],
                            "sql_stacked_queries_status": row["sql_stacked_queries_status"],
                            "sql_embeded_queries_status": row["sql_embeded_queries_status"],
                            "sql_condition_based_status": row["sql_condition_based_status"],
                            "sql_arithmetic_operation_status": row["sql_arithmetic_operation_status"],
                            "sql_line_comments_status": row["sql_line_comments_status"],
                            "sql_function_based_status": row["sql_function_based_status"],
                        },
                        "application_layer_dos_prevention_policy": {
                            "name": row["application_layer_dos_prevention"],
                            "http_request_flood_prevention_rule": row["http_request_flood_prevention_rule"],
                            "enable_layer4_dos_prevention": row["enable_layer4_dos_prevention"],
                            "layer4_access_limit_rule": row["layer4_access_limit_rule"],
                            "layer4_connection_flood_check_rule": row["layer4_connection_flood_check_rule"],
                            "access_limit_in_http_session": row["access_limit_in_http_session"],
                            "action": row["http_request_flood_prevention_action"],
                            "bot_confirmation": row["bot_confirmation"],
                            "bot_recognition": row["bot_recognition"],
                            "layer4_access_limit_rule_policy": {
                                "name": row["layer4_access_limit_rule"],
                                "access_limit_standalone_ip": row["access_limit_standalone_ip"],
                                "access_limit_share_ip": row["access_limit_share_ip"],
                                "bot_confirmation": row["layer4_access_limit_bot_confirmation"],
                                "bot_recognition": row["layer4_access_limit_bot_recognition"],
                                "action": row["layer4_access_limit_action"],
                            },
                            "tcp_flood_prevention_policy": {
                                "name": row["layer4_connection_flood_check_rule"],
                                "layer4_connection_threshold": row["layer4_connection_threshold"],
                                "action": row["tcp_flood_prevention_action"],
                            },
                            "layer4_connection_flood_check_rule_policy": {
                                "name": row["layer4_connection_flood_check_rule"],
                                "layer4_connection_threshold": row["layer4_connection_threshold"],
                                "action": row["tcp_flood_prevention_action"],
                            },
                            "bot_mitigate_policy_detail": {
                                "name": row["bot_mitigate_policy_name"],
                                "biometrics_based_detection": biometric_policy_name,
                                "threshold_based_detection": threshold_policy_name,
                                "known_bots": known_bots_policy_name,
                                "biometric_based_detection_details": {
                                    "name": biometric_lookup.get("name") or biometric_policy_name,
                                    "mouse_movement": biometric_lookup.get("mouse_movement") or row["biometric_mouse_movement"],
                                    "page_focus": biometric_lookup.get("page_focus") or row["biometric_page_focus"],
                                    "keyboard": biometric_lookup.get("keyboard") or row["biometric_keyboard"],
                                    "screen_touch": biometric_lookup.get("screen_touch") or row["biometric_screen_touch"],
                                    "scroll": biometric_lookup.get("scroll") or row["biometric_scroll"],
                                    "bot_traits": biometric_lookup.get("bot_traits") or row["biometric_bot_traits"],
                                    "bot_traits_num": biometric_lookup.get("bot_traits_num") or row["biometric_bot_traits_num"],
                                    "action": biometric_lookup.get("action") or row["biometric_action"],
                                    "host": biometric_lookup.get("host") or row["biometric_host"],
                                },
                                "threshold_based_detection_details": {
                                    "name": threshold_lookup.get("name") or threshold_policy_name,
                                    "bot_confirmation": threshold_lookup.get("bot_confirmation") or row["threshold_bot_confirmation"],
                                    "bot_recognition": threshold_lookup.get("bot_recognition") or row["threshold_bot_recognition"],
                                    "crawler_detection": threshold_lookup.get("crawler_detection") or row["threshold_crawler_detection"],
                                    "crawler_action": threshold_lookup.get("crawler_action") or row["threshold_crawler_action"],
                                    "crawler_occurrence_num": threshold_lookup.get("crawler_occurrence_num") or row["threshold_crawler_occurrence_num"],
                                    "crawler_within": threshold_lookup.get("crawler_within") or row["threshold_crawler_within"],
                                    "slow_attack_detection": threshold_lookup.get("slow_attack_detection") or row["threshold_slow_attack_detection"],
                                    "slow_attack_action": threshold_lookup.get("slow_attack_action") or row["threshold_slow_attack_action"],
                                    "slow_attack_occurrence_num": threshold_lookup.get("slow_attack_occurrence_num") or row["threshold_slow_attack_occurrence_num"],
                                    "slow_attack_within": threshold_lookup.get("slow_attack_within") or row["threshold_slow_attack_within"],
                                },
                                "known_bots_details": {
                                    "name": known_bots_lookup.get("known_bots_name") or known_bots_policy_name,
                                    "dos_status": known_bots_lookup.get("dos_status") or row["known_bots_dos_status"],
                                    "dos_action": known_bots_lookup.get("dos_action") or row["known_bots_dos_action"],
                                    "spam_status": known_bots_lookup.get("spam_status") or row["known_bots_spam_status"],
                                    "spam_action": known_bots_lookup.get("spam_action") or row["known_bots_spam_action"],
                                    "trojan_status": known_bots_lookup.get("trojan_status") or row["known_bots_trojan_status"],
                                    "trojan_action": known_bots_lookup.get("trojan_action") or row["known_bots_trojan_action"],
                                    "scanner_status": known_bots_lookup.get("scanner_status") or row["known_bots_scanner_status"],
                                    "scanner_action": known_bots_lookup.get("scanner_action") or row["known_bots_scanner_action"],
                                    "crawler_status": known_bots_lookup.get("crawler_status") or row["known_bots_crawler_status"],
                                    "crawler_action": known_bots_lookup.get("crawler_action") or row["known_bots_crawler_action"],
                                    "known_engines_status": known_bots_lookup.get("known_engines_status") or row["known_bots_known_engines_status"],
                                    "known_engines_action": known_bots_lookup.get("known_engines_action") or row["known_bots_known_engines_action"],
                                },
                            },
                        },
                    },
                }
            )
            latest_policy = by_device[device_id]["server_policies"][-1]
            current_status = _format_policy_status_label(row["monitor_mode"], row["server_pool_ip"])
            backup_key = (str(device_id), row["server_policy_name"])
            latest_policy["recent_changes"] = _build_recent_policy_changes(
                current_status,
                row["client_certificate_serial_number"],
                backup_states_by_policy.get(backup_key, []),
                {
                    "signature": signature_set_status["status"],
                    "http_rfc": http_rfc_control_status["status"],
                    "http2_rfc_control": http2_rfc_control_status["status"],
                },
            )

    return {"devices": list(by_device.values())}
