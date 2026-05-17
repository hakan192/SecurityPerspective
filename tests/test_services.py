from app.services import (
    _build_device_base_url,
    _build_http_rfc_control_status,
    _build_http2_rfc_control_status,
    _build_policy_maturity_assessment,
    _build_recent_policy_changes,
    _delete_missing_server_policy_rows,
    _extract_certificate_common_name,
    _extract_certificate_local_row,
    _extract_certificate_sni_member_rows,
    _extract_policy_rows,
    _extract_server_pool_row,
    _format_allow_method_value,
    _format_policy_status_label,
    _format_recent_change_date,
    _load_server_policy_state_from_backups,
)


def test_delete_missing_server_policy_rows_removes_policies_absent_from_latest_fetch():
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session

    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE server_policy (device_id integer, server_policy_name text)"))
        connection.execute(
            text(
                """
                INSERT INTO server_policy (device_id, server_policy_name)
                VALUES (1, 'keep-a'), (1, 'remove-b'), (2, 'other-device')
                """
            )
        )

    with Session(engine) as session:
        _delete_missing_server_policy_rows(session, 1, [{"server_policy_name": "keep-a"}])
        remaining = session.execute(
            text("SELECT device_id, server_policy_name FROM server_policy ORDER BY device_id, server_policy_name")
        ).all()

    assert remaining == [(1, "keep-a"), (2, "other-device")]


def test_delete_missing_server_policy_rows_clears_device_when_latest_fetch_is_empty():
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session

    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE server_policy (device_id integer, server_policy_name text)"))
        connection.execute(
            text(
                """
                INSERT INTO server_policy (device_id, server_policy_name)
                VALUES (1, 'remove-a'), (1, 'remove-b'), (2, 'other-device')
                """
            )
        )

    with Session(engine) as session:
        _delete_missing_server_policy_rows(session, 1, [])
        remaining = session.execute(
            text("SELECT device_id, server_policy_name FROM server_policy ORDER BY device_id, server_policy_name")
        ).all()

    assert remaining == [(2, "other-device")]


def test_extract_policy_rows_parses_traffic_mirror_disabled_value():
    payload = {"results": [{"name": "policy-a", "traffic-mirror": "disable"}]}
    rows = _extract_policy_rows(payload)

    assert len(rows) == 1
    assert rows[0]["traffic_mirror"] == "disable"


def test_extract_policy_rows_preserves_zero_valued_traffic_mirror():
    payload = {"results": [{"name": "policy-b", "traffic-mirror": 0}]}
    rows = _extract_policy_rows(payload)

    assert len(rows) == 1
    assert rows[0]["traffic_mirror"] == "disable"


def test_extract_policy_rows_parses_monitor_mode():
    payload = {"results": [{"name": "policy-c", "monitor-mode": "enable"}]}
    rows = _extract_policy_rows(payload)

    assert len(rows) == 1
    assert rows[0]["monitor_mode"] == "enable"


def test_extract_server_pool_row_parses_sni_certificate_and_client_certificate():
    payload = {
        "results": [
            {
                "sni": "enable",
                "sni-certificate": "sni-cert-01",
                "client-certificate": "client-cert-01",
            }
        ]
    }

    row = _extract_server_pool_row(payload, "pool-a")

    assert row["sni"] == "enable"
    assert row["sni_certificate"] == "sni-cert-01"
    assert row["sni_certificate_name"] == "sni-cert-01"
    assert row["client_certificate"] == "client-cert-01"


def test_extract_certificate_common_name_returns_only_cn_from_distinguished_name():
    subject = "C=TR, L=Istanbul, O=Example Org, CN=app.example.com"

    assert _extract_certificate_common_name(subject) == "app.example.com"


def test_extract_certificate_common_name_handles_slash_separated_and_escaped_values():
    subject = r"/C=US/O=Example/CN=api\,internal.example.com/OU=Security"

    assert _extract_certificate_common_name(subject) == "api,internal.example.com"


def test_extract_certificate_common_name_returns_only_issuer_cn():
    issuer = "C=US, O=Example Root CA, CN=Example Issuing CA"

    assert _extract_certificate_common_name(issuer) == "Example Issuing CA"


def test_extract_certificate_local_row_parses_certificate_attributes():
    payload = {
        "results": [
            {
                "subject": "CN=client.example.com",
                "issuer": "CN=Example-CA",
                "not-before": "2025-01-01",
                "not-after": "2027-04-19 20:41:03+00",
                "serial-number": "ABCD1234",
            }
        ]
    }

    row = _extract_certificate_local_row(payload, "client-cert-01")

    assert row["certificate_name"] == "client-cert-01"
    assert row["subject"] == "CN=client.example.com"
    assert row["issuer"] == "CN=Example-CA"
    assert row["valid_from"] == "2025-01-01"
    assert row["valid_to"] == "2027-04-19"
    assert row["serial_number"] == "ABCD1234"


def test_extract_certificate_local_row_parses_camel_case_valid_to_and_serial_number():
    payload = {
        "results": [
            {
                "validTo": "2028-12-31T23:59:59Z",
                "serialNumber": "XYZ7890",
            }
        ]
    }

    row = _extract_certificate_local_row(payload, "client-cert-02")

    assert row["valid_to"] == "2028-12-31"
    assert row["serial_number"] == "XYZ7890"


def test_extract_certificate_sni_member_rows_parses_each_result_entry():
    payload = {
        "results": [
            {
                "seq": 1,
                "domain": "onlineform.example.com",
                "domain-type": "plain",
                "local-cert": "cert-a",
                "inter-group": "ca-group-a",
                "verify": "",
            },
            {
                "seq": 2,
                "domain": "webforms.example.com",
                "domain-type": "plain",
                "local-cert": "cert-b",
                "inter-group": "ca-group-b",
                "verify": "",
            },
        ]
    }

    rows = _extract_certificate_sni_member_rows(payload, "sni-cert-1")

    assert len(rows) == 2
    assert rows[0]["sni_name"] == "sni-cert-1"
    assert rows[0]["seq"] == 1
    assert rows[0]["domain"] == "onlineform.example.com"
    assert rows[0]["local_cert"] == "cert-a"
    assert rows[1]["seq"] == 2
    assert rows[1]["domain"] == "webforms.example.com"
    assert rows[1]["local_cert"] == "cert-b"


def test_build_device_base_url_uses_configured_https_port(monkeypatch):
    monkeypatch.setattr("app.services.settings.fortiweb_base_url", "https://3.236.139.71:443")

    url = _build_device_base_url("10.20.30.40")

    assert url == "https://10.20.30.40:443"


def test_build_http2_rfc_control_status_enabled_when_two_h2_controls_enabled():
    row = {
        "http2": True,
        "http2_max_requests_check": "enable",
        "h2_rst_stream_check": "enabled",
    }

    status = _build_http2_rfc_control_status(row)

    assert status["selected_count"] == 2
    assert status["status"] == "enabled"


def test_build_http2_rfc_control_status_disabled_when_less_than_two_controls_enabled():
    row = {
        "http2": True,
        "http2_max_requests_check": "enable",
        "h2_rst_stream_check": "disable",
    }

    status = _build_http2_rfc_control_status(row)

    assert status["selected_count"] == 1
    assert status["status"] == "disabled"


def test_build_http2_rfc_control_status_disabled_when_server_pool_http2_disabled():
    row = {
        "http2": False,
        "http2_max_requests_check": "enable",
        "h2_rst_stream_check": "enable",
    }

    status = _build_http2_rfc_control_status(row)

    assert status["selected_count"] == 0
    assert status["status"] == "disabled"


def test_build_http_rfc_control_status_enabled_when_any_http_control_enabled():
    row = {
        "max_http_header_length_check": "enable",
        "illegal_http_version_check": "disable",
        "http2_max_requests_check": "disable",
        "h2_rst_stream_check": "disable",
    }

    status = _build_http_rfc_control_status(row)

    assert status["selected_count"] == 1
    assert status["status"] == "enabled"


def test_build_http_rfc_control_status_disabled_when_only_http2_controls_enabled():
    row = {
        "max_http_header_length_check": "disable",
        "http2_max_requests_check": "enable",
        "h2_rst_stream_check": "enabled",
    }

    status = _build_http_rfc_control_status(row)

    assert status["selected_count"] == 0
    assert status["status"] == "disabled"


def test_format_allow_method_value_formats_methods_for_ui():
    parsed = _format_allow_method_value("get, post put")

    assert parsed["raw"] == "get, post put"
    assert parsed["methods"] == ["GET", "POST", "PUT"]
    assert parsed["display"] == "GET, POST, PUT"


def test_format_allow_method_value_handles_all_methods_keyword():
    parsed = _format_allow_method_value("all")

    assert parsed["methods"] == ["ALL"]
    assert parsed["display"] == "All methods"


def test_format_policy_status_label_matches_policy_card_copy():
    assert _format_policy_status_label("enable", "10.0.0.1") == "Monitoring"
    assert _format_policy_status_label("disable", "10.0.0.1") == "Blocking"
    assert _format_policy_status_label("enable", None) == "Not Protected"


def test_format_recent_change_date_uses_day_month_without_year():
    from datetime import datetime, timezone

    assert _format_recent_change_date(datetime(2026, 5, 4, 14, 30, tzinfo=timezone.utc)) == "04/05"


def test_build_recent_policy_changes_keeps_backup_changes_within_window():
    from datetime import datetime, timezone

    older_status = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    newer_status = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)
    current_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Blocking",
        "CURRENT-SERIAL",
        [(older_status, "Monitoring", "CURRENT-SERIAL"), (newer_status, "Blocking", "CURRENT-SERIAL")],
        current_time=current_time,
    )

    assert changes == [
        {
            "id": f"policy-status-{int(newer_status.timestamp())}",
            "title": "Policy Status changed to Blocking",
            "summary": "The policy is now running in Blocking mode.",
            "time": "05/05",
            "type": "Server Policy",
        }
    ]


def test_build_recent_policy_changes_returns_backup_and_current_status_changes():
    from datetime import datetime, timezone

    older_change = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    latest_change = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)
    current_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Not Protected",
        "CURRENT-SERIAL",
        [(older_change, "Monitoring", "CURRENT-SERIAL"), (latest_change, "Blocking", "CURRENT-SERIAL")],
        current_time=current_time,
    )

    assert changes == [
        {
            "id": f"policy-status-{int(latest_change.timestamp())}",
            "title": "Policy Status changed to Blocking",
            "summary": "The policy is now running in Blocking mode.",
            "time": "05/05",
            "type": "Server Policy",
        },
        {
            "id": f"policy-status-{int(current_time.timestamp())}",
            "title": "Policy Status changed to Not Protected",
            "summary": "The policy is not protected because no server pool IP is configured.",
            "time": "06/05",
            "type": "Server Policy",
        },
    ]


def test_load_server_policy_state_from_backups_includes_not_protected_and_certificate_serial(tmp_path, monkeypatch):
    from datetime import datetime, timezone

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    backup_time = datetime.now(timezone.utc)
    backup_file = backup_dir / f"security_perspective_backup_{backup_time.strftime('%d_%m_%y_%H_%M_%S')}.sql"
    backup_file.write_text(
        '\n'.join(
            [
                "INSERT INTO \"server_pool\" (\"device_id\", \"server_pool_name\", \"ip\", \"client_certificate\") VALUES (1, 'pool-a', NULL, 'cert-a');",
                "INSERT INTO \"server_pool\" (\"device_id\", \"server_pool_name\", \"ip\", \"client_certificate\") VALUES (1, 'pool-b', '10.0.0.1', 'cert-b');",
                "INSERT INTO \"certificate_local\" (\"device_id\", \"certificate_name\", \"serial_number\") VALUES (1, 'cert-a', 'OLD-A');",
                "INSERT INTO \"certificate_local\" (\"device_id\", \"certificate_name\", \"serial_number\") VALUES (1, 'cert-b', 'OLD-B');",
                "INSERT INTO \"web_protection_profiles\" (\"device_id\", \"web_protection_profile_name\", \"signature_rule\", \"syntax_based_attack_detection\", \"custom_access_policy\", \"application_layer_dos_prevention\", \"bot_mitigate_policy\", \"allow_method_policy\", \"ip_list_policy\", \"geo_block_list_policy\", \"xml_validation_policy\", \"json_validation_policy\") VALUES (1, 'profile-b', 'sig-b', 'syntax-b', 'custom-b', 'dos-b', 'bot-b', 'allow-b', 'ip-list-b', 'geo-b', 'xml-b', 'json-b');",
                "INSERT INTO \"signature\" (\"device_id\", \"signature_set_name\", \"cross_site_scripting\", \"sql_injection\") VALUES (1, 'sig-b', 'enable', 'enable');",
                "INSERT INTO \"syntax-based-attack-detection\" (\"device_id\", \"name\", \"xss_html_tag_based_status\", \"sql_stacked_queries_status\") VALUES (1, 'syntax-b', 'enable', 'enable');",
                "INSERT INTO \"custom-access-policy\" (\"device_id\", \"custom_access_policy_name\", \"rule_names\") VALUES (1, 'custom-b', '{rule-a}');",
                "INSERT INTO \"application-layer-dos-prevention\" (\"device_id\", \"name\", \"http_request_flood_prevention_rule\", \"layer4_access_limit_rule\", \"layer4_connection_flood_check_rule\") VALUES (1, 'dos-b', 'http-flood-b', 'access-limit-b', 'tcp-flood-b');",
                "INSERT INTO \"bot-mitigate-policy\" (\"device_id\", \"name\", \"biometrics_based_detection\", \"threshold_based_detection\", \"known_bots\") VALUES (1, 'bot-b', 'biometric-b', 'threshold-b', 'known-b');",
                "INSERT INTO biometric_based_detection (\"device_id\", \"name\", \"mouse_movement\") VALUES (1, 'biometric-b', 'enable');",
                "INSERT INTO threshold_based_detection (\"device_id\", \"name\", \"crawler_detection\") VALUES (1, 'threshold-b', 'enable');",
                "INSERT INTO \"Known-bots\" (\"device_id\", \"known_bots_name\", \"dos_status\") VALUES (1, 'known-b', 'enable');",
                "INSERT INTO \"allow-method-policy\" (\"device_id\", \"allow_method_policy_name\", \"allow_method\") VALUES (1, 'allow-b', 'GET POST');",
                "INSERT INTO ip_list_policy (\"device_id\", \"name\", \"seq\", \"type\", \"ip\") VALUES (1, 'ip-list-b', 1, 'trust', '192.0.2.10');",
                "INSERT INTO geo_ip (\"device_id\", \"name\", \"action\", \"country_name\") VALUES (1, 'geo-b', 'block', 'Exampleland');",
                "INSERT INTO \"xml-validation-policy\" (\"device_id\", \"xml_validation_name\", \"enable_signature_detection\") VALUES (1, 'xml-b', 'enable');",
                "INSERT INTO \"json-validation-policy\" (\"device_id\", \"json_validation_name\", \"enable_attack_signatures\") VALUES (1, 'json-b', 'disable');",
                "INSERT INTO \"server_policy\" (\"device_id\", \"server_policy_name\", \"server_pool_name\", \"monitor_mode\", \"web_protection_profile_name\") VALUES (1, 'policy-a', 'pool-a', 'enable', NULL);",
                "INSERT INTO \"server_policy\" (\"device_id\", \"server_policy_name\", \"server_pool_name\", \"monitor_mode\", \"web_protection_profile_name\") VALUES (1, 'policy-b', 'pool-b', 'enable', 'profile-b');",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    states = _load_server_policy_state_from_backups(days=7)

    assert states[("1", "policy-a")][0][1:3] == ("Not Protected", "OLD-A")
    assert states[("1", "policy-b")][0][1:3] == ("Monitoring", "OLD-B")
    assert states[("1", "policy-a")][0][3] == {
        "signature": "disabled",
        "http_rfc": "disabled",
        "http2_rfc_control": "disabled",
    }
    assert states[("1", "policy-b")][0][3]["signature"] == "enabled"
    assert states[("1", "policy-b")][0][4] == {
        "syntax_based_detection": "enabled",
        "custom_access_rules": "enabled",
    }
    assert states[("1", "policy-b")][0][5] == {
        "http_flood_prevention": "enabled",
        "http_access_limit": "enabled",
        "tcp_flood_prevention": "enabled",
    }
    assert states[("1", "policy-b")][0][6] == {
        "biometric_based_detection": "enabled",
        "threshold_based_detection": "enabled",
        "known_bot": "enabled",
    }
    assert states[("1", "policy-b")][0][7] == {"allow_method": "enabled"}
    assert states[("1", "policy-b")][0][8] == {
        "ip_list": "enabled",
        "geo_location": "enabled",
    }
    assert states[("1", "policy-b")][0][9] == {
        "xml_validation_policy": "enabled",
        "json_validation_policy": "disabled",
    }


def test_build_recent_policy_changes_adds_certificate_change():
    from datetime import datetime, timezone

    latest_change = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Blocking",
        "NEW-SERIAL",
        [(latest_change, "Blocking", "OLD-SERIAL")],
        current_time=latest_change,
    )

    assert changes == [
        {
            "id": f"certificate-serial-{int(latest_change.timestamp())}",
            "title": "Certificate changed or renewed",
            "summary": "The client certificate serial number changed to NEW-SERIAL.",
            "time": "05/05",
            "type": "Certificate",
        }
    ]


def test_build_recent_policy_changes_can_list_status_and_certificate_changes():
    from datetime import datetime, timezone

    latest_change = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Monitoring",
        "NEW-SERIAL",
        [(latest_change, "Blocking", "OLD-SERIAL")],
        current_time=latest_change,
    )

    assert [change["title"] for change in changes] == [
        "Policy Status changed to Monitoring",
        "Certificate changed or renewed",
    ]


def test_build_recent_policy_changes_lists_simultaneous_status_and_new_certificate_changes():
    from datetime import datetime, timezone

    latest_change = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Monitoring",
        "NEW-SERIAL",
        [(latest_change, "Blocking", None)],
        current_time=latest_change,
    )

    assert changes == [
        {
            "id": f"policy-status-{int(latest_change.timestamp())}",
            "title": "Policy Status changed to Monitoring",
            "summary": "The policy is now running in Monitoring mode.",
            "time": "05/05",
            "type": "Server Policy",
        },
        {
            "id": f"certificate-serial-{int(latest_change.timestamp())}",
            "title": "Certificate changed or renewed",
            "summary": "The client certificate serial number changed to NEW-SERIAL.",
            "time": "05/05",
            "type": "Certificate",
        },
    ]


def test_build_recent_policy_changes_keeps_historical_certificate_changes():
    from datetime import datetime, timezone

    first_backup = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    renewed_backup = datetime(2026, 5, 3, 12, 0, tzinfo=timezone.utc)
    latest_backup = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)
    current_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Blocking",
        "SERIAL-B",
        [
            (first_backup, "Blocking", "SERIAL-A"),
            (renewed_backup, "Blocking", "SERIAL-B"),
            (latest_backup, "Blocking", "SERIAL-B"),
        ],
        current_time=current_time,
    )

    assert changes == [
        {
            "id": f"certificate-serial-{int(renewed_backup.timestamp())}",
            "title": "Certificate changed or renewed",
            "summary": "The client certificate serial number changed to SERIAL-B.",
            "time": "03/05",
            "type": "Certificate",
        }
    ]


def test_build_recent_policy_changes_adds_standard_protection_feature_change():
    from datetime import datetime, timezone

    backup_time = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)
    current_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Blocking",
        "SERIAL-A",
        [(backup_time, "Blocking", "SERIAL-A", {"signature": "enabled"})],
        {"signature": "disabled"},
        current_time=current_time,
    )

    assert changes == [
        {
            "id": f"standard-protection-signature-{int(current_time.timestamp())}",
            "title": "Signature control disabled",
            "summary": "Standard Protection: Signature changed to Disabled.",
            "time": "06/05",
            "type": "Standard Protection",
        }
    ]


def test_build_recent_policy_changes_keeps_historical_standard_protection_changes():
    from datetime import datetime, timezone

    first_backup = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    disabled_backup = datetime(2026, 5, 3, 12, 0, tzinfo=timezone.utc)
    latest_backup = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)
    current_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Blocking",
        "SERIAL-A",
        [
            (first_backup, "Blocking", "SERIAL-A", {"signature": "enabled"}),
            (disabled_backup, "Blocking", "SERIAL-A", {"signature": "disabled"}),
            (latest_backup, "Blocking", "SERIAL-A", {"signature": "disabled"}),
        ],
        {"signature": "disabled"},
        current_time=current_time,
    )

    assert changes == [
        {
            "id": f"standard-protection-signature-{int(disabled_backup.timestamp())}",
            "title": "Signature control disabled",
            "summary": "Standard Protection: Signature changed to Disabled.",
            "time": "03/05",
            "type": "Standard Protection",
        }
    ]


def test_build_recent_policy_changes_adds_advanced_protection_feature_change():
    from datetime import datetime, timezone

    backup_time = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)
    current_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Blocking",
        "SERIAL-A",
        [(backup_time, "Blocking", "SERIAL-A", {}, {"syntax_based_detection": "enabled"})],
        {},
        {"syntax_based_detection": "disabled"},
        current_time=current_time,
    )

    assert changes == [
        {
            "id": f"advanced-protection-syntax_based_detection-{int(current_time.timestamp())}",
            "title": "Syntax Based Detection control disabled",
            "summary": "Advance Protection: Syntax Based Detection changed to Disabled.",
            "time": "06/05",
            "type": "Advance Protection",
        }
    ]


def test_build_recent_policy_changes_keeps_historical_advanced_protection_changes():
    from datetime import datetime, timezone

    first_backup = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    enabled_backup = datetime(2026, 5, 3, 12, 0, tzinfo=timezone.utc)
    latest_backup = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)
    current_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Blocking",
        "SERIAL-A",
        [
            (first_backup, "Blocking", "SERIAL-A", {}, {"custom_access_rules": "unknown"}),
            (enabled_backup, "Blocking", "SERIAL-A", {}, {"custom_access_rules": "enabled"}),
            (latest_backup, "Blocking", "SERIAL-A", {}, {"custom_access_rules": "enabled"}),
        ],
        {},
        {"custom_access_rules": "enabled"},
        current_time=current_time,
    )

    assert changes == [
        {
            "id": f"advanced-protection-custom_access_rules-{int(enabled_backup.timestamp())}",
            "title": "Custom Access Rules control enabled",
            "summary": "Advance Protection: Custom Access Rules changed to Enabled.",
            "time": "03/05",
            "type": "Advance Protection",
        }
    ]


def test_build_recent_policy_changes_adds_application_dos_feature_change():
    from datetime import datetime, timezone

    backup_time = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)
    current_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Blocking",
        "SERIAL-A",
        [(backup_time, "Blocking", "SERIAL-A", {}, {}, {"http_flood_prevention": "enabled"})],
        {},
        {},
        {"http_flood_prevention": "unknown"},
        current_time=current_time,
    )

    assert changes == [
        {
            "id": f"application-dos-protection-http_flood_prevention-{int(current_time.timestamp())}",
            "title": "HTTP Flood Prevention control unknown",
            "summary": "Application Dos protection: HTTP Flood Prevention changed to Unknown.",
            "time": "06/05",
            "type": "Application Dos protection",
        }
    ]


def test_build_recent_policy_changes_keeps_historical_application_dos_changes():
    from datetime import datetime, timezone

    first_backup = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    enabled_backup = datetime(2026, 5, 3, 12, 0, tzinfo=timezone.utc)
    latest_backup = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)
    current_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Blocking",
        "SERIAL-A",
        [
            (first_backup, "Blocking", "SERIAL-A", {}, {}, {"tcp_flood_prevention": "unknown"}),
            (enabled_backup, "Blocking", "SERIAL-A", {}, {}, {"tcp_flood_prevention": "enabled"}),
            (latest_backup, "Blocking", "SERIAL-A", {}, {}, {"tcp_flood_prevention": "enabled"}),
        ],
        {},
        {},
        {"tcp_flood_prevention": "enabled"},
        current_time=current_time,
    )

    assert changes == [
        {
            "id": f"application-dos-protection-tcp_flood_prevention-{int(enabled_backup.timestamp())}",
            "title": "TCP Flood Prevention control enabled",
            "summary": "Application Dos protection: TCP Flood Prevention changed to Enabled.",
            "time": "03/05",
            "type": "Application Dos protection",
        }
    ]


def test_build_recent_policy_changes_adds_bot_mitigation_feature_change():
    from datetime import datetime, timezone

    backup_time = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)
    current_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Blocking",
        "SERIAL-A",
        [(backup_time, "Blocking", "SERIAL-A", {}, {}, {}, {"known_bot": "unknown"})],
        {},
        {},
        {},
        {"known_bot": "enabled"},
        current_time=current_time,
    )

    assert changes == [
        {
            "id": f"bot-mitigation-known_bot-{int(current_time.timestamp())}",
            "title": "Known-Bot control enabled",
            "summary": "Bot Mitigation: Known-Bot changed to Enabled.",
            "time": "06/05",
            "type": "Bot Mitigation",
        }
    ]


def test_build_recent_policy_changes_keeps_historical_bot_mitigation_changes():
    from datetime import datetime, timezone

    first_backup = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    enabled_backup = datetime(2026, 5, 3, 12, 0, tzinfo=timezone.utc)
    latest_backup = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)
    current_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Blocking",
        "SERIAL-A",
        [
            (first_backup, "Blocking", "SERIAL-A", {}, {}, {}, {"threshold_based_detection": "unknown"}),
            (enabled_backup, "Blocking", "SERIAL-A", {}, {}, {}, {"threshold_based_detection": "enabled"}),
            (latest_backup, "Blocking", "SERIAL-A", {}, {}, {}, {"threshold_based_detection": "enabled"}),
        ],
        {},
        {},
        {},
        {"threshold_based_detection": "enabled"},
        current_time=current_time,
    )

    assert changes == [
        {
            "id": f"bot-mitigation-threshold_based_detection-{int(enabled_backup.timestamp())}",
            "title": "Threshold Based Detection control enabled",
            "summary": "Bot Mitigation: Threshold Based Detection changed to Enabled.",
            "time": "03/05",
            "type": "Bot Mitigation",
        }
    ]


def test_build_recent_policy_changes_adds_access_feature_change():
    from datetime import datetime, timezone

    backup_time = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)
    current_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Blocking",
        "SERIAL-A",
        [(backup_time, "Blocking", "SERIAL-A", {}, {}, {}, {}, {"allow_method": "unknown"})],
        {},
        {},
        {},
        {},
        {"allow_method": "enabled"},
        current_time=current_time,
    )

    assert changes == [
        {
            "id": f"access-allow_method-{int(current_time.timestamp())}",
            "title": "Allow method control enabled",
            "summary": "Access: Allow method changed to Enabled.",
            "time": "06/05",
            "type": "Access",
        }
    ]


def test_build_recent_policy_changes_keeps_historical_access_changes():
    from datetime import datetime, timezone

    first_backup = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    enabled_backup = datetime(2026, 5, 3, 12, 0, tzinfo=timezone.utc)
    latest_backup = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)
    current_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Blocking",
        "SERIAL-A",
        [
            (first_backup, "Blocking", "SERIAL-A", {}, {}, {}, {}, {"allow_method": "unknown"}),
            (enabled_backup, "Blocking", "SERIAL-A", {}, {}, {}, {}, {"allow_method": "enabled"}),
            (latest_backup, "Blocking", "SERIAL-A", {}, {}, {}, {}, {"allow_method": "enabled"}),
        ],
        {},
        {},
        {},
        {},
        {"allow_method": "enabled"},
        current_time=current_time,
    )

    assert changes == [
        {
            "id": f"access-allow_method-{int(enabled_backup.timestamp())}",
            "title": "Allow method control enabled",
            "summary": "Access: Allow method changed to Enabled.",
            "time": "03/05",
            "type": "Access",
        }
    ]


def test_build_recent_policy_changes_adds_ip_protection_feature_change():
    from datetime import datetime, timezone

    backup_time = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)
    current_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Blocking",
        "SERIAL-A",
        [(backup_time, "Blocking", "SERIAL-A", {}, {}, {}, {}, {}, {"ip_list": "unknown"})],
        {},
        {},
        {},
        {},
        {},
        {"ip_list": "enabled"},
        current_time=current_time,
    )

    assert changes == [
        {
            "id": f"ip-protection-ip_list-{int(current_time.timestamp())}",
            "title": "IP List control enabled",
            "summary": "IP Protection: IP List changed to Enabled.",
            "time": "06/05",
            "type": "IP Protection",
        }
    ]


def test_build_recent_policy_changes_keeps_historical_ip_protection_changes():
    from datetime import datetime, timezone

    first_backup = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    enabled_backup = datetime(2026, 5, 3, 12, 0, tzinfo=timezone.utc)
    latest_backup = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)
    current_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Blocking",
        "SERIAL-A",
        [
            (first_backup, "Blocking", "SERIAL-A", {}, {}, {}, {}, {}, {"geo_location": "unknown"}),
            (enabled_backup, "Blocking", "SERIAL-A", {}, {}, {}, {}, {}, {"geo_location": "enabled"}),
            (latest_backup, "Blocking", "SERIAL-A", {}, {}, {}, {}, {}, {"geo_location": "enabled"}),
        ],
        {},
        {},
        {},
        {},
        {},
        {"geo_location": "enabled"},
        current_time=current_time,
    )

    assert changes == [
        {
            "id": f"ip-protection-geo_location-{int(enabled_backup.timestamp())}",
            "title": "Geo Location control enabled",
            "summary": "IP Protection: Geo Location changed to Enabled.",
            "time": "03/05",
            "type": "IP Protection",
        }
    ]


def test_build_recent_policy_changes_adds_api_security_feature_change():
    from datetime import datetime, timezone

    backup_time = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)
    current_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Blocking",
        "SERIAL-A",
        [(backup_time, "Blocking", "SERIAL-A", {}, {}, {}, {}, {}, {}, {"xml_validation_policy": "unknown"})],
        {},
        {},
        {},
        {},
        {},
        {},
        {"xml_validation_policy": "enabled"},
        current_time=current_time,
    )

    assert changes == [
        {
            "id": f"api-security-xml_validation_policy-{int(current_time.timestamp())}",
            "title": "XMLValidation Policy control enabled",
            "summary": "API Security: XMLValidation Policy changed to Enabled.",
            "time": "06/05",
            "type": "API Security",
        }
    ]


def test_build_recent_policy_changes_keeps_historical_api_security_changes():
    from datetime import datetime, timezone

    first_backup = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    disabled_backup = datetime(2026, 5, 3, 12, 0, tzinfo=timezone.utc)
    latest_backup = datetime(2026, 5, 5, 12, 0, tzinfo=timezone.utc)
    current_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

    changes = _build_recent_policy_changes(
        "Blocking",
        "SERIAL-A",
        [
            (first_backup, "Blocking", "SERIAL-A", {}, {}, {}, {}, {}, {}, {"json_validation_policy": "enabled"}),
            (disabled_backup, "Blocking", "SERIAL-A", {}, {}, {}, {}, {}, {}, {"json_validation_policy": "disabled"}),
            (latest_backup, "Blocking", "SERIAL-A", {}, {}, {}, {}, {}, {}, {"json_validation_policy": "disabled"}),
        ],
        {},
        {},
        {},
        {},
        {},
        {},
        {"json_validation_policy": "disabled"},
        current_time=current_time,
    )

    assert changes == [
        {
            "id": f"api-security-json_validation_policy-{int(disabled_backup.timestamp())}",
            "title": "JSON Validation Policy control disabled",
            "summary": "API Security: JSON Validation Policy changed to Disabled.",
            "time": "03/05",
            "type": "API Security",
        }
    ]


def test_build_policy_maturity_assessment_scores_standard_protection_with_http2_enabled():
    assessment = _build_policy_maturity_assessment(
        {"signature": "enabled", "http_rfc": "enabled", "http2_rfc_control": "enabled"},
        "enable",
        {},
        {},
        {},
        {},
        {},
        {},
    )

    standard = assessment["categories"][0]

    assert standard["title"] == "Standart Protection"
    assert standard["points"] == 30
    assert standard["max_points"] == 30
    assert standard["status"] == "Strong"
    assert standard["components"]["signature"]["points"] == 10
    assert standard["components"]["http_rfc"]["points"] == 10
    assert standard["components"]["http2_rfc_control"]["points"] == 10
    assert standard["components"]["http2_rfc_control"]["counted"] is True


def test_build_policy_maturity_assessment_scores_standard_protection_without_http2_full_points_for_two_controls():
    assessment = _build_policy_maturity_assessment(
        {"signature": "enabled", "http_rfc": "enabled", "http2_rfc_control": "disabled"},
        "disable",
        {},
        {},
        {},
        {},
        {},
        {},
    )

    standard = assessment["categories"][0]

    assert standard["points"] == 30
    assert standard["status"] == "Strong"
    assert standard["components"]["signature"]["points"] == 15
    assert standard["components"]["http_rfc"]["points"] == 15
    assert standard["components"]["http2_rfc_control"]["counted"] is False


def test_build_policy_maturity_assessment_scores_standard_protection_without_http2_partial_points():
    assessment = _build_policy_maturity_assessment(
        {"signature": "enabled", "http_rfc": "disabled", "http2_rfc_control": "disabled"},
        False,
        {},
        {},
        {},
        {},
        {},
        {},
    )

    standard = assessment["categories"][0]

    assert standard["points"] == 15
    assert standard["max_points"] == 30
    assert standard["status"] == "Needs improvement"
    assert standard["components"]["signature"]["points"] == 15
    assert standard["components"]["http_rfc"]["points"] == 0


def test_build_policy_maturity_assessment_scores_advance_protection_per_enabled_feature():
    assessment = _build_policy_maturity_assessment(
        {},
        False,
        {"syntax_based_detection": "enabled", "custom_access_rules": "enabled"},
        {},
        {},
        {},
        {},
        {},
    )

    advance = assessment["categories"][1]

    assert advance["title"] == "Advance Protection"
    assert advance["points"] == 20
    assert advance["max_points"] == 20
    assert advance["status"] == "Strong"
    assert advance["components"]["syntax_based_detection"]["points"] == 10
    assert advance["components"]["custom_access_rules"]["points"] == 10


def test_build_policy_maturity_assessment_scores_advance_protection_partial_points():
    assessment = _build_policy_maturity_assessment(
        {},
        False,
        {"syntax_based_detection": "enabled", "custom_access_rules": "unknown"},
        {},
        {},
        {},
        {},
        {},
    )

    advance = assessment["categories"][1]

    assert advance["points"] == 10
    assert advance["max_points"] == 20
    assert advance["status"] == "Needs improvement"
    assert advance["components"]["syntax_based_detection"]["points"] == 10
    assert advance["components"]["custom_access_rules"]["points"] == 0


def test_build_policy_maturity_assessment_scores_advance_protection_zero_when_no_features_enabled():
    assessment = _build_policy_maturity_assessment(
        {},
        False,
        {"syntax_based_detection": "disabled", "custom_access_rules": "unknown"},
        {},
        {},
        {},
        {},
        {},
    )

    advance = assessment["categories"][1]

    assert advance["points"] == 0
    assert advance["max_points"] == 20
    assert advance["status"] == "Needs improvement"
    assert advance["components"]["syntax_based_detection"]["points"] == 0
    assert advance["components"]["custom_access_rules"]["points"] == 0


def test_build_policy_maturity_assessment_scores_application_dos_per_enabled_feature():
    assessment = _build_policy_maturity_assessment(
        {},
        False,
        {},
        {
            "http_flood_prevention": "enabled",
            "http_access_limit": "enabled",
            "tcp_flood_prevention": "enabled",
        },
        {},
        {},
        {},
        {},
    )

    application_dos = assessment["categories"][2]

    assert application_dos["title"] == "Application DoS"
    assert application_dos["points"] == 15
    assert application_dos["max_points"] == 15
    assert application_dos["status"] == "Strong"
    assert application_dos["components"]["http_flood_prevention"]["points"] == 5
    assert application_dos["components"]["http_access_limit"]["points"] == 5
    assert application_dos["components"]["tcp_flood_prevention"]["points"] == 5


def test_build_policy_maturity_assessment_scores_application_dos_partial_points():
    assessment = _build_policy_maturity_assessment(
        {},
        False,
        {},
        {
            "http_flood_prevention": "enabled",
            "http_access_limit": "unknown",
            "tcp_flood_prevention": "enabled",
        },
        {},
        {},
        {},
        {},
    )

    application_dos = assessment["categories"][2]

    assert application_dos["points"] == 10
    assert application_dos["max_points"] == 15
    assert application_dos["status"] == "Needs improvement"
    assert application_dos["components"]["http_flood_prevention"]["points"] == 5
    assert application_dos["components"]["http_access_limit"]["points"] == 0
    assert application_dos["components"]["tcp_flood_prevention"]["points"] == 5


def test_build_policy_maturity_assessment_scores_application_dos_zero_when_no_features_enabled():
    assessment = _build_policy_maturity_assessment(
        {},
        False,
        {},
        {
            "http_flood_prevention": "unknown",
            "http_access_limit": "unknown",
            "tcp_flood_prevention": "unknown",
        },
        {},
        {},
        {},
        {},
    )

    application_dos = assessment["categories"][2]

    assert application_dos["points"] == 0
    assert application_dos["max_points"] == 15
    assert application_dos["status"] == "Needs improvement"
    assert application_dos["components"]["http_flood_prevention"]["points"] == 0
    assert application_dos["components"]["http_access_limit"]["points"] == 0
    assert application_dos["components"]["tcp_flood_prevention"]["points"] == 0


def test_build_policy_maturity_assessment_scores_access_when_allow_method_enabled():
    assessment = _build_policy_maturity_assessment(
        {},
        False,
        {},
        {},
        {},
        {"allow_method": "enabled"},
        {},
        {},
    )

    access = assessment["categories"][4]

    assert access["title"] == "Access"
    assert access["points"] == 5
    assert access["max_points"] == 5
    assert access["status"] == "Strong"
    assert access["components"]["allow_method"]["points"] == 5


def test_build_policy_maturity_assessment_scores_access_zero_when_allow_method_disabled():
    assessment = _build_policy_maturity_assessment(
        {},
        False,
        {},
        {},
        {},
        {"allow_method": "unknown"},
        {},
        {},
    )

    access = assessment["categories"][4]

    assert access["points"] == 0
    assert access["max_points"] == 5
    assert access["status"] == "Needs improvement"
    assert access["components"]["allow_method"]["points"] == 0


def test_build_policy_maturity_assessment_scores_ip_protection_per_enabled_feature():
    assessment = _build_policy_maturity_assessment(
        {},
        False,
        {},
        {},
        {},
        {},
        {"ip_list": "enabled", "geo_location": "enabled"},
        {},
    )

    ip_protection = assessment["categories"][5]

    assert ip_protection["title"] == "IP Protection"
    assert ip_protection["points"] == 10
    assert ip_protection["max_points"] == 10
    assert ip_protection["status"] == "Strong"
    assert ip_protection["components"]["ip_list"]["points"] == 5
    assert ip_protection["components"]["geo_location"]["points"] == 5


def test_build_policy_maturity_assessment_scores_ip_protection_partial_points():
    assessment = _build_policy_maturity_assessment(
        {},
        False,
        {},
        {},
        {},
        {},
        {"ip_list": "enabled", "geo_location": "unknown"},
        {},
    )

    ip_protection = assessment["categories"][5]

    assert ip_protection["points"] == 5
    assert ip_protection["max_points"] == 10
    assert ip_protection["status"] == "Needs improvement"
    assert ip_protection["components"]["ip_list"]["points"] == 5
    assert ip_protection["components"]["geo_location"]["points"] == 0


def test_build_policy_maturity_assessment_scores_ip_protection_zero_when_no_features_enabled():
    assessment = _build_policy_maturity_assessment(
        {},
        False,
        {},
        {},
        {},
        {},
        {"ip_list": "unknown", "geo_location": "unknown"},
        {},
    )

    ip_protection = assessment["categories"][5]

    assert ip_protection["points"] == 0
    assert ip_protection["max_points"] == 10
    assert ip_protection["status"] == "Needs improvement"
    assert ip_protection["components"]["ip_list"]["points"] == 0
    assert ip_protection["components"]["geo_location"]["points"] == 0
