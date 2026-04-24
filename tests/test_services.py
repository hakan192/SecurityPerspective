from app.services import (
    _build_device_base_url,
    _build_http_rfc_control_status,
    _build_http2_rfc_control_status,
    _extract_certificate_local_row,
    _extract_certificate_sni_member_rows,
    _extract_policy_rows,
    _extract_server_pool_row,
)


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
