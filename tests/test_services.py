from app.services import _extract_certificate_local_row, _extract_policy_rows, _extract_server_pool_row


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
