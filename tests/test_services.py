from app.services import _extract_certificate_local_rows, _extract_policy_rows, _extract_server_pool_row


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


def test_extract_server_pool_row_parses_sni_client_certificate_and_sni_certificate():
    payload = {
        "results": [{"name": "pool-a", "sni": "example.com", "client-certificate": "client-cert-a", "sni-certificate": "sni-cert-a"}]
    }

    row = _extract_server_pool_row(payload, "pool-a")

    assert row["sni"] == "example.com"
    assert row["client_certificate"] == "client-cert-a"
    assert row["sni_certificate_name"] == "sni-cert-a"


def test_extract_certificate_local_rows_parses_all_certificates():
    payload = {
        "results": [
            {
                "name": "cert-a",
                "issuer": "CN=IssuerA",
                "serialNumber": "1234",
                "subject": "CN=SubjectA",
                "validTo": "2030-01-01T00:00:00Z",
            },
            {
                "name": "cert-b",
                "issuer": "CN=IssuerB",
                "serial-number": "5678",
                "subject": "CN=SubjectB",
                "valid-to": "2031-01-01T00:00:00Z",
            },
        ]
    }

    rows = _extract_certificate_local_rows(payload)

    assert len(rows) == 2
    assert rows[0]["certificate_name"] == "cert-a"
    assert rows[0]["serial_number"] == "1234"
    assert rows[1]["certificate_name"] == "cert-b"
    assert rows[1]["serial_number"] == "5678"
