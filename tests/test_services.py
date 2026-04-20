from app.services import _extract_policy_rows, _extract_server_pool_row


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
