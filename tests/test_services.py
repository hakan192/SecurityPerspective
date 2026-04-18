from app.services import _extract_ip_intelligence_rows, _extract_policy_rows, _iter_relevant_objects, maturity_level_from_score


def test_maturity_level_thresholds():
    assert maturity_level_from_score(95) == "Optimized"
    assert maturity_level_from_score(80) == "Managed"
    assert maturity_level_from_score(60) == "Defined"
    assert maturity_level_from_score(30) == "Initial"
    assert maturity_level_from_score(10) == "Ad Hoc"


def test_iter_relevant_objects_results_list():
    payload = {"results": [{"name": "a"}, {"name": "b"}]}
    rows = list(_iter_relevant_objects(payload))
    assert len(rows) == 2
    assert rows[0]["name"] == "a"


def test_iter_relevant_objects_single_object():
    payload = {"name": "single"}
    rows = list(_iter_relevant_objects(payload))
    assert len(rows) == 1
    assert rows[0]["name"] == "single"


def test_extract_ip_intelligence_rows():
    payload = {"results": [{"name": "threat-feed", "category": "botnet", "status": "enable", "action": "block"}]}
    rows = _extract_ip_intelligence_rows(payload)

    assert len(rows) == 1
    assert rows[0]["ip_intelligence_name"] == "threat-feed"
    assert rows[0]["category"] == "botnet"
    assert rows[0]["status"] == "enable"
    assert rows[0]["action"] == "block"
    assert rows[0]["raw_json"] == payload["results"][0]


def test_extract_policy_rows_monitor_mode():
    payload = {
        "results": [
            {
                "name": "sp-1",
                "server-pool": "pool-1",
                "monitor-mode": "enable",
            }
        ]
    }

    rows = _extract_policy_rows(payload)
    assert len(rows) == 1
    assert rows[0]["server_policy_name"] == "sp-1"
    assert rows[0]["monitor_mode"] == "enable"
