from app.services import _extract_ip_intelligence_row, _iter_relevant_objects, maturity_level_from_score


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


def test_extract_ip_intelligence_row():
    payload = {"results": [{"category": "botnet", "status": "enable", "action": "block"}]}
    row = _extract_ip_intelligence_row(payload, "threat-feed")

    assert row["ip_intelligence_name"] == "threat-feed"
    assert row["category"] == "botnet"
    assert row["status"] == "enable"
    assert row["action"] == "block"
    assert row["raw_json"] == payload
