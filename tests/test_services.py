from app.services import _iter_relevant_objects, maturity_level_from_score


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
