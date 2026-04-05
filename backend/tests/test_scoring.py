from types import SimpleNamespace

from app.modules.scoring.service import _ratio, level_from_thresholds


def test_ratio():
    expected = {"checks": [{"key": "a", "op": "eq", "value": True}, {"key": "n", "op": "gte", "value": 2}]}
    actual = {"a": True, "n": 3}
    assert _ratio(expected, actual) == 1.0


def test_level_from_thresholds():
    thresholds = [
        SimpleNamespace(level="ad-hoc", min_ratio=0.0, order_index=1),
        SimpleNamespace(level="defined", min_ratio=0.5, order_index=3),
        SimpleNamespace(level="optimized", min_ratio=0.9, order_index=5),
    ]
    assert level_from_thresholds(0.95, thresholds) == "optimized"
    assert level_from_thresholds(0.6, thresholds) == "defined"
