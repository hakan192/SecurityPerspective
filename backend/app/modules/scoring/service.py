from collections import defaultdict

from app.models import Assessment, AssessmentControl, BaselineControl, MaturityThreshold, ParsedRecord


def _ratio(expected: dict, actual: dict) -> float:
    checks = expected.get("checks", [])
    if not checks:
        return 0.0
    ok = 0
    for c in checks:
        val = actual.get(c.get("key"))
        if c.get("op") == "eq" and val == c.get("value"):
            ok += 1
        if c.get("op") == "gte" and isinstance(val, (int, float)) and val >= c.get("value"):
            ok += 1
    return ok / len(checks)


def level_from_thresholds(r: float, thresholds: list[MaturityThreshold]) -> str:
    ordered = sorted(thresholds, key=lambda t: t.order_index, reverse=True)
    for t in ordered:
        if r >= t.min_ratio:
            return t.level
    return "ad-hoc"


def score(
    snapshot_id: int,
    baseline_controls: list[BaselineControl],
    parsed_records: list[ParsedRecord],
    thresholds: list[MaturityThreshold],
    baseline_version: str,
    scoring_version: str,
):
    parsed_by_code = {p.control_code: p for p in parsed_records}
    category = defaultdict(lambda: {"score": 0.0, "max": 0.0})
    controls: list[AssessmentControl] = []
    weighted = 0.0
    max_weighted = 0.0

    for b in baseline_controls:
        record = parsed_by_code.get(b.control_code)
        ratio = _ratio(b.expected, record.normalized_data if record else {})
        sc = ratio * b.max_score
        category[b.category]["score"] += sc
        category[b.category]["max"] += b.max_score
        weighted += sc * b.weight
        max_weighted += b.max_score * b.weight
        if record:
            controls.append(
                AssessmentControl(
                    parsed_record_id=record.id,
                    control_code=b.control_code,
                    category=b.category,
                    score=sc,
                    max_score=b.max_score,
                    maturity_level=level_from_thresholds(ratio, thresholds),
                    recommendation=b.recommendation,
                    evidence=record.normalized_data,
                )
            )

    ratio = (weighted / max_weighted) if max_weighted else 0.0
    assessment = Assessment(
        snapshot_id=snapshot_id,
        overall_score=round(ratio * 100, 2),
        maturity_level=level_from_thresholds(ratio, thresholds),
        baseline_version=baseline_version,
        scoring_version=scoring_version,
        summary={"categories": {k: {"score": v["score"], "max": v["max"]} for k, v in category.items()}},
    )
    return assessment, controls
