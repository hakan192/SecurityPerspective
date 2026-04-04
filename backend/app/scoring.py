import json

from .config import baseline_path


def load_baseline() -> dict:
    with open(baseline_path(), "r", encoding="utf-8") as fp:
        return json.load(fp)


def evaluate(parsed: dict[str, bool], baseline: dict) -> dict:
    total_weight = 0
    achieved_weight = 0
    per_control = []
    categories: dict[str, dict[str, int]] = {}

    for control in baseline["controls"]:
        cid = control["id"]
        weight = int(control.get("weight", 1))
        category = control["category"]
        expected = bool(control.get("expected", True))
        actual = bool(parsed.get(cid, False))
        passed = expected == actual
        score = 100 if passed else 0

        total_weight += weight
        if passed:
            achieved_weight += weight

        categories.setdefault(category, {"achieved": 0, "total": 0})
        categories[category]["total"] += weight
        if passed:
            categories[category]["achieved"] += weight

        per_control.append(
            {
                "control_id": cid,
                "category": category,
                "weight": weight,
                "expected": expected,
                "actual": actual,
                "status": "compliant" if passed else "gap",
                "score": score,
            }
        )

    overall = round((achieved_weight / total_weight) * 100, 2) if total_weight else 0.0
    category_scores = {
        k: round((v["achieved"] / v["total"]) * 100, 2) if v["total"] else 0.0
        for k, v in categories.items()
    }

    maturity = "Initial"
    for level in sorted(baseline["maturity_levels"], key=lambda x: x["min_score"]):
        if overall >= level["min_score"]:
            maturity = level["name"]

    return {
        "per_control": per_control,
        "category_scores": category_scores,
        "overall_score": overall,
        "maturity_level": maturity,
        "improvements": [c for c in per_control if c["status"] == "gap"],
    }
