from collections import defaultdict

from app.models.entities import BaselineControl, ParsedConfigItem


def _maturity_level(score: float) -> str:
    if score >= 90:
        return 'Optimized'
    if score >= 75:
        return 'Managed'
    if score >= 60:
        return 'Defined'
    if score >= 40:
        return 'Developing'
    return 'Initial'


def evaluate_maturity(baseline_controls: list[BaselineControl], parsed_items: list[ParsedConfigItem]) -> dict:
    controls_index = {control.control_key: control for control in baseline_controls}
    parsed_by_name = {item.object_name.lower(): item for item in parsed_items}

    per_control_scores = {}
    category_totals = defaultdict(float)
    category_possible = defaultdict(float)

    for control_key, control in controls_index.items():
        found = control_key.lower() in parsed_by_name
        score = 100.0 if found else 0.0
        weighted_score = score * control.weight

        per_control_scores[control_key] = {
            'score': score,
            'weight': control.weight,
            'category': control.category,
            'found': found,
        }

        category_totals[control.category] += weighted_score
        category_possible[control.category] += 100.0 * control.weight

    category_scores = {
        category: (category_totals[category] / category_possible[category]) if category_possible[category] else 0.0
        for category in category_possible
    }
    overall_score = sum(category_scores.values()) / max(len(category_scores), 1)

    return {
        'overall_score': round(overall_score, 2),
        'maturity_level': _maturity_level(overall_score),
        'per_control_scores': per_control_scores,
        'category_scores': category_scores,
    }
