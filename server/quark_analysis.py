import json
from quark.report import Report

RULE_PATH = "./quark-rules/rules"


def compute_weighted_sum(data: dict) -> float:
    crimes = data.get("crimes")

    weighted_sum = 0.0
    for crime in crimes:
        value = crime.get("weight", crime.get("score", 0))
        weighted_sum += float(value)

    return weighted_sum


def analyze_apk_with_quark(apk_path: str, timeout_seconds: int = 900) -> dict:
    report = Report()
    report.analysis(apk_path, RULE_PATH)

    raw = report.get_report("json")
    data = json.loads(raw) if isinstance(raw, str) else raw

    weighted_sum = compute_weighted_sum(data)
    threat_level = data.get("threat_level", "Unknown")

    malicious = (
        threat_level in {"High Risk", "Moderate Risk"}
        or weighted_sum >= 4
    )

    return {
        "threat_level": threat_level,
        "weighted_sum": round(weighted_sum, 2),
        "malicious": malicious,
    }