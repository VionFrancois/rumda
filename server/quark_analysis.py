import json
from quark.report import Report

def analyze_apk_with_quark(apk_path: str) -> dict:
    rule_path = "./quark-rules/rules"

    report = Report()
    report.analysis(apk_path, rule_path)

    raw = report.get_report("json")
    data = json.loads(raw) if isinstance(raw, str) else raw

    print(data)

    total_score = data.get("total_score", 0)
    threat_level = data.get("threat_level", "Unknown")

    malicious = (
        threat_level in {"High Risk", "Moderate Risk"}
        or total_score >= 4
    )

    return {
        "threat_level": threat_level,
        "total_score": total_score,
        "malicious": malicious,
    }