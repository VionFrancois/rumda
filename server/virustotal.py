import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

API_URL = "https://www.virustotal.com/api/v3/files"
API_KEY_PATH = "./virustotal-api-key"

with API_KEY_PATH.open() as f:
    API_KEY = f.read().strip()


def check_hash(file_hash: str) -> dict:
    request = Request(
        f"{API_URL}/{file_hash}",
        headers={"x-apikey": API_KEY},
        method="GET",
    )

    try:
        with urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))["data"]["attributes"]
    except HTTPError as exc:
        if exc.code == 404:
            return {
                "found": False,
                "hash": file_hash,
                "message": "Hash unknown on VirusTotal.",
            }
        raise RuntimeError(f"VirusTotal returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError(f"VirusTotal request failed: {exc.reason}") from exc

    stats = payload["last_analysis_stats"]
    malicious = stats["malicious"] + stats["suspicious"]
    total = sum(stats.values())

    return {
        "found": True,
        "hash": file_hash,
        "detections": malicious,
        "total_engines": total,
        "stats": stats,
        "meaningful_name": payload.get("meaningful_name"),
        "last_analysis_date": payload.get("last_analysis_date"),
        "report_url": f"https://www.virustotal.com/gui/file/{file_hash}",
    }