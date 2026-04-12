import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

API_URL = "https://api.abuseipdb.com/api/v2/check"
API_KEY_PATH = "abuseipdb-api-key"

with open(API_KEY_PATH) as f:
    API_KEY = f.read().strip()


def check_ip(ip: str, max_age_days: int = 90) -> dict:
    query = urlencode({"ipAddress": ip, "maxAgeInDays": max_age_days})
    request = Request(
        f"{API_URL}?{query}",
        headers={
            "Key": API_KEY,
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        with urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        if exc.code == 404:
            raise RuntimeError(f"IP {ip} not found on AbuseIPDB") from exc
        raise RuntimeError(f"AbuseIPDB returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError(f"AbuseIPDB request failed: {exc.reason}") from exc

    data = payload.get("data", {})
    abuse_score = int(data.get("abuseConfidenceScore", 0) or 0)

    return {
        "ip": data.get("ipAddress", ip),
        "abuse_confidence_score": abuse_score,
    }
