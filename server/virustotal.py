import json
import time
from pathlib import Path

import requests

API_BASE_URL = "https://www.virustotal.com/api/v3"
FILES_API_URL = f"{API_BASE_URL}/files"
ANALYSES_API_URL = f"{API_BASE_URL}/analyses"
API_KEY_PATH = "virustotal-api-key"
VT_UPLOAD_TIMEOUT_SECONDS: int | None = None

with open(API_KEY_PATH) as f:
    API_KEY = f.read().strip()


def api_headers() -> dict[str, str]:
    return {"x-apikey": API_KEY}


def check_hash(file_hash: str) -> dict:
    try:
        response = requests.get(
            f"{FILES_API_URL}/{file_hash}",
            headers=api_headers(),
            timeout=20,
        )

        if response.status_code == 404:
            return {
                "found": False,
                "hash": file_hash,
                "message": "Hash unknown on VirusTotal.",
            }

        response.raise_for_status()
        payload = response.json()["data"]["attributes"]
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else "unknown"
        raise RuntimeError(f"VirusTotal returned HTTP {status_code}") from exc
    except requests.RequestException as exc:
        raise RuntimeError(f"VirusTotal request failed: {exc}") from exc

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


def get_upload_url() -> str:
    try:
        response = requests.get(
            f"{FILES_API_URL}/upload_url",
            headers=api_headers(),
            timeout=20,
        )
        response.raise_for_status()
        return response.json()["data"]
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else "unknown"
        raise RuntimeError(f"VirusTotal upload URL request failed with HTTP {status_code}") from exc
    except requests.RequestException as exc:
        raise RuntimeError(f"VirusTotal upload URL request failed: {exc}") from exc


def upload_file_for_analysis(
    file_path: str,
    upload_timeout_seconds: int | None = VT_UPLOAD_TIMEOUT_SECONDS,
) -> str:
    upload_url = get_upload_url()
    filename = Path(file_path).name

    try:
        with open(file_path, "rb") as file_obj:
            response = requests.post(
                upload_url,
                headers=api_headers(),
                files={"file": (filename, file_obj)},
                timeout=None if upload_timeout_seconds is None else (20, upload_timeout_seconds),
            )
        response.raise_for_status()
        payload = response.json()
        return payload["data"]["id"]
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else "unknown"
        raise RuntimeError(f"VirusTotal file upload failed with HTTP {status_code}") from exc
    except requests.RequestException as exc:
        raise RuntimeError(f"VirusTotal file upload failed: {exc}") from exc
    except (KeyError, json.JSONDecodeError) as exc:
        raise RuntimeError("VirusTotal file upload returned an unexpected response") from exc


def wait_for_analysis_result(
    analysis_id: str,
    file_hash: str,
    timeout_seconds: int = 420,
    poll_interval_seconds: int = 10,
) -> dict:
    deadline = time.monotonic() + timeout_seconds
    analysis_completed = False

    while time.monotonic() < deadline:
        try:
            response = requests.get(
                f"{ANALYSES_API_URL}/{analysis_id}",
                headers=api_headers(),
                timeout=20,
            )
            response.raise_for_status()
            attributes = response.json()["data"]["attributes"]
            if attributes.get("status") == "completed":
                analysis_completed = True
                hash_report = check_hash(file_hash)
                if hash_report.get("found", False):
                    return hash_report
        except requests.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else "unknown"
            raise RuntimeError(f"VirusTotal analysis polling failed with HTTP {status_code}") from exc
        except requests.RequestException as exc:
            raise RuntimeError(f"VirusTotal analysis polling failed: {exc}") from exc
        except (KeyError, json.JSONDecodeError) as exc:
            raise RuntimeError("VirusTotal analysis polling returned an unexpected response") from exc

        time.sleep(poll_interval_seconds)

    if analysis_completed:
        raise RuntimeError(
            f"VirusTotal analysis completed but file report is not available yet within {timeout_seconds} seconds "
            f"(analysis_id={analysis_id})"
        )

    raise RuntimeError(
        f"VirusTotal analysis did not complete within {timeout_seconds} seconds (analysis_id={analysis_id})"
    )


def upload_and_analyze_file(
    file_path: str,
    file_hash: str,
    upload_timeout_seconds: int | None = VT_UPLOAD_TIMEOUT_SECONDS,
    timeout_seconds: int = 420,
    poll_interval_seconds: int = 10,
) -> dict:
    analysis_id = upload_file_for_analysis(
        file_path,
        upload_timeout_seconds=upload_timeout_seconds,
    )
    return wait_for_analysis_result(
        analysis_id,
        file_hash,
        timeout_seconds=timeout_seconds,
        poll_interval_seconds=poll_interval_seconds,
    )