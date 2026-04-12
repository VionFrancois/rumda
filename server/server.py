import hashlib
import ipaddress
from pathlib import Path
from tempfile import NamedTemporaryFile

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, field_validator

from abuseipdb import check_ip
from cache_store import *
from quark_analysis import analyze_apk_with_quark
from virustotal import check_hash

app = FastAPI(title="RuMDA API")
CACHE_TTL_SECONDS = 60 * 60 * 24 * 14 # 14 days
IP_CACHE_TTL_SECONDS = 60 * 60 * 12 # 12 hours
init_cache_db()


class HashRequest(BaseModel):
    hash: str


class IpsRequest(BaseModel):
    ips: list[str]

    @field_validator("ips")
    @classmethod
    def validate_ips(cls, ips: list[str]) -> list[str]:
        if not ips:
            raise ValueError("'ips' must contain at least one IP address")

        for ip in ips:
            try:
                ipaddress.ip_address(ip)
            except ValueError as exc:
                raise ValueError(f"Invalid IP address: {ip}") from exc

        return ips


@app.post("/analysis/apk/hash")
def analyze_apk_hash(payload: HashRequest) -> dict:
    cached = get_cached_verdict(payload.hash)
    if cached is not None:
        return cached

    try:
        verdict = format_hash_analysis(payload.hash, check_hash(payload.hash))
        if verdict.get("found", False):
            set_cached_verdict(payload.hash, verdict, CACHE_TTL_SECONDS)
        else:
            print(f"/analysis/apk/hash skip cache: hash={payload.hash} not found on VirusTotal")
        return verdict
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/analysis/ips")
def analyze_ips(payload: IpsRequest) -> dict:
    ips = payload.ips
    results = []

    try:
        for ip in ips:
            abuse_score = get_cached_ip_score(ip)
            if abuse_score is None:
                check_result = check_ip(ip)
                abuse_score = int(check_result.get("abuse_confidence_score", 0) or 0)
                set_cached_ip_score(ip, abuse_score, IP_CACHE_TTL_SECONDS)

            malicious, degree = classify_ip_score(abuse_score)
            results.append(
                {
                    "ip": ip,
                    "malicious": malicious,
                    "degree": degree,
                }
            )

        return {"results": results}
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/analysis/apk/file")
async def analyze_apk_file(file: UploadFile = File(...)) -> dict:
    # TODO : Ensure the uploaded file is a valid APK
    try:
        content = await file.read()
        file_hash = hashlib.sha256(content).hexdigest()
        cached = get_cached_verdict(file_hash)
        if cached is not None:
            return cached

        with NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
            tmp_path = Path(tmp.name)
            tmp.write(content)
            result = analyze_apk_with_quark(str(tmp_path))

        verdict = format_file_analysis(file_hash, result)
        set_cached_verdict(file_hash, verdict, CACHE_TTL_SECONDS)
        return verdict
    
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"APK analysis failed: {exc}") from exc
    finally:
        await file.close()
        if "tmp_path" in locals() and tmp_path.exists():
            tmp_path.unlink()


def format_hash_analysis(file_hash: str, result: dict) -> dict:
    found = bool(result.get("found", False))
    detections = int(result.get("detections", 0) or 0)

    malicious = False
    if found:
        malicious = detections > 0

    if not found:
        degree = "unknown"
    elif detections >= 10:
        degree = "high"
    elif detections >= 3:
        degree = "medium"
    elif detections >= 1:
        degree = "low"
    else:
        degree = "none"

    return {
        "found": found,
        "analysis_type": "hash",
        "malicious": malicious,
        "degree": degree,
        "details": {
            "hash": result.get("hash", file_hash),
            "detections": detections,
            "total_engines": result.get("total_engines"),
            "meaningful_name": result.get("meaningful_name"),
            "last_analysis_date": result.get("last_analysis_date"),
            "report_url": result.get("report_url"),
        },
    }


def classify_ip_score(abuse_score: int) -> tuple[bool, str]:
    if abuse_score > 75:
        return True, "high"
    if abuse_score > 20:
        return True, "low"
    return False, "none"


def format_file_analysis(file_hash: str, result: dict) -> dict:
    threat_level = result.get("threat_level", "Unknown")
    weighted_sum = float(result.get("weighted_sum", 0) or 0)

    # TODO : Define better thresholds ?
    malicious = weighted_sum >= 4

    if weighted_sum >= 8:
        degree = "high"
    elif weighted_sum >= 4:
        degree = "medium"
    elif weighted_sum > 0:
        degree = "low"
    else:
        degree = "none"

    return {
        "found": True,
        "analysis_type": "file",
        "malicious": malicious,
        "degree": degree,
        "details": {
            "hash": file_hash,
            "threat_level": threat_level,
            "total_score": round(weighted_sum, 2),
        },
    }
