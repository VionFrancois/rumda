import hashlib
from pathlib import Path
from tempfile import NamedTemporaryFile

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel

from cache_store import get_cached_verdict, init_cache_db, set_cached_verdict
from quark_analysis import analyze_apk_with_quark
from virustotal import check_hash

app = FastAPI(title="RuMDA API")
CACHE_TTL_SECONDS = 60 * 60 * 24 * 14 # 14 days
init_cache_db()


class HashRequest(BaseModel):
    hash: str


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
