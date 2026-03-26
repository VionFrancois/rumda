from pathlib import Path
from tempfile import NamedTemporaryFile

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel

from quark_analysis import analyze_apk_with_quark
from virustotal import check_hash

app = FastAPI(title="RuMDA API")


class HashRequest(BaseModel):
    hash: str


@app.post("/analysis/apk/hash")
def analyze_apk_hash(payload: HashRequest) -> dict:
    try:
        return format_hash_analysis(payload.hash, check_hash(payload.hash))
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/analysis/apk/file")
async def analyze_apk_file(file: UploadFile = File(...)) -> dict:
    # TODO : Ensure the uploaded file is a valid APK
    try:
        with NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
            tmp_path = Path(tmp.name)
            tmp.write(await file.read())
            result = analyze_apk_with_quark(str(tmp_path))

        return format_file_analysis(result)
    
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


def format_file_analysis(result: dict) -> dict:
    malicious = bool(result.get("malicious", False))
    threat_level = result.get("threat_level", "Unknown")
    total_score = int(result.get("total_score", 0) or 0)
    normalized_threat_level = threat_level.strip().lower()
    degree = {
        "high risk": "high",
        "moderate risk": "medium",
        "low risk": "low",
    }.get(normalized_threat_level, "none" if not malicious else "medium")

    return {
        "found": True,
        "analysis_type": "file",
        "malicious": malicious,
        "degree": degree,
        "details": {
            "total_score": total_score
        },
    }
