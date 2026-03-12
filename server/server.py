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
        return check_hash(payload.hash)
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

        return result
    
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"APK analysis failed: {exc}") from exc
    finally:
        await file.close()
        if "tmp_path" in locals() and tmp_path.exists():
            tmp_path.unlink()
