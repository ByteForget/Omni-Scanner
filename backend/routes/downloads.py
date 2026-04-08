from __future__ import annotations

import os
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse


router = APIRouter()


@router.get("/download/{filename}")
def download_report(filename: str):
    """
    Download generated report artifacts from `reports/`.

    Kept intentionally strict to prevent path traversal.
    """

    if not filename or filename != os.path.basename(filename):
        raise HTTPException(status_code=400, detail="Invalid filename.")

    allowed_ext = {".pdf", ".html", ".json"}
    _, ext = os.path.splitext(filename.lower())
    if ext not in allowed_ext:
        raise HTTPException(status_code=400, detail="Unsupported file type.")

    path = os.path.join("reports", filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File not found.")

    return FileResponse(path, media_type="application/octet-stream", filename=filename)

