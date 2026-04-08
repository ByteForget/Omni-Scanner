from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from backend.routes.scan import router as scan_router
from backend.routes.reports import router as reports_router
from backend.routes.downloads import router as downloads_router


app = FastAPI(title="OmniScanner API", version="1.0.0")

app.include_router(scan_router)
app.include_router(reports_router)
app.include_router(downloads_router)


@app.get("/")
def ui_root():

    return FileResponse(os.path.join("frontend", "index.html"))


@app.get("/scans")
def ui_scans():
    return FileResponse(os.path.join("frontend", "scans.html"))


@app.get("/history")
def ui_history():
    return FileResponse(os.path.join("frontend", "history.html"))


@app.get("/ai")
def ui_ai():
    return FileResponse(os.path.join("frontend", "ai.html"))


@app.get("/settings")
def ui_settings():
    return FileResponse(os.path.join("frontend", "settings.html"))


app.mount("/frontend", StaticFiles(directory="frontend"), name="frontend")
app.mount("/assets", StaticFiles(directory="Assets"), name="assets")
app.mount("/reports", StaticFiles(directory="reports"), name="reports")


try:
    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
except Exception:

    pass

