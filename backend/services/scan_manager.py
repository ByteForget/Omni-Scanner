from __future__ import annotations
from typing import Any, Dict, Optional
import threading
from datetime import datetime

class ScanManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ScanManager, cls).__new__(cls)
                cls._instance._reset()
                cls._instance._cancelled = False
        return cls._instance

    def _reset(self):
        self.state = {
            "status": "idle",
            "progress": 0,
            "label": "Ready",
            "log": "",
            "results": None,
            "error": None,
            "start_time": None,
            "target": None,
            "scan_type": "web"
        }
        self._cancelled = False

    def start_scan(self, target: str, scan_type: str = "web"):
        self._reset()
        self._cancelled = False
        self.state["status"] = "running"
        self.state["target"] = target
        self.state["scan_type"] = scan_type
        self.state["start_time"] = datetime.now().isoformat()

    def update_progress(self, progress: int, label: str = None, log: str = None):
        if label:
            self.state["label"] = label
        if log:
            self.state["log"] = log
        self.state["progress"] = progress

    def complete_scan(self, results: Dict[str, Any]):
        self.state["status"] = "complete"
        self.state["progress"] = 100
        self.state["results"] = results
        self.state["label"] = "Scan Complete"

    def fail_scan(self, error: str):
        self.state["status"] = "failed"
        self.state["error"] = error
        self.state["label"] = "Scan Failed"

    def cancel_scan(self):
        self._cancelled = True
        self.state["status"] = "failed"
        self.state["label"] = "Scan Cancelled"
        self.state["error"] = "User terminated the scan process."

    def is_cancelled(self) -> bool:
        return self._cancelled

    def get_status(self) -> Dict[str, Any]:
        return self.state

scan_manager = ScanManager()
