from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class UserSettings(BaseModel):
    monitor_windows_events: bool = False
    use_ai_triage: bool = True
    threat_intel_enabled: bool = False
    sample_events_enabled: bool = True
    safe_mode: bool = True
    collector_interval_seconds: int = Field(default=30, ge=10, le=300)


class SettingsStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.Lock()
        self._settings = self._load()

    def _load(self) -> UserSettings:
        if not self.path.exists():
            return UserSettings()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return UserSettings.model_validate(data)
        except (json.JSONDecodeError, ValueError):
            return UserSettings()

    def get(self) -> UserSettings:
        with self.lock:
            return self._settings.model_copy(deep=True)

    def update(self, payload: dict[str, Any]) -> UserSettings:
        with self.lock:
            current = self._settings.model_dump()
            current.update(payload)
            self._settings = UserSettings.model_validate(current)
            self.path.write_text(self._settings.model_dump_json(indent=2), encoding="utf-8")
            return self._settings.model_copy(deep=True)
