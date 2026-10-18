"""Local persistence for Security Regressions (no database).

Mirrors the Assessment repository conventions: id validation + one JSON file per
regression under ``artifacts/security_regressions/``. Execution evidence lives in
the normal run store; this only persists the regression definition + its latest
manual result pointer.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from orion.assessments.repository import identifier
from orion.security_regressions.model import SecurityRegression, RegressionResult

DEFAULT_DIR = "artifacts"


class RegressionRepository:
    def __init__(self, base_dir: str = DEFAULT_DIR) -> None:
        self.directory = Path(base_dir) / "security_regressions"

    def _path(self, regression_id: str) -> Path:
        return self.directory / (identifier(regression_id) + ".json")

    def save(self, reg: SecurityRegression) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        p = self._path(reg.regression_id)
        p.write_text(json.dumps(reg.to_dict(), indent=2, default=str), encoding="utf-8")
        return p

    def get(self, regression_id: str) -> Optional[SecurityRegression]:
        p = self._path(regression_id)
        if not p.exists():
            return None
        return SecurityRegression.from_dict(json.loads(p.read_text(encoding="utf-8")))

    def list(self) -> List[SecurityRegression]:
        if not self.directory.exists():
            return []
        out: List[SecurityRegression] = []
        for f in sorted(self.directory.glob("*.json")):
            if f.name.endswith(".result.json"):
                continue
            try:
                out.append(SecurityRegression.from_dict(json.loads(f.read_text(encoding="utf-8"))))
            except Exception:  # noqa: BLE001 - a bad file must not break the listing
                continue
        out.sort(key=lambda r: r.updated_at, reverse=True)
        return out

    def save_result(self, result: RegressionResult) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        p = self.directory / (identifier(result.regression_id) + ".result.json")
        p.write_text(json.dumps(result.to_dict(), indent=2, default=str), encoding="utf-8")
        return p

    def load_result(self, regression_id: str) -> Optional[dict]:
        p = self.directory / (identifier(regression_id) + ".result.json")
        if not p.exists():
            return None
        return json.loads(p.read_text(encoding="utf-8"))
