"""Structured JSONL transcript — the source of truth for a run.

One JSON object per step, appended to runs/<run_id>/transcript.jsonl. Reports and the ATT&CK
Navigator layer are *derived* from this; the JSONL alone is enough to replay a run.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_run_id(model: str, target: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    safe_model = model.replace("/", "-").replace(":", "-")
    return f"{stamp}_{safe_model}_{target}"


class JSONLLogger:
    def __init__(self, runs_dir: str | Path, run_id: str) -> None:
        self.run_dir = Path(runs_dir) / run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id
        self._transcript = self.run_dir / "transcript.jsonl"

    def write_meta(self, meta: dict[str, Any]) -> None:
        (self.run_dir / "run.json").write_text(
            json.dumps({"run_id": self.run_id, **meta}, indent=2), encoding="utf-8"
        )

    def step(self, obj: dict[str, Any]) -> None:
        record = {"run_id": self.run_id, "ts": utcnow_iso(), **obj}
        with self._transcript.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def write_text(self, name: str, content: str) -> Path:
        path = self.run_dir / name
        path.write_text(content, encoding="utf-8")
        return path

    def write_json(self, name: str, obj: Any) -> Path:
        path = self.run_dir / name
        path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
        return path
