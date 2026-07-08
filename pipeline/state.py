from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from .redaction import redact_data, redact_secrets


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunManifest:
    def __init__(self, run_dir: str | Path, run_id: str, args: dict[str, Any]):
        self.run_dir = Path(run_dir)
        self.path = self.run_dir / "manifest.json"
        self.data: dict[str, Any] = {
            "run_id": run_id,
            "started_at": utc_now(),
            "ended_at": None,
            "status": "running",
            "args": redact_data(args),
            "stages": {},
            "inputs": {},
            "outputs": {},
            "target_count": 0,
            "apply": False,
            "error": None,
        }
        self.write()

    def start_stage(self, name: str, details: dict[str, Any] | None = None) -> None:
        self.data["stages"][name] = {
            "status": "running",
            "started_at": utc_now(),
            "ended_at": None,
            "details": redact_data(details or {}),
            "error": None,
        }
        self.write()

    def finish_stage(self, name: str, status: str, *, details: dict[str, Any] | None = None, error: Any = None) -> None:
        stage = self.data["stages"].setdefault(name, {"started_at": utc_now()})
        stage.update(
            {
                "status": status,
                "ended_at": utc_now(),
                "details": redact_data(details or stage.get("details", {})),
                "error": redact_secrets(str(error)) if error else None,
            }
        )
        self.write()

    def set_input(self, key: str, value: Any) -> None:
        self.data["inputs"][key] = redact_data(value)
        self.write()

    def set_output(self, key: str, value: Any) -> None:
        self.data["outputs"][key] = redact_data(value)
        self.write()

    def set_targets(self, count: int, *, apply: bool) -> None:
        self.data["target_count"] = count
        self.data["apply"] = apply
        self.write()

    def finish(self, status: str, *, error: Any = None) -> None:
        self.data["status"] = status
        self.data["ended_at"] = utc_now()
        self.data["error"] = redact_secrets(str(error)) if error else None
        self.write()

    def write(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(redact_data(self.data), ensure_ascii=False, indent=2), encoding="utf-8")


class EventLogger:
    LEVELS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}

    def __init__(self, run_dir: str | Path, run_id: str, *, console: TextIO | None = None, console_level: str = "INFO"):
        self.run_dir = Path(run_dir)
        self.run_id = run_id
        self.path = self.run_dir / "logs" / "events.jsonl"
        self.pipeline_log_path = self.run_dir / "logs" / "pipeline.log"
        self.console = console
        self.console_level = self.LEVELS.get(console_level.upper(), self.LEVELS["INFO"])
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, stage: str, level: str, event: str, message: str, data: dict[str, Any] | None = None) -> None:
        row = {
            "ts": utc_now(),
            "run_id": self.run_id,
            "stage": stage,
            "level": level,
            "event": event,
            "message": redact_secrets(message),
            "data": redact_data(data or {}),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        line = f"{row['ts']} {level} [{stage}] {event}: {row['message']}"
        if row["data"]:
            line += " " + json.dumps(row["data"], ensure_ascii=False)
        with self.pipeline_log_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        if self.console and self.LEVELS.get(level.upper(), self.LEVELS["INFO"]) >= self.console_level:
            console_line = f"[{level}] {stage} {event}: {row['message']}"
            if row["data"]:
                console_line += " " + json.dumps(row["data"], ensure_ascii=False)
            print(console_line, file=self.console, flush=True)
