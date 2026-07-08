from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class RunArtifacts:
    run_id: str
    run_dir: Path
    exports_dir: Path
    blacklist_dir: Path
    analysis_dir: Path
    block_dir: Path
    reports_dir: Path
    logs_dir: Path


class ArtifactStore:
    def __init__(self, runs_dir: str | Path, state_dir: str | Path):
        self.runs_dir = Path(runs_dir)
        self.state_dir = Path(state_dir)

    def create_run(self, run_id: str | None = None) -> RunArtifacts:
        run_id = run_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = self.runs_dir / run_id
        artifacts = RunArtifacts(
            run_id=run_id,
            run_dir=run_dir,
            exports_dir=run_dir / "exports",
            blacklist_dir=run_dir / "blacklist",
            analysis_dir=run_dir / "analysis",
            block_dir=run_dir / "block",
            reports_dir=run_dir / "reports",
            logs_dir=run_dir / "logs",
        )
        for path in [
            artifacts.exports_dir,
            artifacts.blacklist_dir,
            artifacts.analysis_dir,
            artifacts.block_dir,
            artifacts.reports_dir,
            artifacts.logs_dir,
        ]:
            path.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        latest = {
            "run_id": artifacts.run_id,
            "run_dir": str(artifacts.run_dir),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        (self.state_dir / "latest.json").write_text(json.dumps(latest, ensure_ascii=False, indent=2), encoding="utf-8")
        return artifacts
