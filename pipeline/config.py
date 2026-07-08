from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only on minimal installs
    yaml = None


@dataclass(frozen=True)
class PathConfig:
    sip_session_file: Path
    firewall_session_file: Path
    data_dir: Path
    outputs_dir: Path
    runs_dir: Path
    state_dir: Path


@dataclass(frozen=True)
class AnalysisConfig:
    db_path: Path
    whitelist_file: Path
    recommendation_levels: tuple[str, ...]
    min_final_score: int


@dataclass(frozen=True)
class BlockingConfig:
    default_apply: bool
    description_template: str
    max_targets_per_run: int


@dataclass(frozen=True)
class ScheduleWindowConfig:
    type: str
    timezone: str
    start_time: str
    end_time: str


@dataclass(frozen=True)
class ScheduleConfig:
    name: str
    enabled: bool
    cron: str
    timezone: str
    allow_apply: bool
    favorite_name: str | None
    window: ScheduleWindowConfig


@dataclass(frozen=True)
class SchedulerConfig:
    enabled: bool
    poll_interval_seconds: int


@dataclass(frozen=True)
class PipelineConfig:
    root_dir: Path
    paths: PathConfig
    analysis: AnalysisConfig
    blocking: BlockingConfig
    schedules: dict[str, ScheduleConfig]
    scheduler: SchedulerConfig

    @classmethod
    def load(cls, config_path: str | Path | None = None, *, root_dir: str | Path | None = None) -> "PipelineConfig":
        root = Path(root_dir).resolve() if root_dir else Path(__file__).resolve().parents[1]
        path = Path(config_path).expanduser() if config_path else root / "config" / "pipeline.yaml"
        data: dict[str, Any] = {}
        if path.exists():
            data = _load_yaml(path)
        return cls.from_dict(data, root_dir=root)

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, root_dir: str | Path) -> "PipelineConfig":
        root = Path(root_dir).resolve()
        paths_data = data.get("paths", {}) or {}
        analysis_data = data.get("analysis", {}) or {}
        blocking_data = data.get("blocking", {}) or {}
        schedules_data = data.get("schedules", {}) or {}
        scheduler_data = data.get("scheduler", {}) or {}

        paths = PathConfig(
            sip_session_file=_resolve_path(paths_data.get("sip_session_file", "secrets/sip_session.json"), root),
            firewall_session_file=_resolve_path(paths_data.get("firewall_session_file", "secrets/firewall_session.json"), root),
            data_dir=_resolve_path(paths_data.get("data_dir", "data"), root),
            outputs_dir=_resolve_path(paths_data.get("outputs_dir", "outputs"), root),
            runs_dir=_resolve_path(paths_data.get("runs_dir", "runs"), root),
            state_dir=_resolve_path(paths_data.get("state_dir", "state"), root),
        )
        default_db = paths.data_dir / "attackers.db"
        levels = analysis_data.get("recommendation_levels") or ["立即封禁", "建议封禁"]
        analysis = AnalysisConfig(
            db_path=_resolve_path(analysis_data.get("db_path", default_db), root),
            whitelist_file=_resolve_path(analysis_data.get("whitelist_file", "config/ip_whitelist.txt"), root),
            recommendation_levels=tuple(str(item) for item in levels),
            min_final_score=int(analysis_data.get("min_final_score", 45)),
        )
        blocking = BlockingConfig(
            default_apply=bool(blocking_data.get("default_apply", False)),
            description_template=str(blocking_data.get("description_template", "{month}月自动封禁")),
            max_targets_per_run=int(blocking_data.get("max_targets_per_run", 200)),
        )
        scheduler = SchedulerConfig(
            enabled=bool(scheduler_data.get("enabled", True)),
            poll_interval_seconds=int(scheduler_data.get("poll_interval_seconds", 30)),
        )
        return cls(
            root_dir=root,
            paths=paths,
            analysis=analysis,
            blocking=blocking,
            schedules=_parse_schedules(schedules_data),
            scheduler=scheduler,
        )


def schedule_window(schedule: ScheduleConfig, *, now: datetime | None = None) -> tuple[str, str]:
    tz = ZoneInfo(schedule.window.timezone or schedule.timezone)
    current = now.astimezone(tz) if now else datetime.now(tz)
    if schedule.window.type == "previous_day":
        target_day = current.date() - timedelta(days=1)
    elif schedule.window.type == "today":
        target_day = current.date()
    else:
        raise ValueError(f"unsupported schedule window type: {schedule.window.type}")
    start = datetime.combine(target_day, _parse_time(schedule.window.start_time), tzinfo=tz)
    end = datetime.combine(target_day, _parse_time(schedule.window.end_time), tzinfo=tz)
    return _format_local(start), _format_local(end)


def _resolve_path(value: str | Path, root: Path) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return root / path


def _parse_schedules(data: dict[str, Any]) -> dict[str, ScheduleConfig]:
    schedules: dict[str, ScheduleConfig] = {}
    for name, raw in data.items():
        if not isinstance(raw, dict):
            continue
        window_raw = raw.get("window", {}) or {}
        timezone = str(raw.get("timezone", "Asia/Shanghai"))
        window = ScheduleWindowConfig(
            type=str(window_raw.get("type", "previous_day")),
            timezone=str(window_raw.get("timezone", timezone)),
            start_time=str(window_raw.get("start_time", "00:00:00")),
            end_time=str(window_raw.get("end_time", "23:59:59")),
        )
        schedules[str(name)] = ScheduleConfig(
            name=str(name),
            enabled=bool(raw.get("enabled", True)),
            cron=str(raw.get("cron", "")),
            timezone=timezone,
            allow_apply=bool(raw.get("allow_apply", False)),
            favorite_name=str(raw["favorite_name"]) if raw.get("favorite_name") is not None else None,
            window=window,
        )
    return schedules


def _parse_time(value: str):
    from datetime import time

    parts = [int(part) for part in value.split(":")]
    if len(parts) == 2:
        return time(parts[0], parts[1])
    if len(parts) == 3:
        return time(parts[0], parts[1], parts[2])
    raise ValueError(f"invalid schedule time: {value}")


def _format_local(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _load_yaml(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        loaded = yaml.safe_load(text) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"{path} must contain a YAML mapping")
        return loaded
    return _parse_simple_yaml(text)


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        key, sep, value = raw_line.strip().partition(":")
        if not sep:
            continue
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        value = value.strip()
        if not value:
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
        elif value.startswith("[") and value.endswith("]"):
            parent[key] = [item.strip().strip('"\'') for item in value[1:-1].split(",") if item.strip()]
        elif value.lower() in {"true", "false"}:
            parent[key] = value.lower() == "true"
        elif value.startswith('"') and value.endswith('"'):
            parent[key] = value[1:-1]
        else:
            parent[key] = value.strip('"\'')
    return root
