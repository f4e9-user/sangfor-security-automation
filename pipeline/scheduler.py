#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = "pipeline"

from .config import PipelineConfig, ScheduleConfig


def cron_matches(expr: str, current: datetime) -> bool:
    fields = expr.split()
    if len(fields) != 5:
        raise ValueError(f"unsupported cron expression: {expr}")
    cron_weekday = current.isoweekday() % 7
    values = [current.minute, current.hour, current.day, current.month, cron_weekday]
    return all(_field_matches(field, value) for field, value in zip(fields, values))


def _field_matches(field: str, value: int) -> bool:
    if field == "*":
        return True
    for part in field.split(","):
        if part.startswith("*/"):
            step = int(part[2:])
            if step > 0 and value % step == 0:
                return True
        elif "-" in part:
            start, end = [int(item) for item in part.split("-", 1)]
            if start <= value <= end:
                return True
        elif part and int(part) == value:
            return True
    return False


def due_jobs(config: PipelineConfig, now: datetime) -> list[ScheduleConfig]:
    jobs = []
    for schedule in config.schedules.values():
        if not schedule.enabled or not schedule.cron:
            continue
        local_now = now.astimezone(ZoneInfo(schedule.timezone))
        if cron_matches(schedule.cron, local_now):
            jobs.append(schedule)
    return jobs


def run_scheduled_job(config_path: str | None, schedule: ScheduleConfig, *, apply: bool) -> int:
    command = [sys.executable, str(Path(__file__).with_name("run_pipeline.py"))]
    if config_path:
        command.extend(["--config", config_path])
    command.extend(["scheduled", schedule.name])
    if apply:
        command.append("--apply")
    completed = subprocess.run(command, check=False)
    return completed.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Poll pipeline schedules and run matching Sangfor automation jobs.")
    parser.add_argument("--config", help="pipeline YAML config path")
    parser.add_argument("--apply", action="store_true", help="Request apply for schedules that allow it")
    parser.add_argument("--once", action="store_true", help="Evaluate schedules once and exit")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    last_run: set[tuple[str, str]] = set()
    while True:
        config = PipelineConfig.load(args.config)
        if not config.scheduler.enabled:
            print("scheduler disabled", flush=True)
            return 0
        now = datetime.now().astimezone()
        minute_key = now.strftime("%Y-%m-%dT%H:%M")
        for schedule in due_jobs(config, now):
            key = (schedule.name, minute_key)
            if key in last_run:
                continue
            print(f"[{now.isoformat(timespec='seconds')}] running schedule {schedule.name}", flush=True)
            code = run_scheduled_job(args.config, schedule, apply=args.apply)
            print(f"[{datetime.now().astimezone().isoformat(timespec='seconds')}] schedule {schedule.name} exited {code}", flush=True)
            last_run.add(key)
        if args.once:
            return 0
        time.sleep(max(1, config.scheduler.poll_interval_seconds))


if __name__ == "__main__":
    raise SystemExit(main())
