#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = "pipeline"

from .artifacts import ArtifactStore, RunArtifacts
from .commands import (
    analyze_command,
    ApplyGuardError,
    block_command,
    copy_analyzer_output,
    export_firewall_blacklist_command,
    export_logs_command,
    find_latest_file,
    normalize_recommendations,
    rewrite_normalized_with_selection,
    run_subprocess,
    select_block_targets,
    write_apply_result,
    write_block_artifacts,
)
from .config import PipelineConfig, schedule_window
from .reports import write_daily_report
from .sessions import (
    MissingSessionError,
    check_firewall_session_health,
    check_sip_session_health,
    validate_firewall_session,
    validate_sip_session,
)
from .state import EventLogger, RunManifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the Sangfor security automation pipeline")
    parser.add_argument("--config", help="pipeline YAML config path")
    parser.add_argument("--run-id", help="reuse or create a specific run id")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("check-sessions")

    export_logs = subparsers.add_parser("export-logs")
    export_logs.add_argument("--start", required=True)
    export_logs.add_argument("--end", required=True)
    export_logs.add_argument("--favorite-name", default=None)
    export_logs.add_argument("--export-date", default=None)

    subparsers.add_parser("export-firewall-blacklist")

    analyze = subparsers.add_parser("analyze")
    analyze.add_argument("--xlsx")
    analyze.add_argument("--blacklist")

    block = subparsers.add_parser("block")
    block.add_argument("--recommendations")
    block.add_argument("--apply", action="store_true")
    block.add_argument("--manual-override-reason", help="Required audit reason when applying an explicit external recommendations file")

    full = subparsers.add_parser("full")
    full.add_argument("--start", required=True)
    full.add_argument("--end", required=True)
    full.add_argument("--favorite-name", default=None)
    full.add_argument("--export-date", default=None)
    full.add_argument("--apply", action="store_true")

    scheduled = subparsers.add_parser("scheduled")
    scheduled.add_argument("job_name")
    scheduled.add_argument("--apply", action="store_true")
    return parser


def run_command(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = PipelineConfig.load(args.config)
    artifacts = ArtifactStore(config.paths.runs_dir, config.paths.state_dir).create_run(args.run_id)
    manifest = RunManifest(artifacts.run_dir, artifacts.run_id, vars(args))
    events = EventLogger(artifacts.run_dir, artifacts.run_id)
    runner = PipelineRunner(config, artifacts, manifest, events)

    try:
        if args.command == "check-sessions":
            runner.check_sessions()
        elif args.command == "export-logs":
            runner.export_logs(args.start, args.end, args.favorite_name, args.export_date)
        elif args.command == "export-firewall-blacklist":
            runner.export_firewall_blacklist()
        elif args.command == "analyze":
            runner.analyze(Path(args.xlsx) if args.xlsx else None, Path(args.blacklist) if args.blacklist else None)
        elif args.command == "block":
            runner.block(Path(args.recommendations) if args.recommendations else None, apply=args.apply, manual_override_reason=args.manual_override_reason)
        elif args.command == "full":
            runner.full(args.start, args.end, args.favorite_name, args.export_date, apply=args.apply)
        elif args.command == "scheduled":
            runner.scheduled(args.job_name, apply=args.apply)
        manifest.finish("completed")
        return 0
    except Exception as exc:
        manifest.finish("failed", error=exc)
        events.emit(args.command, "ERROR", "pipeline_failed", str(exc), {"error_type": type(exc).__name__})
        print(str(exc), file=sys.stderr)
        return 1


class PipelineRunner:
    def __init__(self, config: PipelineConfig, artifacts: RunArtifacts, manifest: RunManifest, events: EventLogger):
        self.config = config
        self.artifacts = artifacts
        self.manifest = manifest
        self.events = events

    def check_sessions(self) -> None:
        stage = "check-sessions"
        self.manifest.start_stage(stage)
        self.events.emit(stage, "INFO", "stage_started", "checking session files")
        try:
            sip = validate_sip_session(self.config.paths.sip_session_file)
            firewall = validate_firewall_session(self.config.paths.firewall_session_file)
            sip_health = check_sip_session_health(self.config.paths.sip_session_file)
            firewall_health = check_firewall_session_health(self.config.paths.firewall_session_file)
            self._write_status("sip_session.status.json", sip_health, str(sip.path))
            self._write_status("firewall_session.status.json", firewall_health, str(firewall.path))
            if not sip_health.get("healthy"):
                raise MissingSessionError("SIP session health check failed")
            if not firewall_health.get("healthy"):
                raise MissingSessionError("firewall session health check failed")
        except MissingSessionError as exc:
            self.manifest.finish_stage(stage, "failed", error=exc)
            self.events.emit(stage, "ERROR", "stage_failed", str(exc))
            raise
        details = {"sip_session": str(sip.path), "firewall_session": str(firewall.path), "sip_health": sip_health, "firewall_health": firewall_health}
        self.manifest.finish_stage(stage, "completed", details=details)
        self.events.emit(stage, "INFO", "stage_completed", "session health checks passed")

    def export_logs(self, start: str, end: str, favorite_name: str | None, export_date: str | None) -> Path:
        stage = "export-logs"
        self.manifest.start_stage(stage, {"start": start, "end": end})
        favorite = favorite_name or "3"
        command = export_logs_command(
            self.config.root_dir,
            self.config.paths.sip_session_file,
            start,
            end,
            favorite,
            self.artifacts.exports_dir,
            export_date or date.today().strftime("%Y-%m-%d"),
        )
        result = run_subprocess(
            command,
            stdout_path=self.artifacts.logs_dir / "export-logs.stdout.log",
            stderr_path=self.artifacts.logs_dir / "export-logs.stderr.log",
        )
        if result.returncode != 0:
            self.manifest.finish_stage(stage, "failed", error=result.stderr or result.stdout)
            raise RuntimeError(f"export-logs failed with exit code {result.returncode}")
        latest = find_latest_file(self.artifacts.exports_dir, "*.xlsx")
        self.manifest.set_output("exported_xlsx", str(latest))
        self.manifest.finish_stage(stage, "completed", details={"xlsx": str(latest)})
        self.events.emit(stage, "INFO", "stage_completed", "exported SIP logs", {"xlsx": str(latest)})
        return latest

    def export_firewall_blacklist(self) -> Path:
        stage = "export-firewall-blacklist"
        self.manifest.start_stage(stage)
        command = export_firewall_blacklist_command(self.config.root_dir, self.config.paths.firewall_session_file, self.artifacts.blacklist_dir)
        result = run_subprocess(
            command,
            stdout_path=self.artifacts.logs_dir / "export-firewall-blacklist.stdout.log",
            stderr_path=self.artifacts.logs_dir / "export-firewall-blacklist.stderr.log",
        )
        if result.returncode != 0:
            self.manifest.finish_stage(stage, "failed", error=result.stderr or result.stdout)
            raise RuntimeError(f"export-firewall-blacklist failed with exit code {result.returncode}")
        output = self.artifacts.blacklist_dir / "sangfor_firewall_blacklists.csv"
        self.manifest.set_output("firewall_blacklist", str(output))
        self.manifest.finish_stage(stage, "completed", details={"blacklist": str(output)})
        self.events.emit(stage, "INFO", "stage_completed", "exported firewall blacklist", {"blacklist": str(output)})
        return output

    def analyze(self, xlsx: Path | None = None, blacklist: Path | None = None) -> Path:
        stage = "analyze"
        xlsx = xlsx or find_latest_file(self.artifacts.exports_dir, "*.xlsx")
        blacklist = blacklist or self.artifacts.blacklist_dir / "sangfor_firewall_blacklists.csv"
        self.manifest.start_stage(stage, {"xlsx": str(xlsx), "blacklist": str(blacklist)})
        command, cwd = analyze_command(self.config.root_dir, xlsx, blacklist, self.config.analysis.db_path, self.config.analysis.whitelist_file, self.artifacts.analysis_dir)
        result = run_subprocess(
            command,
            cwd=cwd,
            stdout_path=self.artifacts.logs_dir / "analyze.stdout.log",
            stderr_path=self.artifacts.logs_dir / "analyze.stderr.log",
        )
        if result.returncode != 0:
            self.manifest.finish_stage(stage, "failed", error=result.stderr or result.stdout)
            raise RuntimeError(f"analyze failed with exit code {result.returncode}")
        raw = copy_analyzer_output(self.config.root_dir, self.artifacts.analysis_dir, xlsx)
        normalized = self.artifacts.analysis_dir / "blocklist_recommendations.normalized.csv"
        normalize_recommendations(raw, normalized, source_report=xlsx)
        self.manifest.set_output("raw_recommendations", str(raw))
        self.manifest.set_output("normalized_recommendations", str(normalized))
        self.manifest.finish_stage(stage, "completed", details={"normalized": str(normalized)})
        self.events.emit(stage, "INFO", "stage_completed", "normalized analyzer recommendations", {"normalized": str(normalized)})
        return normalized

    def block(self, recommendations: Path | None = None, *, apply: bool = False, manual_override_reason: str | None = None) -> list[str]:
        stage = "block"
        explicit_recommendations = recommendations is not None
        recommendations = recommendations or self.artifacts.analysis_dir / "blocklist_recommendations.normalized.csv"
        apply = bool(apply)
        self.manifest.start_stage(stage, {"recommendations": str(recommendations), "apply": apply, "manual_override_reason": manual_override_reason or ""})
        if apply:
            self._check_apply_prerequisites(recommendations, explicit_recommendations=explicit_recommendations)
        selection = select_block_targets(
            recommendations,
            whitelist_file=self.config.analysis.whitelist_file,
            max_targets=self.config.blocking.max_targets_per_run,
            min_final_score=self.config.analysis.min_final_score,
            apply=apply,
            recommendation_levels=self.config.analysis.recommendation_levels,
            run_dir=self.artifacts.run_dir,
            explicit_recommendations=explicit_recommendations,
            manual_override_reason=manual_override_reason,
        )
        targets_path, dry_run_path = write_block_artifacts(selection, self.artifacts.block_dir)
        rewrite_normalized_with_selection(selection, recommendations)
        apply_result_path = write_apply_result(selection, self.artifacts.block_dir, executed=False)
        self.manifest.set_targets(len(selection.targets), apply=apply)
        self.manifest.set_output("block_targets", str(targets_path))
        self.manifest.set_output("block_dry_run", str(dry_run_path))
        self.manifest.set_output("block_apply_result", str(apply_result_path))
        if apply and selection.apply_refusal:
            self.manifest.finish_stage(stage, "failed", error=selection.apply_refusal)
            raise RuntimeError(f"apply refused: {selection.apply_refusal}")
        if apply and selection.targets:
            if not targets_path.read_text(encoding="utf-8").strip():
                self.manifest.finish_stage(stage, "failed", error="empty target file")
                raise RuntimeError("apply refused: empty target file")
            command = block_command(
                self.config.root_dir,
                self.config.paths.firewall_session_file,
                targets_path,
                self.config.blocking.description_template.format(month=date.today().month),
                apply=True,
            )
            result = run_subprocess(
                command,
                stdout_path=self.artifacts.logs_dir / "block.stdout.log",
                stderr_path=self.artifacts.logs_dir / "block.stderr.log",
            )
            apply_result_path = write_apply_result(selection, self.artifacts.block_dir, executed=result.returncode == 0, command_result=result)
            self.manifest.set_output("block_apply_result", str(apply_result_path))
            if result.returncode != 0:
                self.manifest.finish_stage(stage, "failed", error=result.stderr or result.stdout)
                raise RuntimeError(f"block apply failed with exit code {result.returncode}")
        self.manifest.finish_stage(stage, "completed", details={"target_count": len(selection.targets), "apply": apply})
        self.events.emit(stage, "INFO", "stage_completed", "selected block targets", {"target_count": len(selection.targets), "apply": apply})
        return selection.targets

    def full(self, start: str, end: str, favorite_name: str | None, export_date: str | None, *, apply: bool = False) -> None:
        self.check_sessions()
        xlsx = self.export_logs(start, end, favorite_name, export_date)
        blacklist = self.export_firewall_blacklist()
        recommendations = self.analyze(xlsx, blacklist)
        self.block(recommendations, apply=False)
        if apply:
            self.block(recommendations, apply=True)
        md_path, json_path = write_daily_report(self.artifacts.run_dir, self.manifest.data, recommendations, log_window=(start, end))
        self.manifest.set_output("daily_report_md", str(md_path))
        self.manifest.set_output("daily_report_json", str(json_path))

    def scheduled(self, job_name: str, *, apply: bool = False) -> None:
        stage = "scheduled"
        schedule = self.config.schedules.get(job_name)
        if schedule is None:
            raise ValueError(f"schedule not found: {job_name}")
        if not schedule.enabled:
            raise ValueError(f"schedule is disabled: {job_name}")
        start, end = schedule_window(schedule)
        effective_apply = bool(apply and schedule.allow_apply)
        details = {
            "job_name": job_name,
            "requested_apply": bool(apply),
            "allow_apply": schedule.allow_apply,
            "effective_apply": effective_apply,
            "apply_downgraded": bool(apply and not schedule.allow_apply),
            "start": start,
            "end": end,
        }
        self.manifest.start_stage(stage, details)
        self.events.emit(stage, "INFO", "stage_started", "starting scheduled pipeline", details)
        self.full(start, end, schedule.favorite_name, None, apply=effective_apply)
        self.manifest.finish_stage(stage, "completed", details=details)
        self.events.emit(stage, "INFO", "stage_completed", "scheduled pipeline completed", details)

    def _check_apply_prerequisites(self, recommendations: Path, *, explicit_recommendations: bool) -> None:
        if not self.artifacts.run_id:
            raise ApplyGuardError("apply requires a concrete run_id")
        validate_sip_session(self.config.paths.sip_session_file)
        validate_firewall_session(self.config.paths.firewall_session_file)
        sip_health = check_sip_session_health(self.config.paths.sip_session_file)
        firewall_health = check_firewall_session_health(self.config.paths.firewall_session_file)
        self._write_status("sip_session.status.json", sip_health, str(self.config.paths.sip_session_file))
        self._write_status("firewall_session.status.json", firewall_health, str(self.config.paths.firewall_session_file))
        if not sip_health.get("healthy"):
            raise ApplyGuardError("apply requires healthy SIP session")
        if not firewall_health.get("healthy"):
            raise ApplyGuardError("apply requires healthy firewall session")
        run_path = self.artifacts.run_dir.resolve()
        rec_path = Path(recommendations).resolve()
        external_recommendations = explicit_recommendations and run_path not in rec_path.parents
        if not external_recommendations:
            for required_stage in ("export-logs", "export-firewall-blacklist", "analyze"):
                stage_data = self.manifest.data.get("stages", {}).get(required_stage, {})
                if stage_data.get("status") != "completed":
                    raise ApplyGuardError(f"apply requires completed same-run {required_stage}")
            expected = (self.artifacts.analysis_dir / "blocklist_recommendations.normalized.csv").resolve()
            if rec_path != expected:
                raise ApplyGuardError("apply requires same-run normalized recommendations")

    def _write_status(self, name: str, status: dict, session_path: str) -> None:
        import json
        from .state import utc_now

        self.config.paths.state_dir.mkdir(parents=True, exist_ok=True)
        path = self.config.paths.state_dir / name
        payload = dict(status)
        payload.setdefault("healthy", bool(payload.get("ok", False)))
        payload.setdefault("session_file", session_path)
        payload.setdefault("timestamp", utc_now())
        payload.setdefault("error", "")
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> None:
    raise SystemExit(run_command(argv))


if __name__ == "__main__":
    main()
