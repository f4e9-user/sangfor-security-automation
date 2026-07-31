#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
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
    normalize_recommendations,
    prepare_analysis_input,
    rewrite_normalized_with_selection,
    run_subprocess,
    select_block_targets,
    write_apply_result,
    write_block_artifacts,
)
from .config import PipelineConfig, schedule_window
from .reports import print_console_report, read_exported_log_count, write_daily_report
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
    parser.add_argument("--debug", action="store_true", help="print DEBUG events and detailed run context to the console")
    subparsers = parser.add_subparsers(dest="command", required=True)

    login = subparsers.add_parser("login")
    login.add_argument("--target", choices=("all", "sip", "firewall"), default="all")
    login.add_argument("--sip-username")
    login.add_argument("--firewall-username")
    login.add_argument("--credentials-file", help="GPG-encrypted JSON containing sip/firewall/chaojiying credentials")
    login.add_argument("--captcha-provider", choices=("manual", "chaojiying"), default="manual")
    login.add_argument("--chaojiying-codetype", help="Override Chaojiying codetype, e.g. 1004")
    login.add_argument("--browser-executable", help="Use an existing Chromium/Chrome executable for login helpers")
    login.add_argument("--headless", action=argparse.BooleanOptionalAction, default=True)
    login.add_argument("--firewall-keepalive", action=argparse.BooleanOptionalAction, default=False)

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
    full.add_argument("--report", action=argparse.BooleanOptionalAction, default=True, help="print a console summary after completion (default: enabled)")

    scheduled = subparsers.add_parser("scheduled")
    scheduled.add_argument("job_name")
    scheduled.add_argument("--apply", action="store_true")
    scheduled.add_argument("--report", action=argparse.BooleanOptionalAction, default=True, help="print a console summary after completion (default: enabled)")

    report = subparsers.add_parser("report", help="print a console summary for the latest or a given run (read-only)")
    report.add_argument("--run-id", default=None, help="run id to summarize; defaults to the latest run")
    return parser


def _resolve_run_dir(config: "PipelineConfig", run_id: str | None) -> Path:
    runs_dir = config.paths.runs_dir
    if run_id:
        run_dir = runs_dir / run_id
        if not run_dir.is_dir():
            raise FileNotFoundError(f"run not found: {run_dir}")
        return run_dir
    latest = config.paths.state_dir / "latest.json"
    if latest.is_file():
        try:
            data = json.loads(latest.read_text(encoding="utf-8"))
            rid = data.get("run_id")
            if rid:
                candidate = runs_dir / str(rid)
                if candidate.is_dir():
                    return candidate
        except (OSError, ValueError):
            pass
    candidates = sorted((p for p in runs_dir.glob("*") if p.is_dir()), reverse=True)
    if not candidates:
        raise FileNotFoundError(f"no runs found under {runs_dir}")
    return candidates[0]


def _run_report_command(args: argparse.Namespace) -> int:
    config = PipelineConfig.load(args.config)
    run_dir = _resolve_run_dir(config, args.run_id)
    print_console_report(run_dir)
    return 0


def run_command(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "report":
        return _run_report_command(args)
    config = PipelineConfig.load(args.config)
    artifacts = ArtifactStore(config.paths.runs_dir, config.paths.state_dir).create_run(args.run_id)
    manifest = RunManifest(artifacts.run_dir, artifacts.run_id, vars(args))
    events = EventLogger(artifacts.run_dir, artifacts.run_id, console=sys.stdout, console_level="DEBUG" if args.debug else "INFO")
    runner = PipelineRunner(config, artifacts, manifest, events)
    print(f"Run ID: {artifacts.run_id}", flush=True)
    print(f"Run dir: {artifacts.run_dir}", flush=True)

    try:
        if args.command == "login":
            runner.login(
                args.target,
                sip_username=args.sip_username,
                firewall_username=args.firewall_username,
                credentials_file=args.credentials_file,
                captcha_provider=args.captcha_provider,
                chaojiying_codetype=args.chaojiying_codetype,
                browser_executable=args.browser_executable,
                headless=args.headless,
                firewall_keepalive=args.firewall_keepalive,
            )
        elif args.command == "check-sessions":
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
            runner.full(args.start, args.end, args.favorite_name, args.export_date, apply=args.apply, report=args.report)
        elif args.command == "scheduled":
            runner.scheduled(args.job_name, apply=args.apply, report=args.report)
        manifest.finish("completed")
        print("Status: completed", flush=True)
        print(f"Events: {events.path}", flush=True)
        print(f"Pipeline log: {events.pipeline_log_path}", flush=True)
        return 0
    except Exception as exc:
        manifest.finish("failed", error=exc)
        events.emit(args.command, "ERROR", "pipeline_failed", str(exc), {"error_type": type(exc).__name__})
        print(str(exc), file=sys.stderr)
        print("Status: failed", flush=True)
        print(f"Events: {events.path}", flush=True)
        print(f"Pipeline log: {events.pipeline_log_path}", flush=True)
        return 1


class PipelineRunner:
    def __init__(self, config: PipelineConfig, artifacts: RunArtifacts, manifest: RunManifest, events: EventLogger):
        self.config = config
        self.artifacts = artifacts
        self.manifest = manifest
        self.events = events

    def login(
        self,
        target: str = "all",
        *,
        sip_username: str | None = None,
        firewall_username: str | None = None,
        credentials_file: str | None = None,
        captcha_provider: str = "manual",
        chaojiying_codetype: str | None = None,
        browser_executable: str | None = None,
        headless: bool = True,
        firewall_keepalive: bool = False,
    ) -> None:
        stage = "login"
        targets = ["sip", "firewall"] if target == "all" else [target]
        self.manifest.start_stage(stage, {"target": target})
        self.events.emit(stage, "INFO", "stage_started", "starting local login helper", {"target": target})
        for item in targets:
            if item == "sip":
                command = [
                    sys.executable,
                    str(self.config.root_dir / "situation-awareness" / "sangfor_login_session.py"),
                    "--base-url",
                    self.config.sip_base_url,
                    "--session-file",
                    str(self.config.paths.sip_session_file),
                ]
                if sip_username:
                    command.extend(["--username", sip_username])
                if credentials_file:
                    command.extend(["--credentials-file", credentials_file])
                command.extend(["--captcha-provider", captcha_provider])
                if chaojiying_codetype:
                    command.extend(["--chaojiying-codetype", chaojiying_codetype])
                if browser_executable:
                    command.extend(["--browser-executable", browser_executable])
                command.append("--headless" if headless else "--no-headless")
                stdout_path = self.artifacts.logs_dir / "login-sip.stdout.log"
                stderr_path = self.artifacts.logs_dir / "login-sip.stderr.log"
            else:
                command = [
                    sys.executable,
                    str(self.config.root_dir / "firewall" / "sangfor_firewall_login_session.py"),
                    "--base-url",
                    self.config.firewall_base_url,
                    "--session-file",
                    str(self.config.paths.firewall_session_file),
                ]
                if firewall_username:
                    command.extend(["--username", firewall_username])
                if credentials_file:
                    command.extend(["--credentials-file", credentials_file])
                command.extend(["--captcha-provider", captcha_provider])
                if chaojiying_codetype:
                    command.extend(["--chaojiying-codetype", chaojiying_codetype])
                if browser_executable:
                    command.extend(["--browser-executable", browser_executable])
                command.append("--headless" if headless else "--no-headless")
                command.append("--keepalive" if firewall_keepalive else "--no-keepalive")
                stdout_path = self.artifacts.logs_dir / "login-firewall.stdout.log"
                stderr_path = self.artifacts.logs_dir / "login-firewall.stderr.log"
            result = run_subprocess(command, stdout_path=stdout_path, stderr_path=stderr_path)
            if result.returncode != 0:
                self.manifest.finish_stage(stage, "failed", error=result.stderr or result.stdout)
                raise RuntimeError(f"{item} login failed with exit code {result.returncode}")
            self.events.emit(stage, "INFO", "login_completed", f"{item} login completed", {"target": item})
        self.manifest.finish_stage(stage, "completed", details={"target": target})

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
        self.events.emit(stage, "INFO", "stage_started", "exporting SIP logs", {"start": start, "end": end, "favorite_name": favorite})
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
            self.events.emit(stage, "ERROR", "stage_failed", "export SIP logs failed", {"returncode": result.returncode})
            raise RuntimeError(f"export-logs failed with exit code {result.returncode}")
        analysis_input = prepare_analysis_input(self.artifacts.exports_dir)
        self.manifest.set_output("exported_xlsx", str(analysis_input))
        self.manifest.set_output("analysis_input_xlsx", str(analysis_input))
        log_count = read_exported_log_count(self.artifacts.exports_dir)
        if log_count is not None:
            self.manifest.set_output("exported_log_count", log_count)
        details = {"xlsx": str(analysis_input), "log_count": log_count}
        self.manifest.finish_stage(stage, "completed", details=details)
        self.events.emit(stage, "INFO", "stage_completed", "exported SIP logs", details)
        return analysis_input

    def export_firewall_blacklist(self) -> Path:
        stage = "export-firewall-blacklist"
        self.manifest.start_stage(stage)
        self.events.emit(stage, "INFO", "stage_started", "exporting firewall blacklist")
        command = export_firewall_blacklist_command(self.config.root_dir, self.config.paths.firewall_session_file, self.artifacts.blacklist_dir)
        result = run_subprocess(
            command,
            stdout_path=self.artifacts.logs_dir / "export-firewall-blacklist.stdout.log",
            stderr_path=self.artifacts.logs_dir / "export-firewall-blacklist.stderr.log",
        )
        if result.returncode != 0:
            self.manifest.finish_stage(stage, "failed", error=result.stderr or result.stdout)
            self.events.emit(stage, "ERROR", "stage_failed", "export firewall blacklist failed", {"returncode": result.returncode})
            raise RuntimeError(f"export-firewall-blacklist failed with exit code {result.returncode}")
        output = self.artifacts.blacklist_dir / "sangfor_firewall_blacklists.csv"
        self.manifest.set_output("firewall_blacklist", str(output))
        self.manifest.finish_stage(stage, "completed", details={"blacklist": str(output)})
        self.events.emit(stage, "INFO", "stage_completed", "exported firewall blacklist", {"blacklist": str(output)})
        return output

    def analyze(self, xlsx: Path | None = None, blacklist: Path | None = None, *, persist_history: bool = False) -> Path:
        stage = "analyze"
        xlsx = xlsx or prepare_analysis_input(self.artifacts.exports_dir)
        blacklist = blacklist or self.artifacts.blacklist_dir / "sangfor_firewall_blacklists.csv"
        self.manifest.start_stage(stage, {"xlsx": str(xlsx), "blacklist": str(blacklist), "persist_history": persist_history})
        self.events.emit(stage, "INFO", "stage_started", "running attacker analysis", {"xlsx": str(xlsx), "blacklist": str(blacklist), "persist_history": persist_history})
        command, cwd = analyze_command(self.config.root_dir, xlsx, blacklist, self.config.analysis.db_path, self.config.analysis.whitelist_file, self.artifacts.analysis_dir, persist_history=persist_history, stats_out=self.artifacts.analysis_dir / "stats.json")
        result = run_subprocess(
            command,
            cwd=cwd,
            stdout_path=self.artifacts.logs_dir / "analyze.stdout.log",
            stderr_path=self.artifacts.logs_dir / "analyze.stderr.log",
        )
        if result.returncode != 0:
            self.manifest.finish_stage(stage, "failed", error=result.stderr or result.stdout)
            self.events.emit(stage, "ERROR", "stage_failed", "attacker analysis failed", {"returncode": result.returncode})
            raise RuntimeError(f"analyze failed with exit code {result.returncode}")
        stats_path = self.artifacts.analysis_dir / "stats.json"
        if stats_path.exists():
            self.manifest.set_output("analysis_stats", str(stats_path))
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
        self.events.emit(stage, "INFO", "stage_started", "selecting block targets", {"recommendations": str(recommendations), "apply": apply})
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
            self.events.emit(stage, "ERROR", "stage_failed", "apply refused", {"reason": selection.apply_refusal})
            raise RuntimeError(f"apply refused: {selection.apply_refusal}")
        if apply and selection.targets:
            if not targets_path.read_text(encoding="utf-8").strip():
                self.manifest.finish_stage(stage, "failed", error="empty target file")
                self.events.emit(stage, "ERROR", "stage_failed", "apply refused", {"reason": "empty target file"})
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
                self.events.emit(stage, "ERROR", "stage_failed", "block apply failed", {"returncode": result.returncode})
                raise RuntimeError(f"block apply failed with exit code {result.returncode}")
        self.manifest.finish_stage(stage, "completed", details={"target_count": len(selection.targets), "apply": apply})
        self.events.emit(stage, "INFO", "stage_completed", "selected block targets", {"target_count": len(selection.targets), "apply": apply})
        return selection.targets

    def full(self, start: str, end: str, favorite_name: str | None, export_date: str | None, *, apply: bool = False, report: bool = True) -> None:
        self.events.emit("full", "INFO", "stage_started", "starting full pipeline", {"start": start, "end": end, "apply": apply})
        self.check_sessions()
        xlsx = self.export_logs(start, end, favorite_name, export_date)
        blacklist = self.export_firewall_blacklist()
        recommendations = self.analyze(xlsx, blacklist, persist_history=apply)
        self.block(recommendations, apply=False)
        if apply:
            self.block(recommendations, apply=True)
        md_path, json_path = write_daily_report(self.artifacts.run_dir, self.manifest.data, recommendations, log_window=(start, end))
        self.manifest.set_output("daily_report_md", str(md_path))
        self.manifest.set_output("daily_report_json", str(json_path))
        self.events.emit("full", "INFO", "stage_completed", "full pipeline completed", {"report": str(md_path), "report_json": str(json_path)})
        if report:
            print_console_report(self.artifacts.run_dir)

    def scheduled(self, job_name: str, *, apply: bool = False, report: bool = True) -> None:
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
        self.full(start, end, schedule.favorite_name, None, apply=effective_apply, report=report)
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
