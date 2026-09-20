#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import threading
from datetime import date, datetime, timedelta
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
    unblock_command,
    write_apply_result,
    write_block_artifacts,
    write_unblock_apply_result,
    write_unblock_artifacts,
)
from .config import PipelineConfig, schedule_window
from . import keepalive as keepalive_manager
from .merge_logs import merge_recent_logs
from .review import review_auto_blocked
from .reports import print_console_report, read_exported_log_count, write_daily_report
from .sessions import (
    MissingSessionError,
    check_firewall_session_health,
    check_sip_session_health,
    validate_firewall_session,
    validate_sip_session,
)
from .state import EventLogger, RunManifest
from .virus_servers import analyze as analyze_virus_export
from .virus_servers import load_export as load_virus_export
from .virus_servers import write_outputs as write_virus_outputs


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
    login.add_argument("--firewall-keepalive", action=argparse.BooleanOptionalAction, default=False,
                       help="旧行为：让防火墙登录脚本带 keepalive 前台常驻（会阻塞 login；推荐用默认的 --keepalive）")
    login.add_argument("--keepalive", action=argparse.BooleanOptionalAction, default=True,
                       help="登录成功后自动启动 detached 后台保活（默认开；--no-keepalive 关闭）")
    login.add_argument("--keepalive-interval", type=int, default=None,
                       help="保活刷新间隔秒数（默认用各脚本的 300s）")

    subparsers.add_parser("check-sessions")

    keepalive = subparsers.add_parser("keepalive", help="查看/停止登录后自动拉起的后台保活进程")
    keepalive.add_argument("--target", choices=("all", "sip", "firewall"), default="all")
    keepalive.add_argument("--stop", action="store_true", help="停止保活进程（默认只打印状态）")

    export_logs = subparsers.add_parser("export-logs")
    export_logs.add_argument("--start", required=True)
    export_logs.add_argument("--end", required=True)
    export_logs.add_argument("--favorite-name", default=None)
    export_logs.add_argument("--export-date", default=None)

    virus = subparsers.add_parser(
        "virus-servers",
        help="病毒日志：内网服务器 TOP N + 各自外联 IP（本地分析；缺导出文件时按收藏夹导出）",
    )
    virus.add_argument("--favorite-name", default=None, help="SIP 收藏夹名称（默认「病毒」）")
    virus.add_argument("--start", default=None)
    virus.add_argument("--end", default=None)
    virus.add_argument("--days", type=int, default=7, help="未给 --start/--end 时回溯的天数")
    virus.add_argument("--export-path", default=None, help="直接分析已有导出 xlsx（不接触设备）")
    virus.add_argument("--top", type=int, default=10, help="内网服务器取前 N（默认 10）")
    virus.add_argument("--top-peers", type=int, default=None, help="每台服务器最多列出多少个外联 IP")

    subparsers.add_parser("export-firewall-blacklist")

    merge_logs = subparsers.add_parser("merge-logs", help="合并近 N 天所有 run 导出的攻击日志（纯本地只读）")
    merge_logs.add_argument("--days", type=int, default=30, help="合并最近多少天的日志（默认 30）")
    merge_logs.add_argument("--output-dir", default=None, help="输出目录，默认 outputs/merged_logs")

    review = subparsers.add_parser("review", help="复查自动封禁黑名单 IP 近 N 天是否仍有攻击流量")
    review.add_argument("--mode", choices=("cached", "fresh"), default="cached", help="数据源模式；fresh 需解除封禁防火墙 API，暂未实现")
    review.add_argument("--days", type=int, default=30, help="检查近多少天的攻击流量（默认 30）")
    review.add_argument("--min-block-age", dest="min_block_age_days", type=int, default=30, help="封禁不满多少天不进入解除候选（默认 30）")
    review.add_argument("--whitelist", default=None, help="白名单文件路径，默认重载 config 里的 whitelist_file")
    review.add_argument("--output-dir", default=None, help="复查产物目录，默认 outputs/blacklist_review")

    analyze = subparsers.add_parser("analyze")
    analyze.add_argument("--xlsx")
    analyze.add_argument("--blacklist")

    block = subparsers.add_parser("block")
    block.add_argument("--recommendations")
    block.add_argument("--apply", action="store_true")
    block.add_argument("--manual-override-reason", help="Required audit reason when applying an explicit external recommendations file")

    unblock = subparsers.add_parser("unblock", help="解除封禁：从黑名单删除目标（dry-run 默认，--apply 才执行）")
    unblock.add_argument("--targets", required=True, help="待解除 IP 清单文件，每行一个 IP")
    unblock.add_argument("--apply", action="store_true", help="真正提交解除封禁（需防火墙会话健康）")

    firewall_phase = subparsers.add_parser(
        "firewall-phase",
        help="登录后短窗口内跑完防火墙相关阶段：黑名单导出 → 分析 → 封禁 → 日报（复用已有 SIP 导出）",
    )
    firewall_phase.add_argument("--apply", action="store_true", help="真正提交封禁；不加则只 dry-run")
    firewall_phase.add_argument("--report", action=argparse.BooleanOptionalAction, default=True, help="print a console summary after completion (default: enabled)")
    firewall_phase.add_argument("--xlsx", help="显式指定复用的 SIP 导出 xlsx（默认取本 run 记录，其次其他 run 最新导出）")

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
                keepalive_enabled=args.keepalive,
                keepalive_interval=args.keepalive_interval,
            )
        elif args.command == "check-sessions":
            runner.check_sessions()
        elif args.command == "keepalive":
            runner.keepalive_control(target=args.target, stop=args.stop)
        elif args.command == "export-logs":
            runner.export_logs(args.start, args.end, args.favorite_name, args.export_date)
        elif args.command == "virus-servers":
            runner.virus_servers(
                favorite_name=args.favorite_name,
                start=args.start,
                end=args.end,
                days=args.days,
                export_path=Path(args.export_path) if args.export_path else None,
                top=args.top,
                top_peers=args.top_peers,
            )
        elif args.command == "export-firewall-blacklist":
            runner.export_firewall_blacklist()
        elif args.command == "merge-logs":
            runner.merge_logs(days=args.days, output_dir=Path(args.output_dir) if args.output_dir else None)
        elif args.command == "review":
            runner.review(
                mode=args.mode,
                days=args.days,
                min_block_age_days=args.min_block_age_days,
                whitelist_file=Path(args.whitelist) if args.whitelist else None,
                output_dir=Path(args.output_dir) if args.output_dir else None,
            )
        elif args.command == "analyze":
            runner.analyze(Path(args.xlsx) if args.xlsx else None, Path(args.blacklist) if args.blacklist else None)
        elif args.command == "block":
            runner.block(Path(args.recommendations) if args.recommendations else None, apply=args.apply, manual_override_reason=args.manual_override_reason)
        elif args.command == "unblock":
            runner.unblock(Path(args.targets), apply=args.apply)
        elif args.command == "firewall-phase":
            runner.firewall_phase(apply=args.apply, report=args.report, xlsx=Path(args.xlsx) if args.xlsx else None)
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


# 实测防火墙会话空闲几分钟就会失效（2026-09-11：17:57 登录 → 18:05 已 302），
# 而 SIP 导出要 ~14 分钟，因此默认 120s 心跳一次；可用环境变量调。
DEFAULT_FIREWALL_KEEPALIVE_SECONDS = int(os.environ.get("SANGFOR_FIREWALL_KEEPALIVE_SECONDS", "120"))


def ping_firewall_session(session_file: Path, *, timeout: float = 30.0) -> tuple[bool, str]:
    """轻量刷新：带会话 Cookie 请求 /framework.php，200 且未跳登录页即视为有效。

    两个必须遵守的点（2026-09-11 踩过）：
    1. **禁止跟随重定向**：会话失效时设备回 302 → login.php，而登录页本身是 HTTP 200，
       跟随重定向会把失效判成健康（早期的心跳脚本就是这样给出假 200 的）。这里用自定义
       opener 让 302 直接抛 HTTPError。
    2. 不复用 ``firewall/firewall_keepalive.py``：它用 ``wait_until="networkidle"``，
       在防火墙控制台上会超时，且第一次失败就 return 1 退出，不适合长跑保活。

    每次读取最新的会话文件，因此期间手动刷新的 cookie 会被自动采用。
    """
    import ssl
    import urllib.error
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
            return None

    payload = json.loads(Path(session_file).read_text(encoding="utf-8"))
    base_url = str(payload["base_url"]).rstrip("/")
    request = urllib.request.Request(
        f"{base_url}/framework.php",
        headers={
            "Cookie": str(payload["cookie"]),
            "User-Agent": "sangfor-pipeline-keepalive/1.0",
            "Referer": f"{base_url}/framework.php",
            "Accept": "text/html,*/*",
        },
    )
    opener = urllib.request.build_opener(
        _NoRedirect,
        urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(400).decode("utf-8", "replace")
            healthy = response.status == 200 and "login.php" not in body
            return healthy, f"HTTP {response.status}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001 - caller decides; keepalive must not raise
        return False, f"{type(exc).__name__}: {exc}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def latest_export_xlsx(runs_dir: Path, *, exclude_run: Path | None = None) -> Path | None:
    """在 runs/*/exports 里找最新的 SIP 导出文件（跨 run 复用已导出数据）。"""
    candidates = [p for p in Path(runs_dir).glob("*/exports/*.xlsx") if not p.name.startswith(".")]
    if exclude_run is not None:
        excluded = Path(exclude_run).resolve()
        candidates = [p for p in candidates if excluded not in p.resolve().parents]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


class FirewallKeepalive:
    """后台线程周期性刷新防火墙会话，避免长阶段（如 80k 行的 SIP 导出约 14 分钟）期间空闲超时。

    - 用 ``ping_firewall_session``（urllib 轻量 GET），不起浏览器；
    - 单次失败只回调事件、不退出循环；会话真失效由阶段守卫（``_require_healthy_firewall``）报告；
    - 重复 start 不重复起线程，stop 幂等。
    """

    def __init__(
        self,
        session_file: Path,
        *,
        interval: int = DEFAULT_FIREWALL_KEEPALIVE_SECONDS,
        ping=None,
        on_event=None,
    ) -> None:
        self.session_file = Path(session_file)
        self.interval = max(0.05, float(interval))
        self._ping = ping or (lambda: ping_firewall_session(self.session_file))
        self._on_event = on_event
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="firewall-keepalive", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=10)

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                healthy, detail = self._ping()
            except Exception as exc:  # noqa: BLE001 - 保活线程绝不能把整条 run 带崩
                healthy, detail = False, f"{type(exc).__name__}: {exc}"
            if self._on_event is not None:
                self._on_event(healthy, detail)

    def __enter__(self) -> "FirewallKeepalive":
        self.start()
        return self

    def __exit__(self, *exc_info) -> bool:
        self.stop()
        return False


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
        keepalive_enabled: bool = True,
        keepalive_interval: int | None = None,
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
            if keepalive_enabled and not (item == "firewall" and firewall_keepalive):
                self._start_keepalive(item, interval=keepalive_interval)
        self.manifest.finish_stage(stage, "completed", details={"target": target})

    def _start_keepalive(self, target: str, *, interval: int | None = None) -> dict:
        """登录成功后自动把该目标的保活拉成独立后台进程。

        为什么是独立进程而不是前台常驻：`sangfor_firewall_login_session.py --keepalive` 会让
        `login` 一直不返回（subprocess.run 无超时）；detached 进程登录完就能继续干活、
        需要时用 `keepalive --stop` 收掉。保活失败只告警，不影响登录结果本身。
        """
        session_file = (
            self.config.paths.sip_session_file if target == "sip" else self.config.paths.firewall_session_file
        )
        try:
            info = keepalive_manager.start(
                target,
                root_dir=self.config.root_dir,
                session_file=session_file,
                logs_dir=Path(self.config.root_dir) / "logs",
                state_dir=self.config.paths.state_dir,
                interval=interval,
            )
        except Exception as exc:  # noqa: BLE001 - 保活失败不应让登录阶段失败
            self.events.emit("login", "WARNING", "keepalive_start_failed", f"{target} keepalive not started: {exc}")
            print(f"[login] {target} 保活未启动：{exc}")
            return {"target": target, "started": False, "error": str(exc)}
        if info.get("started"):
            self.events.emit("login", "INFO", "keepalive_started", f"{target} keepalive started",
                             {"pid": info.get("pid"), "log": info.get("log")})
            print(f"[login] {target} 保活已启动：pid={info.get('pid')}，日志 {info.get('log')}")
        else:
            print(f"[login] {target} 保活已在运行：pid={info.get('pid')}（{info.get('reason', '')}）")
        return info

    def keepalive_control(self, *, target: str = "all", stop: bool = False) -> None:
        """查看/停止登录后自动拉起的保活进程。"""
        stage = "keepalive"
        targets = list(keepalive_manager.TARGETS) if target == "all" else [target]
        self.manifest.start_stage(stage, {"target": target, "stop": stop})
        self.events.emit(stage, "INFO", "stage_started", "keepalive control", {"target": target, "stop": stop})
        results: list[dict] = []
        try:
            for item in targets:
                if stop:
                    info = keepalive_manager.stop(item, state_dir=self.config.paths.state_dir)
                    print(f"[keepalive] {item}: {'已停止' if info.get('stopped') else '未在运行'}（pid={info.get('pid')}）")
                else:
                    info = keepalive_manager.status(item, state_dir=self.config.paths.state_dir)
                    print(f"[keepalive] {item}: {'运行中' if info.get('running') else '未运行'} "
                          f"pid={info.get('pid')} 日志={info.get('log')}")
                results.append(info)
            self.manifest.finish_stage(stage, "completed", details={"results": results})
            self.events.emit(stage, "INFO", "stage_completed", "keepalive control done", {"results": results})
        except Exception as exc:  # noqa: BLE001 - 阶段失败照常记录并抛出
            self.manifest.finish_stage(stage, "failed", error=exc)
            raise

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

    def virus_servers(
        self,
        *,
        favorite_name: str | None = None,
        start: str | None = None,
        end: str | None = None,
        days: int = 7,
        export_path: Path | None = None,
        top: int = 10,
        top_peers: int | None = None,
    ) -> Path:
        """病毒日志 → 内网服务器 TOP N + 各自外联 IP。

        未给 `export_path` 时按收藏夹导出（需要健康的 SIP 会话）；给了 `export_path` 则纯本地分析，
        便于把「导出」与「分析」两个阶段拆开单独跑。
        """
        stage = "virus-servers"
        fav = favorite_name or "病毒"
        self.manifest.start_stage(stage, {
            "favorite_name": fav,
            "start": start,
            "end": end,
            "days": days,
            "export_path": str(export_path) if export_path else None,
            "top": top,
        })
        try:
            if export_path is None:
                now = datetime.now()
                s = start or (now - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
                e = end or now.strftime("%Y-%m-%d %H:%M:%S")
                self.events.emit(stage, "INFO", "stage_started", "exporting virus favorite logs",
                                 {"favorite_name": fav, "start": s, "end": e})
                xlsx = self.export_logs(s, e, fav, None)
            else:
                xlsx = Path(export_path)
            meta, rows = load_virus_export(xlsx)
            report = analyze_virus_export(rows, top=top, top_peers=top_peers)
            paths = write_virus_outputs(self.artifacts.run_dir / "virus", meta, report)
            details = {
                "export": str(xlsx),
                "favorite_name": fav,
                "query_string": meta.query_string,
                "rows": report["rows_total"],
                "servers": report["servers_total"],
                "top": top,
                "artifacts": paths,
            }
            self.manifest.set_output("virus_report", paths["json"])
            self.manifest.finish_stage(stage, "completed", details=details)
            self.events.emit(stage, "INFO", "stage_completed", "virus servers analyzed", details)
            print(f"[virus] 内网主机 {report['servers_total']} 台，参与明细 {report['rows_with_internal']} 行；TOP {top}：")
            for srv in report["servers"]:
                peers = "、".join(p["ip"] for p in srv["external_peers"][:5]) or "（无外联）"
                print(f"  #{srv['rank']} {srv['ip']}  {srv['events']} 条  {srv['direction']}  外联: {peers}")
            print(f"[virus] 报告: {paths['markdown']}")
            return self.artifacts.run_dir / "virus"
        except Exception as exc:
            self.manifest.finish_stage(stage, "failed", error=exc)
            self.events.emit(stage, "ERROR", "stage_failed", str(exc), {"error_type": type(exc).__name__})
            raise

    def _resolve_export_input(self, explicit: Path | None = None) -> Path:
        """确定分析要用的 SIP 导出文件：显式指定 > 本 run 记录/本 run exports 目录 > 其他 run 最新导出。

        防火墙会话是硬性 TTL、SIP 导出又要十几分钟，所以「导出」和「封禁」必须分两次跑；
        第二阶段得能复用已落盘的导出，而不是再导一遍。
        """
        if explicit is not None:
            if not Path(explicit).exists():
                raise FileNotFoundError(f"指定复用的 SIP 导出不存在: {explicit}")
            return Path(explicit)
        recorded = (self.manifest.data.get("outputs") or {}).get("analysis_input_xlsx")
        if recorded and Path(recorded).exists():
            self.events.emit("full", "INFO", "export_reused", "reusing this run's SIP export", {"xlsx": str(recorded)})
            return Path(recorded)
        try:
            existing = prepare_analysis_input(self.artifacts.exports_dir)
        except Exception:  # noqa: BLE001 - 本 run 还没有导出时退到跨 run 兜底
            existing = None
        if existing is not None and Path(existing).exists():
            self.events.emit("full", "INFO", "export_reused", "reusing this run's SIP export", {"xlsx": str(existing)})
            return Path(existing)
        fallback = latest_export_xlsx(self.config.paths.runs_dir, exclude_run=self.artifacts.run_dir)
        if fallback is None:
            raise FileNotFoundError(
                "没有可复用的 SIP 导出：请先跑 export-logs（或 full）把日志导出落盘，再执行 firewall-phase"
            )
        self.events.emit(
            "full",
            "WARNING",
            "export_reused",
            "reusing SIP export from another run",
            {"xlsx": str(fallback), "source_run": fallback.parent.parent.name},
        )
        return fallback

    def firewall_phase(self, *, apply: bool = False, report: bool = True, xlsx: Path | None = None) -> None:
        """登录后的短窗口内跑完所有依赖防火墙的阶段：黑名单导出 → 分析 → 封禁 → 日报。

        为什么要单独拆出来：防火墙会话实测是**硬性 TTL（约 12 分钟，活动不延长）**，而 SIP
        导出约 14 分钟 —— `full` 一步式跑到 apply 时会话必然已失效。推荐用法：

            1) `export-logs`（或 `full`：数据落盘即可，它会在 apply 守卫处停下并说明原因）
            2) `login --target firewall` 刷新会话
            3) 立刻 `firewall-phase --apply`（几秒到几分钟内跑完）
        """
        stage = "firewall-phase"
        self.manifest.start_stage(stage, {"apply": apply, "xlsx": str(xlsx) if xlsx else None})
        self.events.emit(stage, "INFO", "stage_started", "starting firewall phase", {"apply": apply})
        try:
            self._require_healthy_firewall(stage)  # 早失败，别让后面的阶段白跑
            analysis_input = self._resolve_export_input(xlsx)
            keepalive = FirewallKeepalive(self.config.paths.firewall_session_file)
            keepalive.start()
            self.events.emit(
                stage,
                "INFO",
                "keepalive_started",
                "firewall session keepalive running",
                {"interval_seconds": DEFAULT_FIREWALL_KEEPALIVE_SECONDS},
            )
            try:
                blacklist = self.export_firewall_blacklist()
                recommendations = self.analyze(analysis_input, blacklist, persist_history=apply)
                self.block(recommendations, apply=False)
                if apply:
                    self.block(recommendations, apply=True)
                md_path, json_path = write_daily_report(self.artifacts.run_dir, self.manifest.data, recommendations)
                self.manifest.set_output("daily_report_md", str(md_path))
                self.manifest.set_output("daily_report_json", str(json_path))
            finally:
                keepalive.stop()
                self.events.emit(stage, "INFO", "keepalive_stopped", "firewall session keepalive stopped")
            details = {"apply": apply, "xlsx": str(analysis_input)}
            self.manifest.finish_stage(stage, "completed", details=details)
            self.events.emit(stage, "INFO", "stage_completed", "firewall phase completed", details)
        except Exception as exc:
            self.manifest.finish_stage(stage, "failed", error=exc)
            self.events.emit(stage, "ERROR", "stage_failed", str(exc), {"error_type": type(exc).__name__})
            raise
        if report:
            print_console_report(self.artifacts.run_dir)

    def _require_healthy_firewall(self, stage: str) -> dict:
        """阶段开始前确认防火墙会话可用，失效时给出可执行的刷新指引。

        会话空闲超时后设备会把 /framework.php 重定向到 login.php，导黑名单接口只会回
        HTTP 400 request error —— 与其让调用方猜，不如在这里提前失败并说明怎么修。
        """
        health = check_firewall_session_health(self.config.paths.firewall_session_file)
        self._write_status("firewall_session.status.json", health, str(self.config.paths.firewall_session_file))
        if not health.get("healthy"):
            hint = "（/framework.php 已跳转登录页，会话说失效）" if health.get("login_page") else ""
            raise MissingSessionError(
                f"{stage} 需要健康的防火墙会话{hint}，当前状态 {health.get('status')}；"
                "请在浏览器中登录防火墙控制台后，从 devtools 抓取 Cookie 头与 _cftoken 请求头，"
                f"写回 {self.config.paths.firewall_session_file} 的 cookie 与 csrf._cftoken 后重跑该阶段"
            )
        return health

    def export_firewall_blacklist(self) -> Path:
        stage = "export-firewall-blacklist"
        self.manifest.start_stage(stage)
        self.events.emit(stage, "INFO", "stage_started", "exporting firewall blacklist")
        try:
            self._require_healthy_firewall(stage)
        except MissingSessionError as exc:
            self.manifest.finish_stage(stage, "failed", error=exc)
            self.events.emit(stage, "ERROR", "stage_failed", str(exc))
            raise
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

    def merge_logs(self, *, days: int = 30, output_dir: Path | None = None) -> dict:
        """合并近 N 天所有 run 导出的攻击日志（纯本地只读，不访问设备）。"""
        stage = "merge-logs"
        self.manifest.start_stage(stage, {"days": days})
        self.events.emit(stage, "INFO", "stage_started", "merging recent exported logs", {"days": days})
        try:
            coverage = merge_recent_logs(self.config.paths.runs_dir, output_dir, days=days)
        except Exception as exc:
            self.manifest.finish_stage(stage, "failed", error=exc)
            self.events.emit(stage, "ERROR", "stage_failed", str(exc))
            raise
        self.manifest.set_output("merged_logs_coverage", coverage.get("outputs", {}).get("coverage_json"))
        self.manifest.set_output("merged_logs_csv", coverage.get("outputs", {}).get("merged_csv"))
        details = {
            "days": days,
            "total_rows": coverage.get("total_rows"),
            "unique_source_ips": coverage.get("unique_source_ips"),
            "runs_used": len(coverage.get("runs_used") or []),
            "coverage": coverage.get("outputs", {}).get("coverage_json"),
        }
        self.manifest.finish_stage(stage, "completed", details=details)
        self.events.emit(stage, "INFO", "stage_completed", "merged recent exported logs", details)
        return coverage

    def review(
        self,
        *,
        mode: str = "cached",
        days: int = 30,
        min_block_age_days: int = 30,
        whitelist_file: Path | None = None,
        output_dir: Path | None = None,
    ) -> dict:
        """复查自动封禁黑名单 IP 近 N 天是否仍有攻击流量。

        cached 模式复用已导出的日志与最近黑名单；fresh 需解除封禁防火墙 API，未实现。
        """
        stage = "review"
        if mode == "fresh":
            self.events.emit(stage, "INFO", "stage_started", "review fresh mode requested", {"mode": mode})
            error = "fresh 模式需要解除封禁的防火墙 API，尚未实现（当前仅支持 --mode cached）"
            self.manifest.finish_stage(stage, "failed", error=error)
            raise NotImplementedError(error)
        self.manifest.start_stage(stage, {"mode": mode, "days": days, "min_block_age_days": min_block_age_days})
        self.events.emit(stage, "INFO", "stage_started", "reviewing auto-blocked blacklist IPs", {"mode": mode, "days": days})
        whitelist = whitelist_file or Path(self.config.analysis.whitelist_file)
        output = output_dir or self.config.paths.outputs_dir / "blacklist_review"
        try:
            summary = review_auto_blocked(
                self.config.paths.runs_dir,
                days=days,
                min_block_age_days=min_block_age_days,
                whitelist_file=whitelist,
                output_dir=output,
            )
        except Exception as exc:
            self.manifest.finish_stage(stage, "failed", error=exc)
            self.events.emit(stage, "ERROR", "stage_failed", str(exc))
            raise
        details = {
            "mode": summary["mode"],
            "candidates_count": summary["candidates_count"],
            "still_active_count": summary["still_active_count"],
            "whitelisted_ips": summary["whitelisted_ips"],
            "blocked_too_recent_count": summary["blocked_too_recent_count"],
            "report": summary["outputs"]["report_json"],
        }
        self.manifest.finish_stage(stage, "completed", details=details)
        self.events.emit(stage, "INFO", "stage_completed", "review completed", details)
        return summary

    def _record_analysis_input(self, xlsx: Path) -> None:
        """把分析用的 SIP 导出记进 manifest（路径 + sha256 + 字节数），供 apply 守卫审计。

        `firewall-phase` 允许复用别的 run 已导出的数据，守卫据此确认「推荐结论有可追溯的
        数据来源」，而不是凭空生成。
        """
        entry: dict[str, object] = {"path": str(xlsx)}
        try:
            entry["sha256"] = sha256_file(xlsx)
            entry["bytes"] = Path(xlsx).stat().st_size
        except OSError:
            pass
        self.manifest.data.setdefault("inputs", {})["sip_xlsx"] = entry
        self.manifest.write()

    def analyze(self, xlsx: Path | None = None, blacklist: Path | None = None, *, persist_history: bool = False) -> Path:
        stage = "analyze"
        xlsx = xlsx or prepare_analysis_input(self.artifacts.exports_dir)
        blacklist = blacklist or self.artifacts.blacklist_dir / "sangfor_firewall_blacklists.csv"
        self._record_analysis_input(xlsx)
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

    def unblock(self, targets_file: Path, *, apply: bool = False) -> list[str]:
        """解除封禁：从黑名单删除指定 IP（dry-run 默认，--apply 才真正执行）。"""
        stage = "unblock"
        self.manifest.start_stage(stage, {"targets_file": str(targets_file), "apply": apply})
        self.events.emit(stage, "INFO", "stage_started", "preparing unblock targets", {"targets_file": str(targets_file), "apply": apply})

        targets = [line.strip() for line in targets_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not targets:
            error = f"targets 文件为空或不可读: {targets_file}"
            self.manifest.finish_stage(stage, "failed", error=error)
            raise ValueError(error)
        targets = list(dict.fromkeys(targets))  # 去重保序

        unblock_dir = self.artifacts.run_dir / "unblock"
        if apply:
            firewall_health = check_firewall_session_health(self.config.paths.firewall_session_file)
            self._write_status("firewall_session.status.json", firewall_health, str(self.config.paths.firewall_session_file))
            if not firewall_health.get("healthy"):
                self.manifest.finish_stage(stage, "failed", error="unblock apply requires healthy firewall session")
                raise RuntimeError("unblock apply requires healthy firewall session")
        targets_path, dry_run_path = write_unblock_artifacts(targets, unblock_dir, apply=apply)
        self.manifest.set_output("unblock_targets", str(targets_path))
        self.manifest.set_output("unblock_dry_run", str(dry_run_path))

        apply_result_path = write_unblock_apply_result(targets, unblock_dir, executed=False)
        self.manifest.set_output("unblock_apply_result", str(apply_result_path))
        if apply:
            command = unblock_command(self.config.root_dir, self.config.paths.firewall_session_file, targets_path, apply=True)
            result = run_subprocess(
                command,
                stdout_path=self.artifacts.logs_dir / "unblock.stdout.log",
                stderr_path=self.artifacts.logs_dir / "unblock.stderr.log",
            )
            apply_result_path = write_unblock_apply_result(targets, unblock_dir, executed=result.returncode == 0, command_result=result)
            self.manifest.set_output("unblock_apply_result", str(apply_result_path))
            if result.returncode != 0:
                self.manifest.finish_stage(stage, "failed", error=result.stderr or result.stdout)
                self.events.emit(stage, "ERROR", "stage_failed", "unblock apply failed", {"returncode": result.returncode})
                raise RuntimeError(f"unblock apply failed with exit code {result.returncode}")
        self.manifest.finish_stage(stage, "completed", details={"target_count": len(targets), "apply": apply})
        self.events.emit(stage, "INFO", "stage_completed", "unblock stage completed", {"target_count": len(targets), "apply": apply})
        return targets

    def full(self, start: str, end: str, favorite_name: str | None, export_date: str | None, *, apply: bool = False, report: bool = True) -> None:
        self.events.emit("full", "INFO", "stage_started", "starting full pipeline", {"start": start, "end": end, "apply": apply})
        self.check_sessions()
        keepalive = FirewallKeepalive(
            self.config.paths.firewall_session_file,
            on_event=lambda healthy, detail: self.events.emit(
                "full",
                "INFO" if healthy else "WARNING",
                "keepalive_ping",
                "firewall session keepalive refreshed" if healthy else "firewall session keepalive failed",
                {"healthy": healthy, "detail": detail},
            ),
        )
        keepalive.start()
        self.events.emit(
            "full",
            "INFO",
            "keepalive_started",
            "firewall session keepalive running",
            {"interval_seconds": DEFAULT_FIREWALL_KEEPALIVE_SECONDS},
        )
        try:
            # 防火墙黑名单导出只需刚校验过的会话、耗时可忽略，因此排在 SIP 长导出之前；
            # SIP 导出（80k 行约 14 分钟）放后面，避免防火墙会话在导出期间空闲超时。
            blacklist = self.export_firewall_blacklist()
            xlsx = self.export_logs(start, end, favorite_name, export_date)
            recommendations = self.analyze(xlsx, blacklist, persist_history=apply)
            self.block(recommendations, apply=False)
            if apply:
                self.block(recommendations, apply=True)
            md_path, json_path = write_daily_report(self.artifacts.run_dir, self.manifest.data, recommendations, log_window=(start, end))
            self.manifest.set_output("daily_report_md", str(md_path))
            self.manifest.set_output("daily_report_json", str(json_path))
            self.events.emit("full", "INFO", "stage_completed", "full pipeline completed", {"report": str(md_path), "report_json": str(json_path)})
        finally:
            keepalive.stop()
            self.events.emit("full", "INFO", "keepalive_stopped", "firewall session keepalive stopped")
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
            raise ApplyGuardError(
                "apply requires a healthy firewall session "
                f"(status {firewall_health.get('status')}, login_page={bool(firewall_health.get('login_page'))}); "
                "刷新会话文件中的 cookie 与 csrf._cftoken 后重跑 export-firewall-blacklist → analyze → block"
            )
        run_path = self.artifacts.run_dir.resolve()
        rec_path = Path(recommendations).resolve()
        external_recommendations = explicit_recommendations and run_path not in rec_path.parents
        if not external_recommendations:
            # 允许 firewall-phase 复用已导出数据：只要本 run 的 analyze 记录了所用导出的
            # sha256（inputs.sip_xlsx），就不强制本 run 自己跑过 export-logs。
            sip_input = (self.manifest.data.get("inputs") or {}).get("sip_xlsx") or {}
            required_stages = ["export-firewall-blacklist", "analyze"]
            if not sip_input.get("sha256"):
                required_stages.insert(0, "export-logs")
            for required_stage in required_stages:
                stage_data = self.manifest.data.get("stages", {}).get(required_stage, {})
                if stage_data.get("status") != "completed":
                    hint = "（或改用 firewall-phase 复用已导出数据）" if required_stage == "export-logs" else ""
                    raise ApplyGuardError(f"apply requires completed same-run {required_stage}{hint}")
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
