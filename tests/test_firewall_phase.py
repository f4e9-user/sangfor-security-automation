"""`firewall-phase`：把依赖防火墙的阶段从长导出里拆出来，登录后短窗口内单独跑完。

背景：防火墙会话实测是硬性 TTL（约 12 分钟，活动不延长），SIP 导出约 14 分钟，
`full --apply` 一步式跑到 apply 时会话必然失效。所以导出与封禁必须能分两次执行，
且第二次要能复用上一次落盘的导出（并在 manifest 里留下 sha256 供守卫审计）。
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from pipeline import run_pipeline as rp
from pipeline.sessions import MissingSessionError
from pipeline.state import EventLogger, RunManifest


class RecordingKeepalive:
    instances: list["RecordingKeepalive"] = []

    def __init__(self, *args, **kwargs):
        self.started = self.stopped = False
        RecordingKeepalive.instances.append(self)

    @property
    def running(self) -> bool:
        return self.started and not self.stopped

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True


@pytest.fixture(autouse=True)
def _reset_keepalive() -> None:
    RecordingKeepalive.instances = []
    yield
    RecordingKeepalive.instances = []


def _make_runner(tmp_path: Path, calls: list, monkeypatch, *, healthy: bool = True) -> rp.PipelineRunner:
    run_dir = tmp_path / "runs" / "20260101_000000"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "logs").mkdir(exist_ok=True)
    (run_dir / "exports").mkdir(exist_ok=True)
    (run_dir / "analysis").mkdir(exist_ok=True)
    artifacts = SimpleNamespace(
        run_id="20260101_000000",
        run_dir=run_dir,
        exports_dir=run_dir / "exports",
        analysis_dir=run_dir / "analysis",
        blacklist_dir=run_dir / "blacklist",
        logs_dir=run_dir / "logs",
    )
    config = SimpleNamespace(
        root_dir=tmp_path,
        analysis=SimpleNamespace(db_path=tmp_path / "state" / "analysis.db", whitelist_file=tmp_path / "secrets" / "whitelist.txt"),
        paths=SimpleNamespace(
            runs_dir=tmp_path / "runs",
            state_dir=tmp_path / "state",
            firewall_session_file=tmp_path / "secrets" / "firewall_session.json",
            sip_session_file=tmp_path / "secrets" / "sip_session.json",
        ),
    )
    manifest = RunManifest(run_dir, artifacts.run_id, {"command": "firewall-phase"})
    events = EventLogger(run_dir, artifacts.run_id)
    runner = rp.PipelineRunner(config, artifacts, manifest, events)
    monkeypatch.setattr(rp, "FirewallKeepalive", RecordingKeepalive)
    monkeypatch.setattr(rp, "print_console_report", lambda *a, **k: calls.append(("report-printed", None)))
    monkeypatch.setattr(rp, "write_daily_report", lambda *a, **k: (run_dir / "reports" / "d.md", run_dir / "reports" / "d.json"))
    monkeypatch.setattr(rp, "check_firewall_session_health", lambda path: {"healthy": healthy, "status": 200 if healthy else 302, "login_page": not healthy})
    monkeypatch.setattr(rp, "validate_sip_session", lambda path: None)
    monkeypatch.setattr(rp, "validate_firewall_session", lambda path: None)
    monkeypatch.setattr(rp, "check_sip_session_health", lambda path: {"healthy": True, "status": 200})
    monkeypatch.setattr(runner, "export_firewall_blacklist", lambda: (calls.append(("export-firewall-blacklist", None)), run_dir / "blacklist" / "b.csv")[1])
    monkeypatch.setattr(runner, "analyze", lambda xlsx, blacklist=None, *, persist_history=False: (calls.append(("analyze", str(xlsx))), run_dir / "analysis" / "blocklist_recommendations.normalized.csv")[1])
    monkeypatch.setattr(runner, "block", lambda recs, *, apply=False, manual_override_reason=None: calls.append(("block", apply)) or ["1.1.1.1"])
    return runner


def test_firewall_phase_orders_stages_and_reuses_export(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    runner = _make_runner(tmp_path, calls, monkeypatch)
    exported = runner.artifacts.exports_dir / "sangfor-sip-report.xlsx"
    exported.write_bytes(b"fake-xlsx")
    runner.manifest.data["outputs"]["analysis_input_xlsx"] = str(exported)

    runner.firewall_phase(apply=True, report=True)

    assert [c[0] for c in calls] == ["export-firewall-blacklist", "analyze", "block", "block", "report-printed"]
    assert calls[1][1] == str(exported)  # 复用了已导出的数据
    assert calls[2][1] is False and calls[3][1] is True  # 先 dry-run 再 apply
    keepalive = RecordingKeepalive.instances[0]
    assert keepalive.started and keepalive.stopped
    assert runner.manifest.data["stages"]["firewall-phase"]["status"] == "completed"


def test_firewall_phase_fails_fast_when_session_unhealthy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    runner = _make_runner(tmp_path, calls, monkeypatch, healthy=False)
    monkeypatch.setattr(runner, "_write_status", lambda *a, **k: None)

    with pytest.raises(MissingSessionError) as excinfo:
        runner.firewall_phase(apply=True, report=True)

    assert calls == []  # 会话不健康时一个阶段都不许跑
    assert "_cftoken" in str(excinfo.value)
    assert runner.manifest.data["stages"]["firewall-phase"]["status"] == "failed"


def test_resolve_export_input_prefers_run_record_then_latest_other_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    runner = _make_runner(tmp_path, calls, monkeypatch)

    other_run = tmp_path / "runs" / "20260102_000000" / "exports"
    other_run.mkdir(parents=True)
    other = other_run / "sangfor-sip-report-other.xlsx"
    other.write_bytes(b"other")

    # 本 run 没有导出记录、exports 目录为空 → 退到其他 run 的最新导出，并留 WARNING 事件
    resolved = runner._resolve_export_input()
    assert resolved == other
    events = [json.loads(line) for line in (runner.artifacts.run_dir / "logs" / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert any(e["event"] == "export_reused" and e["level"] == "WARNING" for e in events)

    # 本 run 有记录时优先用本 run 的
    recorded = runner.artifacts.exports_dir / "own.xlsx"
    recorded.write_bytes(b"own")
    runner.manifest.data["outputs"]["analysis_input_xlsx"] = str(recorded)
    assert runner._resolve_export_input() == recorded

    # 显式指定优先
    assert runner._resolve_export_input(other) == other
    with pytest.raises(FileNotFoundError):
        runner._resolve_export_input(tmp_path / "nope.xlsx")


def test_apply_guard_accepts_recorded_reused_export(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    runner = _make_runner(tmp_path, calls, monkeypatch)
    for stage in ("export-firewall-blacklist", "analyze"):
        runner.manifest.start_stage(stage)
        runner.manifest.finish_stage(stage, "completed")
    runner.manifest.data["inputs"]["sip_xlsx"] = {"path": "/tmp/x.xlsx", "sha256": "a" * 64}

    normalized = runner.artifacts.analysis_dir / "blocklist_recommendations.normalized.csv"
    normalized.write_text("ip,recommend\n1.1.1.1,block\n", encoding="utf-8")

    runner._check_apply_prerequisites(normalized, explicit_recommendations=False)  # 不抛异常即通过


def test_apply_guard_still_requires_export_logs_without_recorded_input(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    runner = _make_runner(tmp_path, calls, monkeypatch)
    for stage in ("export-firewall-blacklist", "analyze"):
        runner.manifest.start_stage(stage)
        runner.manifest.finish_stage(stage, "completed")
    normalized = runner.artifacts.analysis_dir / "blocklist_recommendations.normalized.csv"
    normalized.write_text("ip,recommend\n1.1.1.1,block\n", encoding="utf-8")

    with pytest.raises(rp.ApplyGuardError) as excinfo:
        runner._check_apply_prerequisites(normalized, explicit_recommendations=False)
    assert "export-logs" in str(excinfo.value) and "firewall-phase" in str(excinfo.value)


def test_analyze_records_export_hash_in_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    runner = _make_runner(tmp_path, calls, monkeypatch)
    # 用真实 analyze（helper 里被替换成 stub 了），只打桩它调用的外部命令
    runner.analyze = rp.PipelineRunner.analyze.__get__(runner)
    xlsx = runner.artifacts.exports_dir / "sip.xlsx"
    xlsx.write_bytes(b"payload")
    monkeypatch.setattr(rp, "run_subprocess", lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(rp, "copy_analyzer_output", lambda *a, **k: runner.artifacts.analysis_dir / "raw.csv")
    monkeypatch.setattr(rp, "normalize_recommendations", lambda *a, **k: None)
    monkeypatch.setattr(rp, "analyze_command", lambda *a, **k: (["true"], tmp_path))

    runner.analyze(xlsx, runner.artifacts.blacklist_dir / "b.csv")

    entry = runner.manifest.data["inputs"]["sip_xlsx"]
    assert entry["path"] == str(xlsx)
    assert entry["sha256"] == rp.sha256_file(xlsx)
    assert entry["bytes"] == 7
