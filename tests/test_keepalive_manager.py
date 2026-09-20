"""登录后自动保活（`pipeline/keepalive.py` + `login` 接线）的回归测试。

背景：文档要求 SIP 用 HTTP keepalive、防火墙用 headless Chromium 每 5 分钟刷 `/framework.php`；
本次改造让 `login` 成功后**自动**把保活拉成 detached 后台进程（`--no-keepalive` 可关），
并新增 `keepalive` 子命令查看/停止。这里覆盖命令构造、PID 生命周期、以及 login 的接线。
"""
from __future__ import annotations

import json
import signal
from pathlib import Path
from types import SimpleNamespace

import pytest

import pipeline.keepalive as kv
import pipeline.run_pipeline as rp
from pipeline.state import EventLogger, RunManifest


# ---------------------------------------------------------------- manager 单测

def test_build_command_per_target(tmp_path: Path) -> None:
    sip = kv.build_command("sip", root_dir=tmp_path, session_file=tmp_path / "s.json", status_file=tmp_path / "st.json")
    fw = kv.build_command("firewall", root_dir=tmp_path, session_file=tmp_path / "s.json", status_file=tmp_path / "st.json", interval=600)
    assert sip[1].endswith("situation-awareness/sangfor_sip_cookie_keepalive.py")
    assert fw[1].endswith("firewall/firewall_keepalive.py")
    assert "--session-file" in sip and "--status-file" in sip and "--interval" in sip
    assert fw[fw.index("--interval") + 1] == "600"
    assert "--insecure" in sip and "--insecure" in fw
    with pytest.raises(ValueError):
        kv.build_command("nope", root_dir=tmp_path, session_file=tmp_path / "s.json", status_file=tmp_path / "st.json")


class FakeProcess:
    def __init__(self, pid: int) -> None:
        self.pid = pid


def _make_session(tmp_path: Path) -> Path:
    path = tmp_path / "secrets" / "firewall_session.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"base_url": "https://fw.local", "cookie": "a=1"}), encoding="utf-8")
    return path


def test_start_spawns_and_writes_pid_file(tmp_path: Path) -> None:
    session = _make_session(tmp_path)
    spawned: list[list[str]] = []

    def spawn(command, *, cwd, log_path, env):
        spawned.append(command)
        return FakeProcess(4242)

    info = kv.start("firewall", root_dir=tmp_path, session_file=session, logs_dir=tmp_path / "logs",
                    state_dir=tmp_path / "state", spawn_fn=spawn, pid_alive_fn=lambda pid: True)
    assert info["started"] is True and info["pid"] == 4242
    record = json.loads((tmp_path / "state" / "keepalive-firewall.pid").read_text(encoding="utf-8"))
    assert record["pid"] == 4242 and record["target"] == "firewall"
    assert spawned and spawned[0][1].endswith("firewall/firewall_keepalive.py")
    assert info["log"].endswith("logs/keepalive-firewall.log")


def test_start_is_idempotent_when_already_running(tmp_path: Path) -> None:
    session = _make_session(tmp_path)
    calls: list = []
    kv.start("sip", root_dir=tmp_path, session_file=session, logs_dir=tmp_path / "logs",
             state_dir=tmp_path / "state", spawn_fn=lambda *a, **k: (calls.append(1), FakeProcess(11))[1],
             pid_alive_fn=lambda pid: True)
    again = kv.start("sip", root_dir=tmp_path, session_file=session, logs_dir=tmp_path / "logs",
                     state_dir=tmp_path / "state", spawn_fn=lambda *a, **k: (calls.append(2), FakeProcess(12))[1],
                     pid_alive_fn=lambda pid: True)
    assert again["started"] is False and again["reason"] == "already running"
    assert calls == [1]  # 第二次没有再次 spawn


def test_start_requires_session_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        kv.start("firewall", root_dir=tmp_path, session_file=tmp_path / "missing.json",
                 logs_dir=tmp_path / "logs", state_dir=tmp_path / "state", spawn_fn=lambda *a, **k: FakeProcess(1))


def test_status_reports_dead_pid(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(parents=True)
    (state / "keepalive-sip.pid").write_text(json.dumps({"pid": 999999, "log": "x"}), encoding="utf-8")
    info = kv.status("sip", state_dir=state, pid_alive_fn=lambda pid: False)
    assert info["running"] is False and info["pid"] == 999999


def test_stop_sends_sigterm_and_cleans_pid_file(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(parents=True)
    pid_file = state / "keepalive-firewall.pid"
    pid_file.write_text(json.dumps({"pid": 555, "log": "x"}), encoding="utf-8")
    sent: list[tuple[int, int]] = []
    alive = {"value": True}

    def kill(pid, sig):
        sent.append((pid, sig))
        alive["value"] = False

    info = kv.stop("firewall", state_dir=state, kill_fn=kill, pid_alive_fn=lambda pid: alive["value"], grace_seconds=0.2)
    assert sent == [(555, signal.SIGTERM)]
    assert info["stopped"] is True
    assert not pid_file.exists()


def test_stop_when_not_running_removes_stale_pid_file(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(parents=True)
    pid_file = state / "keepalive-sip.pid"
    pid_file.write_text(json.dumps({"pid": 4}), encoding="utf-8")
    info = kv.stop("sip", state_dir=state, pid_alive_fn=lambda pid: False)
    assert info["stopped"] is False and info["reason"] == "not running"
    assert not pid_file.exists()


# ---------------------------------------------------------------- login 接线

def _make_runner(tmp_path: Path) -> rp.PipelineRunner:
    run_dir = tmp_path / "runs" / "20260101_000000"
    for sub in ("logs", "exports", "analysis"):
        (run_dir / sub).mkdir(parents=True, exist_ok=True)
    artifacts = SimpleNamespace(
        run_id="20260101_000000", run_dir=run_dir, exports_dir=run_dir / "exports",
        analysis_dir=run_dir / "analysis", blacklist_dir=run_dir / "blacklist", logs_dir=run_dir / "logs",
    )
    config = SimpleNamespace(
        root_dir=tmp_path,
        sip_base_url="https://sip.local",
        firewall_base_url="https://fw.local",
        paths=SimpleNamespace(
            runs_dir=tmp_path / "runs", state_dir=tmp_path / "state",
            sip_session_file=tmp_path / "secrets" / "sip_session.json",
            firewall_session_file=tmp_path / "secrets" / "firewall_session.json",
        ),
    )
    manifest = RunManifest(run_dir, artifacts.run_id, {"command": "login"})
    return rp.PipelineRunner(config, artifacts, manifest, EventLogger(run_dir, artifacts.run_id))


def _patch_login(monkeypatch, tmp_path: Path):
    commands: list[list[str]] = []
    started: list[tuple[str, int | None]] = []

    def fake_run_subprocess(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="", args=command)

    def fake_start(target, **kwargs):
        started.append((target, kwargs.get("interval")))
        return {"target": target, "started": True, "pid": 1000 + len(started), "log": f"/tmp/{target}.log"}

    monkeypatch.setattr(rp, "run_subprocess", fake_run_subprocess)
    monkeypatch.setattr(rp.keepalive_manager, "start", fake_start)
    return commands, started


def test_login_auto_starts_keepalive_for_all_targets(tmp_path: Path, monkeypatch) -> None:
    commands, started = _patch_login(monkeypatch, tmp_path)
    runner = _make_runner(tmp_path)
    runner.login(target="all", headless=True)

    assert started == [("sip", None), ("firewall", None)]
    fw = [c for c in commands if any(str(part).endswith("sangfor_firewall_login_session.py") for part in c)][0]
    assert "--no-keepalive" in fw  # 登录子进程必须返回，保活交给 detached 进程
    sip = [c for c in commands if any(str(part).endswith("sangfor_login_session.py") for part in c)][0]
    assert "--keepalive" not in sip


def test_login_respects_no_keepalive(tmp_path: Path, monkeypatch) -> None:
    commands, started = _patch_login(monkeypatch, tmp_path)
    runner = _make_runner(tmp_path)
    runner.login(target="all", headless=True, keepalive_enabled=False)
    assert started == []
    assert commands  # 登录本身照常执行


def test_login_legacy_firewall_keepalive_keeps_in_process_mode(tmp_path: Path, monkeypatch) -> None:
    commands, started = _patch_login(monkeypatch, tmp_path)
    runner = _make_runner(tmp_path)
    runner.login(target="firewall", headless=True, firewall_keepalive=True)
    fw = commands[-1]
    assert "--keepalive" in fw and "--no-keepalive" not in fw  # 旧行为：前台常驻
    assert started == []  # 不再重复拉起 detached 保活


def test_login_passes_keepalive_interval(tmp_path: Path, monkeypatch) -> None:
    _commands, started = _patch_login(monkeypatch, tmp_path)
    runner = _make_runner(tmp_path)
    runner.login(target="firewall", headless=True, keepalive_interval=600)
    assert started == [("firewall", 600)]


def test_keepalive_control_stop_uses_manager(tmp_path: Path, monkeypatch) -> None:
    runner = _make_runner(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(rp.keepalive_manager, "stop",
                        lambda target, **kw: (calls.append(target), {"target": target, "running": False, "stopped": True, "pid": 1})[1])
    runner.keepalive_control(target="all", stop=True)
    assert calls == ["sip", "firewall"]
