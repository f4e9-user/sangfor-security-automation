#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""登录后自动保活：把保活脚本以独立后台进程拉起并管理（start / status / stop）。

2026-09-20 背景与约定：
- 文档规定 SIP 用 **HTTP keepalive**、防火墙用 **headless Chromium 每 5 分钟刷新 `/framework.php`**；
- `login` 命令只负责登录并写会话文件，登录成功后**自动调用**本模块把对应保活拉起（可用
  `--no-keepalive` 关闭）；
- 保活进程是 **detached**（`start_new_session=True`）：`login` 立即返回，不会像
  `sangfor_firewall_login_session.py --keepalive` 那样让命令一直前台挂着；
- 进程信息落 `state/keepalive-<target>.pid`（JSON），日志落 `logs/keepalive-<target>.log`；
- 重复 start 不会拉起第二个（PID 仍在跑则直接返回既有信息）；`stop` 发 SIGTERM 并清理 PID 文件。

注意：保活脚本**只在启动时读一次会话文件**，所以刷新 cookie 后必须 `stop` + 重新 start。
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterable

TARGETS: tuple[str, ...] = ("sip", "firewall")
DEFAULT_INTERVAL_SECONDS = 300
STOP_GRACE_SECONDS = 10.0


def _script_for(target: str) -> tuple[str, int]:
    """返回 (相对项目根的脚本路径, 默认 interval)。"""
    if target == "sip":
        return ("situation-awareness/sangfor_sip_cookie_keepalive.py", DEFAULT_INTERVAL_SECONDS)
    if target == "firewall":
        return ("firewall/firewall_keepalive.py", DEFAULT_INTERVAL_SECONDS)
    raise ValueError(f"unknown keepalive target: {target!r} (expected one of {TARGETS})")


def build_command(
    target: str,
    *,
    root_dir: str | Path,
    session_file: str | Path,
    status_file: str | Path,
    interval: int | None = None,
) -> list[str]:
    script, default_interval = _script_for(target)
    resolved_interval = int(interval or default_interval)
    command = [
        sys.executable,
        str(Path(root_dir) / script),
        "--session-file",
        str(session_file),
        "--interval",
        str(resolved_interval),
        "--status-file",
        str(status_file),
    ]
    if target == "sip":
        command.append("--insecure")
    elif target == "firewall":
        command.append("--insecure")
    return command


def _default_spawn(command: list[str], *, cwd: str | Path, log_path: Path, env: dict[str, str]) -> subprocess.Popen:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = log_path.open("ab", buffering=0)
    return subprocess.Popen(  # noqa: S603 - 命令由本模块构造
        command,
        cwd=str(cwd),
        stdout=handle,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        env=env,
        start_new_session=True,
    )


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # 存在但不属于当前用户
        return True
    return True


def _pid_path(state_dir: str | Path, target: str) -> Path:
    return Path(state_dir) / f"keepalive-{target}.pid"


def _read_record(state_dir: str | Path, target: str) -> dict[str, Any]:
    path = _pid_path(state_dir, target)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def status(
    target: str,
    *,
    state_dir: str | Path,
    pid_alive_fn: Callable[[int], bool] = pid_alive,
) -> dict[str, Any]:
    record = _read_record(state_dir, target)
    pid = int(record.get("pid") or 0)
    running = pid_alive_fn(pid) if pid else False
    return {
        "target": target,
        "running": running,
        "pid": pid,
        "started_at": record.get("started_at", ""),
        "log": record.get("log", ""),
        "command": record.get("command", []),
        "pid_file": str(_pid_path(state_dir, target)),
    }


def start(
    target: str,
    *,
    root_dir: str | Path,
    session_file: str | Path,
    logs_dir: str | Path,
    state_dir: str | Path,
    status_file: str | Path | None = None,
    interval: int | None = None,
    spawn_fn: Callable[..., Any] | None = None,
    pid_alive_fn: Callable[[int], bool] = pid_alive,
) -> dict[str, Any]:
    """启动（或复用）某目标的保活后台进程。"""
    existing = status(target, state_dir=state_dir, pid_alive_fn=pid_alive_fn)
    if existing["running"]:
        return {**existing, "started": False, "reason": "already running"}

    root = Path(root_dir)
    if not Path(session_file).exists():
        raise FileNotFoundError(f"session file not found: {session_file}")

    resolved_status_file = Path(status_file) if status_file else Path(state_dir) / f"{target}_session.status.json"
    log_path = Path(logs_dir) / f"keepalive-{target}.log"
    command = build_command(
        target,
        root_dir=root,
        session_file=session_file,
        status_file=resolved_status_file,
        interval=interval,
    )

    env = dict(os.environ)
    browsers = root / ".playwright-browsers"
    if browsers.is_dir():
        env.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(browsers))

    spawner = spawn_fn or _default_spawn
    if spawn_fn is None:
        process = spawner(command, cwd=root, log_path=log_path, env=env)
    else:  # 测试注入：签名固定为 (command, cwd=..., log_path=..., env=...)
        process = spawner(command, cwd=root, log_path=log_path, env=env)
    pid = int(getattr(process, "pid", 0) or 0)

    record = {
        "target": target,
        "pid": pid,
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "log": str(log_path),
        "session_file": str(session_file),
        "command": command,
    }
    pid_path = _pid_path(state_dir, target)
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"target": target, "started": True, "running": pid_alive_fn(pid) if pid else False,
            "pid": pid, "log": str(log_path), "pid_file": str(pid_path), "command": command}


def stop(
    target: str,
    *,
    state_dir: str | Path,
    kill_fn: Callable[[int, int], None] | None = None,
    pid_alive_fn: Callable[[int], bool] = pid_alive,
    grace_seconds: float = STOP_GRACE_SECONDS,
) -> dict[str, Any]:
    """停止某目标的保活进程（SIGTERM，宽限到期后清理 PID 文件）。"""
    current = status(target, state_dir=state_dir, pid_alive_fn=pid_alive_fn)
    pid_path = _pid_path(state_dir, target)
    if not current["running"]:
        if pid_path.exists():
            pid_path.unlink()
        return {**current, "stopped": False, "reason": "not running"}

    sender = kill_fn or (lambda pid, sig: os.kill(pid, sig))
    sender(current["pid"], signal.SIGTERM)
    deadline = time.monotonic() + max(0.0, grace_seconds)
    while time.monotonic() < deadline and pid_alive_fn(current["pid"]):
        time.sleep(0.1)
    gone = not pid_alive_fn(current["pid"])
    if gone and pid_path.exists():
        pid_path.unlink()
    return {**current, "stopped": gone, "reason": "" if gone else "still running after SIGTERM"}


def status_all(
    targets: Iterable[str] = TARGETS,
    *,
    state_dir: str | Path,
    pid_alive_fn: Callable[[int], bool] = pid_alive,
) -> list[dict[str, Any]]:
    return [status(t, state_dir=state_dir, pid_alive_fn=pid_alive_fn) for t in targets]
