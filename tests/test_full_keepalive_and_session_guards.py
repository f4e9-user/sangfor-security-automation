"""Regression tests for `full` stage ordering, firewall keepalive and the pre-stage session guard.

Context: a 2026-09-11 `full --apply` run lost the firewall session during the ~14 minute SIP export
(80k rows), so `export-firewall-blacklist` failed with HTTP 400 request error. Fixes pinned here:
the firewall blacklist export now runs BEFORE the long SIP export, a lightweight firewall keepalive
thread pings the session for the duration of `full`, and firewall-dependent stages fail fast with an
actionable message when the session is dead instead of surfacing a bare 400.

The first keepalive attempt reused `firewall/firewall_keepalive.py`, which died on its first refresh
(`Page.goto ... wait_until="networkidle"` timeout → `return 1`); the thread + urllib ping replaced it
because it must survive single failures and must not start a browser during the SIP export.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from pipeline import run_pipeline as rp
from pipeline.sessions import MissingSessionError


class RecordingKeepalive:
    """测试替身：记录 start/stop，不真正起线程。"""

    instances: list["RecordingKeepalive"] = []

    def __init__(self, *args, **kwargs):
        self.started = False
        self.stopped = False
        RecordingKeepalive.instances.append(self)

    @property
    def running(self) -> bool:
        return self.started and not self.stopped

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True


@pytest.fixture(autouse=True)
def _reset_recording_keepalive():
    RecordingKeepalive.instances = []
    yield
    RecordingKeepalive.instances = []


def _dummy_config(root: Path) -> SimpleNamespace:
    return SimpleNamespace(
        root_dir=root,
        paths=SimpleNamespace(
            firewall_session_file=root / "secrets" / "firewall_session.json",
            state_dir=root / "state",
        ),
    )


def _runner_stub(root: Path, calls: list, monkeypatch) -> rp.PipelineRunner:
    runner = object.__new__(rp.PipelineRunner)
    runner.config = _dummy_config(root)
    runner.events = SimpleNamespace(emit=lambda stage, level, event, message, data=None: calls.append((stage, event)))
    runner.manifest = SimpleNamespace(set_output=lambda *a, **k: None, data={})
    runner.artifacts = SimpleNamespace(run_dir=root / "runs" / "r1")
    monkeypatch.setattr(runner, "check_sessions", lambda: calls.append(("check-sessions", "stage")))
    monkeypatch.setattr(runner, "export_logs", lambda *a, **k: (calls.append(("export-logs", "stage")), root / "x.xlsx")[1])
    monkeypatch.setattr(runner, "export_firewall_blacklist", lambda: (calls.append(("export-firewall-blacklist", "stage")), root / "bl.csv")[1])
    monkeypatch.setattr(runner, "analyze", lambda *a, **k: (calls.append(("analyze", "stage")), root / "rec.csv")[1])
    monkeypatch.setattr(runner, "block", lambda rec, apply=False: calls.append((f"block-apply={apply}", "stage")))
    monkeypatch.setattr(rp, "write_daily_report", lambda *a, **k: (root / "r.md", root / "r.json"))
    monkeypatch.setattr(rp, "print_console_report", lambda *a, **k: None)
    monkeypatch.setattr(rp, "FirewallKeepalive", RecordingKeepalive)
    return runner


def test_firewall_blacklist_exports_before_the_long_sip_export(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    runner = _runner_stub(tmp_path, calls, monkeypatch)
    runner.full("2026-08-28 17:30:00", "2026-09-05 17:30:00", "3", None, apply=True, report=False)

    stages = [c[0] for c in calls if c[1] == "stage"]
    assert stages == [
        "check-sessions",
        "export-firewall-blacklist",
        "export-logs",
        "analyze",
        "block-apply=False",
        "block-apply=True",
    ]
    assert len(RecordingKeepalive.instances) == 1
    keepalive = RecordingKeepalive.instances[0]
    assert keepalive.started and keepalive.stopped
    events = [c[1] for c in calls]
    assert "keepalive_started" in events and "keepalive_stopped" in events


def test_keepalive_stops_even_when_a_stage_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    runner = _runner_stub(tmp_path, calls, monkeypatch)

    def boom(*a, **k):
        raise RuntimeError("export-logs exploded")

    monkeypatch.setattr(runner, "export_logs", boom)
    with pytest.raises(RuntimeError, match="exploded"):
        runner.full("2026-08-28 17:30:00", "2026-09-05 17:30:00", "3", None, apply=False, report=False)
    assert RecordingKeepalive.instances[0].stopped
    assert ("full", "keepalive_stopped") in calls


def test_dead_firewall_session_fails_fast_with_refresh_hint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = object.__new__(rp.PipelineRunner)
    runner.config = _dummy_config(tmp_path)
    runner.artifacts = SimpleNamespace(blacklist_dir=tmp_path / "blacklist", logs_dir=tmp_path / "logs")
    stages: list = []
    runner.manifest = SimpleNamespace(
        start_stage=lambda *a, **k: stages.append(("start", a)),
        finish_stage=lambda *a, **k: stages.append(("finish", a[0], a[1])),
    )
    runner.events = SimpleNamespace(emit=lambda *a, **k: None)
    monkeypatch.setattr(rp, "check_firewall_session_health", lambda path: {"healthy": False, "status": 302, "login_page": True})
    monkeypatch.setattr(runner, "_write_status", lambda *a, **k: None)

    def fail_if_called(*a, **k):  # pragma: no cover - must not run
        raise AssertionError("stage command must not run when the firewall session is dead")

    monkeypatch.setattr(rp, "run_subprocess", fail_if_called)
    with pytest.raises(MissingSessionError) as excinfo:
        runner.export_firewall_blacklist()
    message = str(excinfo.value)
    assert "防火墙会话" in message and "_cftoken" in message
    assert ("finish", "export-firewall-blacklist", "failed") in stages


def test_keepalive_thread_pings_repeatedly_and_survives_ping_errors(tmp_path: Path) -> None:
    results: list[tuple[bool, str]] = []
    calls = {"n": 0}

    def flaky_ping() -> tuple[bool, str]:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient keepalive failure")
        return True, "HTTP 200"

    keepalive = rp.FirewallKeepalive(
        tmp_path / "secrets" / "firewall_session.json",
        interval=0.05,
        ping=flaky_ping,
        on_event=lambda healthy, detail: results.append((healthy, detail)),
    )
    assert keepalive.running is False
    with keepalive:
        assert keepalive.running is True
        keepalive.start()  # 重复 start 不重复起线程
        deadline = time.time() + 5
        while len(results) < 2 and time.time() < deadline:
            time.sleep(0.05)
    assert keepalive.running is False
    keepalive.stop()  # stop 幂等
    assert len(results) >= 2
    assert results[0][0] is False and "transient keepalive failure" in results[0][1]
    assert results[1] == (True, "HTTP 200")


class _FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self, size: int = -1) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _write_session(tmp_path: Path) -> Path:
    path = tmp_path / "firewall_session.json"
    path.write_text(
        json.dumps({"base_url": "https://firewall.example", "cookie": "SESSID=secret", "csrf_token": "t"}),
        encoding="utf-8",
    )
    return path


def test_ping_firewall_session_does_not_follow_redirects(tmp_path: Path) -> None:
    """会话失效时设备回 302 → login.php；登录页本身是 200，绝不能跟随重定向判成健康。"""
    import json as _json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    state = {"mode": "302"}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if state["mode"] == "302":
                self.send_response(302)
                self.send_header("Location", "login.php")
                self.end_headers()
            else:
                body = b"<title>AF</title>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        def log_message(self, *args):  # noqa: D102
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        session = tmp_path / "firewall_session.json"
        session.write_text(
            _json.dumps({"base_url": f"http://127.0.0.1:{server.server_port}", "cookie": "SESSID=secret"}),
            encoding="utf-8",
        )
        assert rp.ping_firewall_session(session) == (False, "HTTP 302")
        state["mode"] = "200"
        healthy, detail = rp.ping_firewall_session(session)
        assert healthy is True and detail == "HTTP 200"
    finally:
        server.shutdown()
        server.server_close()


def test_ping_firewall_session_flags_login_page_body_and_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    session = _write_session(tmp_path)
    monkeypatch.setattr(rp, "ping_firewall_session", rp.ping_firewall_session)  # 明确使用真实实现

    class _Opener:
        def __init__(self, response=None, error=None):
            self._response, self._error = response, error

        def open(self, request, timeout=None):
            if self._error:
                raise self._error
            return self._response

    monkeypatch.setattr(
        "urllib.request.build_opener",
        lambda *handlers: _Opener(_FakeResponse(200, b'<script>location.href="login.php"</script>')),
    )
    healthy, _ = rp.ping_firewall_session(session)
    assert healthy is False

    monkeypatch.setattr("urllib.request.build_opener", lambda *handlers: _Opener(error=TimeoutError("timed out")))
    healthy, detail = rp.ping_firewall_session(session)
    assert healthy is False and "TimeoutError" in detail

    monkeypatch.setattr(
        "urllib.request.build_opener",
        lambda *handlers: _Opener(error=urllib.error.HTTPError("u", 302, "Found", {}, None)),
    )
    healthy, detail = rp.ping_firewall_session(session)
    assert healthy is False and detail == "HTTP 302"
