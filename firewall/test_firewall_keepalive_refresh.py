"""防火墙保活的回归测试（2026-09-20 修 `networkidle` 假死）。

实测背景：会话健康时，防火墙控制台页面**永远到不了 `networkidle`**，
`firewall_keepalive.py` / 登录脚本的保活循环都会在第一次刷新就 60s/45s 超时并退出，
容器表现为“常驻但什么都没做”。修法：改用 `domcontentloaded`，并把
「导航超时（retry）」与「落到登录页（expired）」分开处理。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sangfor_firewall_login_session as login_mod  # noqa: E402
from firewall_keepalive import refresh_once  # noqa: E402


class FakePage:
    def __init__(self, *, raises: Exception | None = None) -> None:
        self.raises = raises
        self.calls: list[dict] = []

    def goto(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        if self.raises is not None:
            raise self.raises
        return None


def test_refresh_once_uses_domcontentloaded_and_reports_ok(monkeypatch):
    page = FakePage()
    monkeypatch.setattr("firewall_keepalive.page_login_info", lambda p: {"url": "https://fw.local/framework.php"})
    verdict, message, url = refresh_once(page, "https://fw.local/framework.php", 45)
    assert (verdict, message) == ("ok", "")
    assert url == "https://fw.local/framework.php"
    assert page.calls[0]["wait_until"] == "domcontentloaded"
    assert page.calls[0]["timeout"] == 45000


def test_refresh_once_treats_navigation_timeout_as_retry(monkeypatch):
    page = FakePage(raises=TimeoutError("Timeout 45000ms exceeded"))
    verdict, message, url = refresh_once(page, "https://fw.local/framework.php", 45)
    assert verdict == "retry"
    assert "Timeout" in message
    assert url == ""


def test_refresh_once_detects_login_page_as_expired(monkeypatch):
    page = FakePage()
    monkeypatch.setattr(
        "firewall_keepalive.page_login_info",
        lambda p: {"url": "https://fw.local/login.php", "user_inputs": 1, "password_inputs": 1},
    )
    verdict, message, url = refresh_once(page, "https://fw.local/framework.php", 45)
    assert verdict == "expired"
    assert message == "login page detected"
    assert url.endswith("/login.php")


def _patch_sleep(monkeypatch, *, stop_after: int):
    calls: list[float] = []

    def _sleep(seconds):
        calls.append(seconds)
        if len(calls) > stop_after:
            raise _StopLoop

    monkeypatch.setattr(login_mod.time, "sleep", _sleep)
    return calls


class _StopLoop(Exception):
    pass


def test_keepalive_loop_exits_after_consecutive_failures(monkeypatch, capsys):
    _patch_sleep(monkeypatch, stop_after=99)
    page = FakePage(raises=TimeoutError("Timeout 60000ms exceeded"))
    with pytest.raises(SystemExit) as exc:
        login_mod.keepalive_loop(page, "https://fw.local", 1, max_consecutive_failures=2)
    assert exc.value.code == 1
    assert "repeated refresh failures" in capsys.readouterr().out


def test_keepalive_loop_exits_immediately_on_login_page(monkeypatch, capsys):
    _patch_sleep(monkeypatch, stop_after=99)
    page = FakePage()
    monkeypatch.setattr(login_mod, "page_login_info", lambda p: {"url": "https://fw.local/login.php", "password_inputs": 1})
    with pytest.raises(SystemExit) as exc:
        login_mod.keepalive_loop(page, "https://fw.local", 1, max_consecutive_failures=5)
    assert exc.value.code == 1
    assert "no longer authenticated" in capsys.readouterr().out


def test_keepalive_loop_survives_single_timeout_then_recovers(monkeypatch, capsys):
    """一次超时不得判死：上限 3 时，1 次超时后恢复应继续跑并打印 OK。"""
    _patch_sleep(monkeypatch, stop_after=3)  # 第 4 次 sleep 抛 _StopLoop 结束测试
    state = {"n": 0}

    class FlakyPage(FakePage):
        def goto(self, url, **kwargs):
            self.calls.append({"url": url, **kwargs})
            state["n"] += 1
            if state["n"] == 1:
                raise TimeoutError("Timeout 60000ms exceeded")
            return None

    monkeypatch.setattr(login_mod, "page_login_info", lambda p: {"url": "https://fw.local/framework.php"})
    page = FlakyPage()
    with pytest.raises(_StopLoop):
        login_mod.keepalive_loop(page, "https://fw.local", 1, path="/framework.php", max_consecutive_failures=3)
    out = capsys.readouterr().out
    assert "Keepalive refresh error (1/3)" in out
    assert "Keepalive OK" in out
    assert page.calls[0]["wait_until"] == "domcontentloaded"
    assert page.calls[0]["url"] == "https://fw.local/framework.php"
