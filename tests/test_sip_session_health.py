"""`check_sip_session_health` 的回归测试。

背景（2026-09-20 实测）：SIP 在缺少 `feature_id: /logsearch` 请求头时，对任何查询一律回
`{"success":false,"message":"您没有权限进行此操作"}`（HTTP 200），于是健康检查把失效会话
判成健康——构造性假健康。修复后：请求必须带 `feature_id`，且 `data.need_login` / `success=false`
都要判为不健康。
"""
from __future__ import annotations

import json

import pytest

import pipeline.sessions as sessions


class FakeResponse:
    def __init__(self, status: int, payload: bytes) -> None:
        self.status = status
        self._payload = payload

    def read(self, amount: int | None = None) -> bytes:
        return self._payload


class FakeConnection:
    """记录请求，按脚本返回响应。"""

    def __init__(self, *args, **kwargs) -> None:
        self.request_args: dict = {}
        self.response = FakeConnection.next_response
        FakeConnection.last = self

    last: "FakeConnection | None" = None
    next_response: tuple[int, bytes] = (200, b"{}")

    def request(self, method, path, body=None, headers=None) -> None:
        self.request_args = {"method": method, "path": path, "body": body, "headers": dict(headers or {})}

    def getresponse(self) -> FakeResponse:
        status, payload = self.response
        return FakeResponse(status, payload)

    def close(self) -> None:
        pass


@pytest.fixture()
def session_file(tmp_path):
    path = tmp_path / "sip_session.json"
    path.write_text(
        json.dumps({"base_url": "https://sip.local", "cookie": "sess=abc", "xid": "deadbeef"}),
        encoding="utf-8",
    )
    return path


@pytest.fixture(autouse=True)
def patch_connection(monkeypatch):
    FakeConnection.last = None
    monkeypatch.setattr(sessions.http.client, "HTTPSConnection", FakeConnection)
    return FakeConnection


def test_request_sends_feature_id_header(session_file):
    FakeConnection.next_response = (200, json.dumps({"success": True, "data": {"total": 0}}).encode())
    status = sessions.check_sip_session_health(session_file)
    assert status["healthy"] is True
    assert status["error"] == ""
    assert FakeConnection.last is not None
    assert FakeConnection.last.request_args["headers"].get("feature_id") == "/logsearch"


def test_need_login_payload_is_unhealthy(session_file):
    """设备用 HTTP 200 + need_login 表示会话过期（假 200）。"""
    payload = json.dumps(
        {"success": True, "message": "用户未登录或会话已过期", "data": {"href": "/ui/login/login.html", "need_login": True}}
    ).encode()
    FakeConnection.next_response = (200, payload)
    status = sessions.check_sip_session_health(session_file)
    assert status["healthy"] is False
    assert status["need_login"] is True
    assert "过期" in status["error"]


def test_permission_denied_is_unhealthy(session_file):
    """缺 feature_id 时设备回的 `success:false` 不能被当成健康。"""
    payload = json.dumps({"success": False, "message": "您没有权限进行此操作"}).encode()
    FakeConnection.next_response = (200, payload)
    status = sessions.check_sip_session_health(session_file)
    assert status["healthy"] is False
    assert status["need_login"] is False
    assert "权限" in status["error"]


def test_redirect_is_unhealthy(session_file):
    FakeConnection.next_response = (302, b"")
    status = sessions.check_sip_session_health(session_file)
    assert status["healthy"] is False
    assert status["status"] == 302
