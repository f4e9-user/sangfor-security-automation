import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sangfor_sip_cookie_keepalive as keepalive
from sangfor_sip_cookie_keepalive import load_session_file, resolve_auth_args, should_exit_after_response, write_status


def test_redirect_response_exits_without_retry():
    assert should_exit_after_response(302, None, stop_on_need_login=False)


def test_need_login_response_exits_by_default():
    assert should_exit_after_response(200, {"data": {"need_login": True}}, stop_on_need_login=False)


def test_load_session_file_reads_required_auth_values(tmp_path):
    session_path = tmp_path / "session.json"
    session_path.write_text(
        json.dumps({"base_url": "https://sip.local", "cookie": "sess_id=abc", "xid": "x-123"}),
        encoding="utf-8",
    )

    assert load_session_file(session_path) == {
        "base_url": "https://sip.local",
        "cookie": "sess_id=abc",
        "xid": "x-123",
    }


def test_load_session_file_rejects_missing_xid(tmp_path):
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps({"base_url": "https://sip.local", "cookie": "sess_id=abc"}), encoding="utf-8")

    try:
        load_session_file(session_path)
    except ValueError as exc:
        assert "xid" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_resolve_auth_args_reads_session_file_without_default_secrets(tmp_path):
    session_path = tmp_path / "session.json"
    session_path.write_text(
        json.dumps({"base_url": "https://sip.local", "cookie": "sess_id=abc", "xid": "x-123"}),
        encoding="utf-8",
    )

    class Args:
        session_file = str(session_path)
        host = "ignored.local"
        cookie = None
        xid = None

    host, cookie, xid = resolve_auth_args(Args())

    assert host == "sip.local"
    assert cookie == "sess_id=abc"
    assert xid == "x-123"


def test_resolve_auth_args_requires_cookie_and_xid_without_session_file():
    class Args:
        session_file = None
        host = "sip.local"
        cookie = None
        xid = None

    try:
        resolve_auth_args(Args())
    except ValueError as exc:
        assert "cookie" in str(exc)
        assert "xid" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_write_status_records_health_need_login_timestamp_and_error(tmp_path):
    status_path = tmp_path / "state" / "sip_session.status.json"

    write_status(status_path, healthy=False, need_login=True, session_file="session.json", error="login required")

    payload = json.loads(status_path.read_text(encoding="utf-8"))
    assert payload["healthy"] is False
    assert payload["need_login"] is True
    assert payload["session_file"] == "session.json"
    assert payload["error"] == "login required"
    assert "timestamp" in payload


def test_main_preserves_redirect_status_on_exit(tmp_path, monkeypatch):
    status_path = tmp_path / "state" / "sip_session.status.json"

    class FakeConnection:
        def __init__(self, *args, **kwargs):
            self.closed = False

        def close(self):
            self.closed = True

    def fake_do_post(conn, path, headers, payload, timeout_s, max_read_bytes):
        return 302, "Found", b""

    monkeypatch.setattr(keepalive.http.client, "HTTPSConnection", FakeConnection)
    monkeypatch.setattr(keepalive, "do_post", fake_do_post)
    monkeypatch.setattr(keepalive.ssl, "create_default_context", lambda: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sangfor_sip_cookie_keepalive.py",
            "--host",
            "sip.local",
            "--cookie",
            "sess_id=abc",
            "--xid",
            "x-123",
            "--status-file",
            str(status_path),
        ],
    )

    assert keepalive.main() == 0

    payload = json.loads(status_path.read_text(encoding="utf-8"))
    assert payload["healthy"] is False
    assert payload["need_login"] is None
    assert payload["error"] == "redirect"
    assert payload["status"] == 302


def test_main_preserves_need_login_status_on_exit(tmp_path, monkeypatch):
    status_path = tmp_path / "state" / "sip_session.status.json"

    class FakeConnection:
        def __init__(self, *args, **kwargs):
            self.closed = False

        def close(self):
            self.closed = True

    def fake_do_post(conn, path, headers, payload, timeout_s, max_read_bytes):
        body = json.dumps({"message": "login expired", "data": {"need_login": True, "href": "/login"}}).encode("utf-8")
        return 200, "OK", body

    monkeypatch.setattr(keepalive.http.client, "HTTPSConnection", FakeConnection)
    monkeypatch.setattr(keepalive, "do_post", fake_do_post)
    monkeypatch.setattr(keepalive.ssl, "create_default_context", lambda: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sangfor_sip_cookie_keepalive.py",
            "--host",
            "sip.local",
            "--cookie",
            "sess_id=abc",
            "--xid",
            "x-123",
            "--stop-on-need-login",
            "--status-file",
            str(status_path),
        ],
    )

    assert keepalive.main() == 0

    payload = json.loads(status_path.read_text(encoding="utf-8"))
    assert payload["healthy"] is False
    assert payload["need_login"] is True
    assert payload["error"] == "login expired"
    assert payload["status"] == 200
