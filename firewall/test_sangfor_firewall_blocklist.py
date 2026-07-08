import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sangfor_firewall_blocklist import BlacklistClient, load_session_file, resolve_auth_config


class FakeTransport:
    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or [(200, {"content-type": "text/html"}, b"ok")]

    def request(self, method, url, *, headers=None, data=None):
        self.calls.append({"method": method, "url": url, "headers": headers or {}, "data": data})
        return self.responses.pop(0)


def test_load_session_file_reads_base_url_cookie_and_csrf(tmp_path):
    session_path = tmp_path / "session.json"
    session_path.write_text(
        json.dumps(
            {
                "base_url": "https://fw.local",
                "cookie": "SESSID=abc; x-anti-csrf-gcs=gcs",
                "csrf": {"_cftoken": "csrf-header", "gcs_csrf": "gcs"},
            }
        ),
        encoding="utf-8",
    )

    assert load_session_file(session_path) == {
        "base_url": "https://fw.local",
        "cookie": "SESSID=abc; x-anti-csrf-gcs=gcs",
        "csrf_token": "csrf-header",
    }


def test_resolve_auth_config_does_not_fall_back_to_default_cookie():
    class Args:
        session_file = None
        base_url = "https://fw.local"
        cookie = None
        csrf_token = None

    try:
        resolve_auth_config(Args())
    except ValueError as exc:
        assert "cookie" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_resolve_auth_config_prefers_session_file(tmp_path):
    session_path = tmp_path / "session.json"
    session_path.write_text(
        json.dumps({"base_url": "https://fw.local", "cookie": "SESSID=abc", "csrf": {"_cftoken": "csrf-header"}}),
        encoding="utf-8",
    )

    class Args:
        session_file = str(session_path)
        base_url = "https://override.local"
        cookie = None
        csrf_token = None

    assert resolve_auth_config(Args()) == ("https://fw.local", "SESSID=abc", "csrf-header")


def test_check_login_uses_framework_php():
    transport = FakeTransport()
    client = BlacklistClient(base_url="https://fw.local", cookie="SESSID=abc", csrf_token="csrf-header", transport=transport)

    client.check_login()

    assert transport.calls[0]["method"] == "GET"
    assert transport.calls[0]["url"] == "https://fw.local/framework.php"