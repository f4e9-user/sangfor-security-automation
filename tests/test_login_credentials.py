import json
import subprocess
from pathlib import Path

import pytest

from pipeline.login_credentials import (
    ChaojiyingError,
    chaojiying_pass2,
    decrypt_credentials_file,
    load_login_credentials,
    recognize_captcha_with_chaojiying,
)


class FakeResponse:
    def __init__(self, payload: dict):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


def test_chaojiying_pass2_is_lowercase_md5():
    assert chaojiying_pass2("123456") == "e10adc3949ba59abbe56e057f20f883e"


def test_decrypt_credentials_file_uses_gpg_without_printing_secret(tmp_path, monkeypatch):
    encrypted = tmp_path / "login.json.gpg"
    encrypted.write_bytes(b"encrypted")
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout='{"sip":{"username":"u","password":"p"}}', stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    payload = decrypt_credentials_file(encrypted)

    assert payload["sip"]["username"] == "u"
    assert calls[0][0] == ["gpg", "--quiet", "--batch", "--decrypt", str(encrypted)]
    assert calls[0][1]["capture_output"] is True


def test_load_login_credentials_selects_service_and_chaojiying(tmp_path, monkeypatch):
    encrypted = tmp_path / "login.json.gpg"
    encrypted.write_bytes(b"encrypted")

    monkeypatch.setattr(
        "pipeline.login_credentials.decrypt_credentials_file",
        lambda path: {
            "sip": {"username": "sip-user", "password": "sip-pass"},
            "firewall": {"username": "fw-user", "password": "fw-pass"},
            "chaojiying": {"username": "cy-user", "password": "cy-pass", "softid": "96001", "codetype": "1004"},
        },
    )

    creds = load_login_credentials(encrypted, "firewall")

    assert creds.username == "fw-user"
    assert creds.password == "fw-pass"
    assert creds.chaojiying.username == "cy-user"
    assert creds.chaojiying.password == "cy-pass"
    assert creds.chaojiying.softid == "96001"
    assert creds.chaojiying.codetype == "1004"


def test_load_login_credentials_requires_service_section(tmp_path, monkeypatch):
    encrypted = tmp_path / "login.json.gpg"
    encrypted.write_bytes(b"encrypted")
    monkeypatch.setattr("pipeline.login_credentials.decrypt_credentials_file", lambda path: {})

    with pytest.raises(ValueError, match="missing sip credentials"):
        load_login_credentials(encrypted, "sip")


def test_recognize_captcha_with_chaojiying_sends_pass2_and_returns_pic_str(tmp_path):
    captcha = tmp_path / "captcha.png"
    captcha.write_bytes(b"fake-png")
    captured = {}

    def fake_urlopen(request, timeout):
        body = request.data
        captured["url"] = request.full_url
        captured["body"] = body
        captured["timeout"] = timeout
        return FakeResponse({"err_no": 0, "err_str": "OK", "pic_id": "1", "pic_str": "abcd"})

    result = recognize_captcha_with_chaojiying(
        captcha,
        username="cy-user",
        password="123456",
        softid="96001",
        codetype="1004",
        urlopen=fake_urlopen,
    )

    assert result == "abcd"
    assert captured["url"] == "https://upload.chaojiying.net/Upload/Processing.php"
    assert b'name="user"' in captured["body"]
    assert b"cy-user" in captured["body"]
    assert b'name="pass2"' in captured["body"]
    assert b"e10adc3949ba59abbe56e057f20f883e" in captured["body"]
    assert b'name="userfile"' in captured["body"]


def test_recognize_captcha_with_chaojiying_raises_on_error(tmp_path):
    captcha = tmp_path / "captcha.png"
    captcha.write_bytes(b"fake-png")

    def fake_urlopen(request, timeout):
        return FakeResponse({"err_no": -1, "err_str": "bad account"})

    with pytest.raises(ChaojiyingError, match="bad account"):
        recognize_captcha_with_chaojiying(
            captcha,
            username="cy-user",
            password="123456",
            softid="96001",
            codetype="1004",
            urlopen=fake_urlopen,
        )
