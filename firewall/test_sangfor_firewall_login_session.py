from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sangfor_firewall_login_session import build_parser, is_login_page_info


def test_is_login_page_info_detects_login_inputs():
    assert is_login_page_info({"url": "https://172.16.1.116/", "user_inputs": 1, "password_inputs": 1, "captcha_inputs": 1})


def test_is_login_page_info_detects_login_url():
    assert is_login_page_info({"url": "https://172.16.1.116/login.html", "user_inputs": 0, "password_inputs": 0, "captcha_inputs": 0})


def test_is_login_page_info_allows_authenticated_page():
    assert not is_login_page_info({"url": "https://172.16.1.116/main", "user_inputs": 0, "password_inputs": 0, "captcha_inputs": 0})


def test_parser_keepalive_defaults():
    args = build_parser().parse_args([])
    assert args.keepalive
    assert args.keepalive_interval == 300
