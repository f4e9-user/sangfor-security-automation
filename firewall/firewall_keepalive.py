#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

STOP = False
DEFAULT_SESSION_FILE = Path.home() / ".config" / "sangfor-firewall" / "session.json"
DEFAULT_STATE_FILE = Path("state/firewall_session.status.json")


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _handle_signal(signum, frame) -> None:
    global STOP
    STOP = True


def load_session_file(path: str | Path) -> dict[str, str]:
    session_path = Path(path).expanduser()
    payload = json.loads(session_path.read_text(encoding="utf-8"))
    required = ["base_url", "cookie"]
    missing = [name for name in required if not isinstance(payload.get(name), str) or not payload[name].strip()]
    if missing:
        raise ValueError(f"{session_path} missing required field(s): {', '.join(missing)}")
    return {"base_url": payload["base_url"].strip().rstrip("/"), "cookie": payload["cookie"].strip()}


def parse_cookie_header(cookie_header: str, base_url: str) -> list[dict[str, str]]:
    parsed = urlparse(base_url)
    if not parsed.hostname:
        raise ValueError("session base_url must include a host")
    cookies = []
    for part in cookie_header.split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name:
            cookies.append({"name": name, "value": value, "domain": parsed.hostname, "path": "/"})
    if not cookies:
        raise ValueError("session cookie header contains no cookie pairs")
    return cookies


def page_login_info(page) -> dict:
    return page.evaluate(
        """
        () => ({
            url: location.href,
            title: document.title || '',
            user_inputs: document.querySelectorAll('input[name="user"], input[name="username"], input[type="text"]').length,
            password_inputs: document.querySelectorAll('input[name="password"], input[type="password"]').length,
            captcha_inputs: document.querySelectorAll('input[name="captcha"], input[placeholder*="验证码"]').length
        })
        """
    )


def is_login_page_info(info: dict) -> bool:
    url = str(info.get("url", "")).lower()
    title = str(info.get("title", ""))
    return (
        "login.php" in url
        or "欢迎登录" in title
        or int(info.get("user_inputs") or 0) > 0
        or int(info.get("password_inputs") or 0) > 0
        or int(info.get("captcha_inputs") or 0) > 0
    )


def write_status(path: str | Path, *, ok: bool, session_file: str | Path, message: str, url: str = "") -> None:
    status_path = Path(path).expanduser()
    status_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "ok": ok,
        "session_file": str(session_file),
        "checked_at": _now_iso(),
        "message": message,
        "url": url,
    }
    status_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def framework_url(base_url: str, framework_path: str) -> str:
    return base_url.rstrip("/") + "/" + framework_path.lstrip("/")


def run_keepalive(args: argparse.Namespace) -> int:
    session = load_session_file(args.session_file)
    target = framework_url(session["base_url"], args.framework_path)
    cookies = parse_cookie_header(session["cookie"], session["base_url"])

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
        try:
            context = browser.new_context(ignore_https_errors=args.insecure, viewport={"width": 1440, "height": 950})
            context.add_cookies(cookies)
            page = context.new_page()
            attempt = 0
            next_t = time.monotonic()
            while not STOP:
                now = time.monotonic()
                if now < next_t:
                    time.sleep(min(0.5, next_t - now))
                    continue
                attempt += 1
                try:
                    page.goto(target, wait_until="networkidle", timeout=int(args.timeout * 1000))
                    info = page_login_info(page)
                except Exception as exc:
                    write_status(args.status_file, ok=False, session_file=args.session_file, message=f"refresh failed: {exc}")
                    print(f"[{_now_iso()}] #{attempt} refresh failed: {exc}", flush=True)
                    return 1
                if is_login_page_info(info):
                    url = str(info.get("url", ""))
                    write_status(args.status_file, ok=False, session_file=args.session_file, message="login page detected", url=url)
                    print(f"[{_now_iso()}] #{attempt} login page detected url={url}", flush=True)
                    return 1
                url = str(info.get("url", ""))
                write_status(args.status_file, ok=True, session_file=args.session_file, message="framework refresh ok", url=url)
                print(f"[{_now_iso()}] #{attempt} framework refresh ok url={url}", flush=True)
                next_t += args.interval
            write_status(args.status_file, ok=True, session_file=args.session_file, message="stopped by signal")
            print(f"[{_now_iso()}] stopped", flush=True)
            return 0
        finally:
            browser.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Keep a Sangfor firewall session alive by refreshing /framework.php with Playwright.")
    parser.add_argument("--session-file", default=str(DEFAULT_SESSION_FILE), help="Firewall session JSON with base_url and cookie")
    parser.add_argument("--status-file", default=str(DEFAULT_STATE_FILE), help="Health status JSON output path")
    parser.add_argument("--framework-path", default="/framework.php", help="Authenticated framework path to refresh")
    parser.add_argument("--interval", type=int, default=300, help="Seconds between refreshes")
    parser.add_argument("--timeout", type=float, default=60.0, help="Per-refresh timeout seconds")
    parser.add_argument("--insecure", action=argparse.BooleanOptionalAction, default=True, help="Ignore TLS certificate errors")
    return parser


def main() -> int:
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    try:
        return run_keepalive(build_parser().parse_args())
    except Exception as exc:
        print(f"firewall keepalive failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
