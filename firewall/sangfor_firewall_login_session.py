#!/usr/bin/env python3
"""Local-only Sangfor firewall login helper that writes cookie session JSON.

Run this from your own terminal. It prompts for the password with getpass so the
password is not sent through chat or written to disk.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import struct
import time
import zlib
from datetime import datetime
from pathlib import Path

from playwright.sync_api import sync_playwright

DEFAULT_BASE_URL = "https://172.16.1.116"
DEFAULT_SESSION_FILE = Path.home() / ".config" / "sangfor-firewall" / "session.json"
DEFAULT_CAPTCHA_FILE = Path("/tmp/sangfor-firewall-login-captcha.png")
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def cookie_header(cookies: list[dict]) -> str:
    pairs = []
    for cookie in cookies:
        name = cookie.get("name")
        value = cookie.get("value")
        if name is not None and value is not None:
            pairs.append(f"{name}={value}")
    return "; ".join(pairs)


def cookie_value(cookies: list[dict], name: str) -> str:
    for cookie in cookies:
        if cookie.get("name") == name:
            return str(cookie.get("value", ""))
    return ""


def md5_hex(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def firewall_csrf_tokens(cookies: list[dict]) -> dict:
    sessid = cookie_value(cookies, "SESSID")
    gcs_seed = cookie_value(cookies, "x-anti-csrf-gcs")
    tokens = {}
    if sessid:
        tokens["_cftoken"] = md5_hex(md5_hex(md5_hex(sessid)))
    if gcs_seed:
        tokens["gcs_csrf"] = md5_hex(gcs_seed)
    return tokens


def _paeth(left: int, up: int, up_left: int) -> int:
    p = left + up - up_left
    pa = abs(p - left)
    pb = abs(p - up)
    pc = abs(p - up_left)
    if pa <= pb and pa <= pc:
        return left
    if pb <= pc:
        return up
    return up_left


def read_png_rgb(path: Path) -> tuple[int, int, list[list[tuple[int, int, int]]]]:
    data = path.read_bytes()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("captcha screenshot is not a PNG")
    pos = 8
    width = height = color_type = bit_depth = None
    compressed = bytearray()
    while pos < len(data):
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        chunk_type = data[pos + 4 : pos + 8]
        chunk_data = data[pos + 8 : pos + 8 + length]
        pos += 12 + length
        if chunk_type == b"IHDR":
            width, height, bit_depth, color_type = struct.unpack(">IIBB", chunk_data[:10])[:4]
        elif chunk_type == b"IDAT":
            compressed.extend(chunk_data)
        elif chunk_type == b"IEND":
            break
    if bit_depth != 8 or color_type not in (2, 6):
        raise ValueError(f"unsupported PNG format: bit_depth={bit_depth}, color_type={color_type}")
    channels = 4 if color_type == 6 else 3
    row_size = width * channels
    raw = zlib.decompress(bytes(compressed))
    rows = []
    prev = [0] * row_size
    offset = 0
    for _ in range(height):
        filter_type = raw[offset]
        offset += 1
        scan = list(raw[offset : offset + row_size])
        offset += row_size
        recon = [0] * row_size
        for i, value in enumerate(scan):
            left = recon[i - channels] if i >= channels else 0
            up = prev[i]
            up_left = prev[i - channels] if i >= channels else 0
            if filter_type == 0:
                recon[i] = value
            elif filter_type == 1:
                recon[i] = (value + left) & 255
            elif filter_type == 2:
                recon[i] = (value + up) & 255
            elif filter_type == 3:
                recon[i] = (value + ((left + up) // 2)) & 255
            elif filter_type == 4:
                recon[i] = (value + _paeth(left, up, up_left)) & 255
            else:
                raise ValueError(f"unsupported PNG filter: {filter_type}")
        rows.append([(recon[i], recon[i + 1], recon[i + 2]) for i in range(0, row_size, channels)])
        prev = recon
    return width, height, rows


def print_captcha_image(path: Path) -> None:
    width, height, pixels = read_png_rgb(path)
    max_width = 140
    step_x = max(1, (width + max_width - 1) // max_width)
    print("CAPTCHA:", flush=True)
    for y in range(0, height, 2):
        parts = []
        for x in range(0, width, step_x):
            top_block = pixels[y][x : min(x + step_x, width)]
            bottom_y = min(y + 1, height - 1)
            bottom_block = pixels[bottom_y][x : min(x + step_x, width)]
            tr = sum(pixel[0] for pixel in top_block) // len(top_block)
            tg = sum(pixel[1] for pixel in top_block) // len(top_block)
            tb = sum(pixel[2] for pixel in top_block) // len(top_block)
            br = sum(pixel[0] for pixel in bottom_block) // len(bottom_block)
            bg = sum(pixel[1] for pixel in bottom_block) // len(bottom_block)
            bb = sum(pixel[2] for pixel in bottom_block) // len(bottom_block)
            parts.append(f"\x1b[38;2;{tr};{tg};{tb}m\x1b[48;2;{br};{bg};{bb}m▀")
        print("".join(parts) + "\x1b[0m", flush=True)
    print("", flush=True)


def page_login_info(page) -> dict:
    return page.evaluate(
        """
        () => ({
            url: location.href,
            title: document.title,
            text: document.body ? document.body.innerText.slice(0, 500) : '',
            user_inputs: document.querySelectorAll('input[name="user"]').length,
            password_inputs: document.querySelectorAll('input[name="password"]').length,
            captcha_inputs: document.querySelectorAll('input[name="captcha"]').length
        })
        """
    )


def is_login_page_info(info: dict) -> bool:
    url = str(info.get("url", "")).lower()
    text = str(info.get("text", ""))
    return (
        "login" in url
        or int(info.get("user_inputs") or 0) > 0
        or int(info.get("password_inputs") or 0) > 0
        or int(info.get("captcha_inputs") or 0) > 0
        or "立即登录" in text
    )


def keepalive_loop(page, base_url: str, interval: int) -> None:
    print(f"Keepalive started: interval={interval}s", flush=True)
    while True:
        time.sleep(interval)
        try:
            page.goto(base_url.rstrip("/"), wait_until="networkidle", timeout=60000)
        except Exception as exc:
            print(f"Keepalive failed during refresh: {exc}", flush=True)
            raise SystemExit(1)
        info = page_login_info(page)
        if is_login_page_info(info):
            print(f"Keepalive stopped: session is no longer authenticated; url={info.get('url')}", flush=True)
            raise SystemExit(1)
        print(f"Keepalive OK: {datetime.now().strftime(DATETIME_FORMAT)} url={info.get('url')}", flush=True)


def login(args: argparse.Namespace) -> dict:
    username = args.username or input("Sangfor firewall username: ").strip()
    password = getpass.getpass("Sangfor firewall password: ")
    session_path = Path(args.session_file).expanduser()
    session_path.parent.mkdir(parents=True, exist_ok=True)
    captcha_path = Path(args.captcha_file).expanduser()

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=args.headless, args=["--ignore-certificate-errors"])
        try:
            page = browser.new_page(ignore_https_errors=True, viewport={"width": 1440, "height": 950})
            page.goto(args.base_url.rstrip("/"), wait_until="networkidle", timeout=60000)
            page.locator('input[name="user"]').fill(username)
            page.locator('input[name="password"]').fill(password)
            captcha_img = page.locator('img[alt="点击刷新"]').first
            captcha_img.screenshot(path=str(captcha_path))
            print_captcha_image(captcha_path)
            captcha = input("Captcha: ").strip()
            page.locator('input[name="captcha"]').fill(captcha)
            checkbox = page.locator('input[name="checkbox"]').first
            if not checkbox.is_checked():
                checkbox.check(force=True)
            page.get_by_text("立即登录").click()
            page.wait_for_timeout(3000)
            try:
                page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass
            info = page_login_info(page)
            if is_login_page_info(info):
                body = page.locator("body").inner_text(timeout=5000)
                raise RuntimeError(f"login appears unsuccessful; current url={info.get('url')}; body={body[:300]}")
            page.wait_for_timeout(1000)
            cookies = page.context.cookies()
            session = {
                "base_url": args.base_url.rstrip("/"),
                "product": "sangfor-firewall",
                "cookie": cookie_header(cookies),
                "csrf": firewall_csrf_tokens(cookies),
                "created_at": datetime.now().strftime(DATETIME_FORMAT),
            }
            session_path.write_text(json.dumps(session, ensure_ascii=False, indent=2), encoding="utf-8")
            session_path.chmod(0o600)
            print(f"Session written: {session_path}")
            if args.keepalive:
                keepalive_loop(page, args.base_url, args.keepalive_interval)
            return session
        finally:
            browser.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--session-file", default=str(DEFAULT_SESSION_FILE))
    parser.add_argument("--captcha-file", default=str(DEFAULT_CAPTCHA_FILE))
    parser.add_argument("--username")
    parser.add_argument("--keepalive", action=argparse.BooleanOptionalAction, default=True, help="Keep Playwright open and refresh periodically after login")
    parser.add_argument("--keepalive-interval", type=int, default=300, help="Seconds between keepalive refreshes")
    parser.add_argument("--headless", action=argparse.BooleanOptionalAction, default=True)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    login(args)


if __name__ == "__main__":
    main()
