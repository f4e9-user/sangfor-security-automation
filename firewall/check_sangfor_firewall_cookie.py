#!/usr/bin/env python3
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright

SESSION_PATH = Path('/home/user/.config/sangfor-firewall/session.json')
URL = 'https://firewall.local/framework.php'
SCREENSHOT = Path('/tmp/sangfor-firewall-keepalive-check.png')


def parse_cookie_header(raw: str, domain: str) -> list[dict]:
    cookies = []
    for part in raw.split(';'):
        part = part.strip()
        if not part or '=' not in part:
            continue
        name, value = part.split('=', 1)
        cookies.append({
            'name': name,
            'value': value,
            'domain': domain,
            'path': '/',
            'secure': True,
            'httpOnly': False,
            'sameSite': 'Lax',
        })
    return cookies


def main() -> None:
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if not SESSION_PATH.exists():
        print(f'[{now}] Sangfor firewall cookie check: FAIL session file missing: {SESSION_PATH}')
        return
    session = json.loads(SESSION_PATH.read_text(encoding='utf-8'))
    raw_cookie = session.get('cookie') or ''
    if not raw_cookie:
        print(f'[{now}] Sangfor firewall cookie check: FAIL session file has no cookie')
        return

    host = urlparse(URL).hostname or 'firewall.local'
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=['--ignore-certificate-errors'])
        try:
            context = browser.new_context(ignore_https_errors=True, viewport={'width': 1440, 'height': 950})
            context.add_cookies(parse_cookie_header(raw_cookie, host))
            page = context.new_page()
            try:
                page.goto(URL, wait_until='domcontentloaded', timeout=30000)
            except PlaywrightTimeoutError:
                pass
            page.wait_for_timeout(3000)
            page.screenshot(path=str(SCREENSHOT), full_page=True)
            info = page.evaluate("""() => ({
                url: location.href,
                title: document.title,
                text: document.body ? document.body.innerText.slice(0, 500) : '',
                userInputs: document.querySelectorAll('input[name="user"]').length,
                passwordInputs: document.querySelectorAll('input[name="password"]').length,
                captchaInputs: document.querySelectorAll('input[name="captcha"]').length
            })""")
        finally:
            browser.close()

    is_login = bool(
        info['userInputs'] or info['passwordInputs'] or info['captchaInputs']
        or '立即登录' in info['text']
        or 'login' in info['url'].lower()
    )
    if is_login:
        print(f'[{now}] Sangfor firewall cookie check: EXPIRED/LOGIN_PAGE url={info["url"]} title={info["title"]} screenshot={SCREENSHOT}')
    else:
        print(f'[{now}] Sangfor firewall cookie check: OK authenticated url={info["url"]} title={info["title"]} screenshot={SCREENSHOT}')


if __name__ == '__main__':
    main()
