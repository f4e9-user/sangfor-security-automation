#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""防火墙保活观测实验：同一 Playwright context 周期刷新 + 独立 HTTP 探针，输出时间序列 CSV。

为什么合成一个进程：
- 文档规定的"可靠模式"就是**登录后不关 browser context**，所以这里让浏览器 context 一直活着；
- 同时用 `http.client`（**不跟重定向**）独立探一次 `/framework.php`，把"cookie 会话状态"与
  "浏览器刷新结果"分开记录，便于判断到底是谁在续命、谁先失效。

只读：仅 GET `/framework.php`，不下发任何配置。

用法：
    python scripts/firewall_keepalive_experiment.py \
        --session-file secrets/firewall_session.json \
        --out /tmp/keepalive_obs/experiment.csv \
        --probe-interval 120 --refresh-interval 300 --duration 3600
"""
from __future__ import annotations

import argparse
import csv
import http.client
import json
import ssl
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

FW_DIR = Path(__file__).resolve().parent.parent / "firewall"
sys.path.insert(0, str(FW_DIR))

from firewall_keepalive import is_login_page_info, page_login_info, parse_cookie_header  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

FIELDS = ["sample", "time", "elapsed_s", "probe_state", "probe_http", "probe_location",
          "refresh_verdict", "refresh_url", "refresh_message", "consecutive_failures"]


def probe_session(base: str, cookie: str, timeout: float) -> tuple[str, object, str]:
    """独立探针：不复用浏览器，直接 GET /framework.php 且不跟重定向。"""
    try:
        parsed = urlparse(base)
        conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        kwargs: dict = {"timeout": timeout}
        if parsed.scheme == "https":
            kwargs["context"] = ssl._create_unverified_context()
        conn = conn_cls(parsed.hostname, parsed.port, **kwargs)
        try:
            conn.request("GET", "/framework.php", headers={"Host": parsed.hostname or "", "Cookie": cookie,
                                                          "User-Agent": "sangfor-keepalive-experiment/1.0"})
            resp = conn.getresponse()
            body = resp.read(2048)
            status = resp.status
            location = resp.getheader("Location") or ""
        finally:
            conn.close()
        expired = status in (301, 302, 303, 307, 308) or b"login" in body[:2000].lower()
        return ("expired" if expired else "alive"), status, location[:80]
    except Exception as exc:  # noqa: BLE001
        return "error", "", f"{type(exc).__name__}: {exc}"[:80]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--session-file", default="secrets/firewall_session.json")
    parser.add_argument("--out", default="/tmp/keepalive_obs/experiment.csv")
    parser.add_argument("--probe-interval", type=int, default=120)
    parser.add_argument("--refresh-interval", type=int, default=300)
    parser.add_argument("--duration", type=int, default=3600)
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument("--max-consecutive-failures", type=int, default=3)
    args = parser.parse_args()

    session = json.loads(Path(args.session_file).read_text(encoding="utf-8"))
    base = str(session["base_url"]).rstrip("/")
    cookie = str(session["cookie"])
    target = base + "/framework.php"
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    started = time.monotonic()
    sample = 0
    failures = 0
    last_verdict, last_url, last_msg = "(未刷新)", "", ""
    # 注意：time.monotonic() 是大数值，用 0.0 做起点会导致条件恒真、每轮都触发
    # （2026-09-20 实测踩过：0.5s 一轮刷了 94 次）；起点必须取当前时刻。
    next_probe = time.monotonic()
    next_refresh = time.monotonic()

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
        try:
            context = browser.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 950})
            context.add_cookies(parse_cookie_header(cookie, base))
            page = context.new_page()
            with out_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=FIELDS)
                writer.writeheader()
                fh.flush()
                print(f"[{datetime.now():%H:%M:%S}] experiment started; probe={args.probe_interval}s "
                      f"refresh={args.refresh_interval}s target={target}", flush=True)
                while (time.monotonic() - started) < args.duration:
                    now = time.monotonic()
                    if now >= next_refresh:
                        try:
                            page.goto(target, wait_until="domcontentloaded", timeout=int(args.timeout * 1000))
                            info = page_login_info(page)
                            last_url = str(info.get("url", ""))
                            if is_login_page_info(info):
                                last_verdict, last_msg = "expired", "login page detected"
                            else:
                                last_verdict, last_msg, failures = "ok", "", 0
                        except Exception as exc:  # noqa: BLE001
                            failures += 1
                            last_verdict, last_msg = "retry", f"{type(exc).__name__}: {exc}"[:120]
                        print(f"[{datetime.now():%H:%M:%S}] refresh -> {last_verdict} {last_url or last_msg}", flush=True)
                        next_refresh = time.monotonic() + args.refresh_interval
                    if now >= next_probe:
                        sample += 1
                        state, status, location = probe_session(base, cookie, 15)
                        row = {"sample": sample, "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                               "elapsed_s": round(time.monotonic() - started), "probe_state": state,
                               "probe_http": status, "probe_location": location,
                               "refresh_verdict": last_verdict, "refresh_url": last_url,
                               "refresh_message": last_msg, "consecutive_failures": failures}
                        writer.writerow(row)
                        fh.flush()
                        print(f"[{row['time']}] #{sample} probe={state} http={status} refresh={last_verdict}", flush=True)
                        next_probe = time.monotonic() + args.probe_interval
                        if state == "expired" or last_verdict == "expired":
                            print(f"[{datetime.now():%H:%M:%S}] session expired -> stop", flush=True)
                            break
                        if failures >= args.max_consecutive_failures:
                            print(f"[{datetime.now():%H:%M:%S}] too many refresh failures -> stop", flush=True)
                            break
                    time.sleep(0.5)
                else:
                    print(f"[{datetime.now():%H:%M:%S}] duration reached ({args.duration}s)", flush=True)
        finally:
            browser.close()
    print(f"[{datetime.now():%H:%M:%S}] experiment finished; rows={sample} -> {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
