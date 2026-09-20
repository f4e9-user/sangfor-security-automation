#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""保活观测器：按固定间隔记录防火墙会话与保活进程的时间序列。

用途（2026-09-20 保活观测实验）：回答两个问题——
1. `firewall/firewall_keepalive.py`（新开 context 注入 cookie 的低阶策略）在真机上能活多久、
   以什么方式结束（networkidle 超时 / 落到登录页 / 其他异常）。
2. 同一 cookie 的会话在“浏览器手动登录”与“脚本注入 cookie 刷新”并存时，谁先失效。

只读：每个 tick 用 `http.client` 对 `/framework.php` 发一次 GET，**不跟重定向**
（302 → login 即判失效），并读取保活脚本写的 status JSON。不触碰防火墙配置。

用法：
    python scripts/observe_firewall_keepalive.py \
        --session-file secrets/firewall_session.json \
        --status-file /tmp/keepalive_obs/firewall_session.status.json \
        --out /tmp/keepalive_obs/timeseries.csv \
        --interval 60 --duration 3600
"""
from __future__ import annotations

import argparse
import csv
import http.client
import json
import signal
import ssl
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

STOP = False


def _handle_signal(signum, frame) -> None:  # noqa: ANN001
    global STOP
    STOP = True


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def probe_cookie_session(session_file: Path, *, timeout: float = 15.0) -> dict:
    """不复用保活脚本的浏览器：直接用 cookie GET /framework.php（不跟重定向）。"""
    try:
        payload = json.loads(Path(session_file).read_text(encoding="utf-8"))
        base = str(payload["base_url"]).rstrip("/")
        parsed = urlparse(base)
        conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        kwargs: dict = {"timeout": timeout}
        if parsed.scheme == "https":
            kwargs["context"] = ssl._create_unverified_context()
        conn = conn_cls(parsed.hostname, parsed.port, **kwargs)
        try:
            conn.request(
                "GET",
                "/framework.php",
                headers={"Host": parsed.hostname or "", "Cookie": str(payload["cookie"]), "User-Agent": "sangfor-obs/1.0"},
            )
            resp = conn.getresponse()
            body = resp.read(4096)
            status = resp.status
            location = resp.getheader("Location") or ""
        finally:
            conn.close()
        login_page = status in (301, 302, 303, 307, 308) or b"login" in body[:4000].lower()
        return {"cookie_session": "expired" if login_page else "alive", "http_status": status, "location": location[:80]}
    except Exception as exc:  # noqa: BLE001
        return {"cookie_session": "error", "http_status": "", "location": f"{type(exc).__name__}: {exc}"[:80]}


def read_status(path: Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return {"keepalive_ok": data.get("ok"), "keepalive_message": str(data.get("message", ""))[:60],
                "keepalive_url": str(data.get("url", ""))[:60], "keepalive_ts": str(data.get("timestamp", ""))[::-1][:0] or str(data.get("timestamp", ""))}
    except Exception:
        return {"keepalive_ok": "", "keepalive_message": "(无状态文件)", "keepalive_url": "", "keepalive_ts": ""}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--session-file", default="secrets/firewall_session.json")
    parser.add_argument("--status-file", default="state/firewall_session.status.json")
    parser.add_argument("--out", default="/tmp/keepalive_obs/timeseries.csv")
    parser.add_argument("--interval", type=int, default=60, help="Seconds between samples (default 60)")
    parser.add_argument("--duration", type=int, default=3600, help="Total seconds to observe (default 3600)")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    session_file = Path(args.session_file)
    status_file = Path(args.status_file)

    started = time.monotonic()
    fields = ["sample", "time", "elapsed_s", "cookie_session", "http_status", "location",
              "keepalive_ok", "keepalive_message", "keepalive_url", "keepalive_ts"]
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        fh.flush()
        sample = 0
        while not STOP and (time.monotonic() - started) < args.duration:
            sample += 1
            row = {"sample": sample, "time": _now(), "elapsed_s": round(time.monotonic() - started)}
            row.update(probe_cookie_session(session_file))
            row.update(read_status(status_file))
            writer.writerow(row)
            fh.flush()
            print(f"[{row['time']}] #{sample} cookie={row['cookie_session']} http={row['http_status']} "
                  f"keepalive_ok={row['keepalive_ok']} keepalive={row['keepalive_message']}", flush=True)
            deadline = time.monotonic() + args.interval
            while not STOP and time.monotonic() < deadline:
                time.sleep(min(0.5, deadline - time.monotonic()))
        print(f"[{_now()}] observer stopped after {round(time.monotonic() - started)}s -> {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
