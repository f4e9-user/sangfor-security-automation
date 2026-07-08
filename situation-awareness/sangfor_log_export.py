#!/usr/bin/env python3
"""Export Sangfor SIP Ksearch logs by favorite query and time range."""
from __future__ import annotations

import argparse
import base64
import json
import math
import os
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlencode, urlparse

from playwright.sync_api import BrowserContext, Page, sync_playwright

DEFAULT_BASE_URL = "https://172.16.1.118"
DEFAULT_OUTPUT_DIR = Path.home() / "sangfor-exports"
DEFAULT_SESSION_FILE = Path.home() / ".config" / "sangfor" / "session.json"
DEFAULT_KEY_FIELDS = "record_time,depict,module_type,attack_type,src_ip,src_classify1_id,src_port,dst_ip,dst_classify1_id,dst_port,level,net_action,status_code,dev_id,in_dev,attack_state,is_white,proxy"
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


@dataclass(frozen=True)
class Segment:
    start: datetime
    end: datetime
    count: int

    def to_manifest(self, file_name: str | None = None) -> dict:
        data = {
            "start": self.start.strftime(DATETIME_FORMAT),
            "end": self.end.strftime(DATETIME_FORMAT),
            "count": self.count,
        }
        if file_name:
            data["file_name"] = file_name
        return data


def parse_dt(value: str) -> datetime:
    return datetime.strptime(value, DATETIME_FORMAT)


def timestamp(value: str | datetime) -> int:
    if isinstance(value, str):
        value = parse_dt(value)
    return int(value.timestamp())


def sanitize_stamp(value: str | datetime) -> str:
    if isinstance(value, str):
        value = parse_dt(value)
    return value.strftime("%Y%m%d_%H%M%S")


def build_output_name(export_date: str | date, sequence: int) -> str:
    if isinstance(export_date, str):
        parsed = datetime.strptime(export_date, "%Y-%m-%d").date()
    else:
        parsed = export_date
    return f"sangfor-sip-report-KsearchLog-{parsed:%Y%m%d}{sequence:02d}.xlsx"


def parse_cookie_header(raw: str, domain: str = "172.16.1.118") -> list[dict]:
    cookies = []
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        cookies.append(
            {
                "name": name,
                "value": value,
                "domain": domain,
                "path": "/",
                "secure": True,
                "httpOnly": False,
                "sameSite": "Lax",
            }
        )
    return cookies


def load_session_file(path: str | Path) -> dict:
    session_path = Path(path).expanduser()
    data = json.loads(session_path.read_text(encoding="utf-8"))
    missing = [key for key in ("cookie", "xid") if not data.get(key)]
    if missing:
        raise ValueError(f"session file {session_path} missing required field(s): {', '.join(missing)}")
    if not data.get("base_url"):
        data["base_url"] = DEFAULT_BASE_URL
    return data


def resolve_auth_args(args: argparse.Namespace) -> tuple[str, str, str]:
    if getattr(args, "session_file", None):
        session = load_session_file(args.session_file)
        return session["cookie"], session["xid"], session["base_url"]
    if getattr(args, "cookie", None):
        cookie = args.cookie
    elif getattr(args, "cookie_file", None):
        cookie = Path(args.cookie_file).read_text(encoding="utf-8").strip()
    else:
        raise ValueError("one of --session-file, --cookie, or --cookie-file is required")
    if not getattr(args, "xid", None):
        raise ValueError("--xid is required unless --session-file is used")
    return cookie, args.xid, args.base_url


def build_payload(favorite: dict, start: str | datetime, end: str | datetime) -> dict:
    query_string = favorite.get("query_string") or favorite.get("search_condition") or favorite.get("query") or ""
    payload = {
        "index": favorite.get("index", "ngfw.security"),
        "range_type": favorite.get("range_type", "security_log:all"),
        "range_name": favorite.get("range_name", "安全检测日志"),
        "direction_type": favorite.get("direction_type", "outside"),
        "direction_name": favorite.get("direction_name", "外部"),
        "query_string": query_string,
        "search_condition": favorite.get("search_condition") or query_string,
        "filter": favorite.get("filter") or {"filter_op": "AND"},
        "start_time": timestamp(start),
        "end_time": timestamp(end),
        "view_branch_id": favorite.get("view_branch_id", 0),
        "type_click": False,
    }
    if favorite.get("id") is not None:
        payload["record_id"] = favorite["id"]
    return payload


def _find_best_segment_end(
    start: datetime,
    end: datetime,
    counter: Callable[[datetime, datetime], int],
    limit: int,
    granularity: timedelta,
) -> tuple[datetime, int]:
    low = start + granularity
    high = end
    best_end = low
    best_count = counter(start, low)

    while low <= high:
        seconds = int((high - low).total_seconds())
        steps = seconds // int(granularity.total_seconds())
        midpoint = low + granularity * (steps // 2)
        count = counter(start, midpoint)
        if count <= limit:
            best_end = midpoint
            best_count = count
            low = midpoint + granularity
        else:
            high = midpoint - granularity

    if best_end <= start:
        return end, counter(start, end)
    return best_end, best_count


def split_segments(
    start: datetime,
    end: datetime,
    counter: Callable[[datetime, datetime], int],
    limit: int = 10000,
    granularity: timedelta = timedelta(minutes=1),
) -> list[Segment]:
    if end <= start:
        raise ValueError("end must be later than start")
    if limit <= 0:
        raise ValueError("limit must be positive")

    segments: list[Segment] = []
    cursor = start
    remaining_total = counter(cursor, end)

    while remaining_total > limit:
        segment_end, segment_count = _find_best_segment_end(cursor, end, counter, limit, granularity)
        if segment_end >= end:
            break
        if segment_count <= 0:
            raise RuntimeError(f"cannot split non-empty interval at {cursor:%Y-%m-%d %H:%M:%S}")
        segments.append(Segment(cursor, segment_end, segment_count))
        cursor = segment_end + timedelta(seconds=1)
        remaining_total -= segment_count
        actual_remaining = counter(cursor, end)
        if actual_remaining != remaining_total:
            remaining_total = actual_remaining

    final_count = counter(cursor, end)
    if final_count > limit and cursor != start:
        segment_end, segment_count = _find_best_segment_end(cursor, end, counter, limit, granularity)
        if segment_end < end and segment_count > 0:
            segments.append(Segment(cursor, segment_end, segment_count))
            cursor = segment_end
            final_count = counter(cursor, end)
    segments.append(Segment(cursor, end, final_count))
    return segments


class SangforExporter:
    def __init__(self, page: Page, base_url: str, xid: str):
        self.page = page
        self.base_url = base_url.rstrip("/")
        self.xid = xid

    def load(self) -> None:
        self.page.goto(f"{self.base_url}/ui/#/logsearch", wait_until="domcontentloaded", timeout=60000)
        self.page.wait_for_timeout(1000)

    def post(self, path: str, payload: dict) -> dict:
        url = f"{self.base_url}{path}"
        result = self.page.evaluate(
            """
            async ({url, payload, xid}) => {
                const response = await fetch(url, {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest',
                        'xid': xid,
                        'feature_id': '/logsearch'
                    },
                    body: JSON.stringify(payload)
                });
                const text = await response.text();
                let data;
                try { data = JSON.parse(text); } catch (e) { data = {raw: text}; }
                return {status: response.status, ok: response.ok, data};
            }
            """,
            {"url": url, "payload": payload, "xid": self.xid},
        )
        if not result["ok"]:
            raise RuntimeError(f"POST {path} failed: HTTP {result['status']} {result['data']}")
        return result["data"]

    def get_favorite(self, favorite_name: str) -> dict:
        payload = {"record_type": 1, "page": 1, "start": 0, "limit": 200, "view_branch_id": 0}
        data = self.post("/apps/secvisual/log_query2/record_collection/on_search", payload)
        rows = data.get("data") or data.get("rows") or []
        if isinstance(rows, dict):
            rows = rows.get("rows") or rows.get("data") or []
        for row in rows:
            if str(row.get("record_name") or row.get("name")) == favorite_name:
                return row
        names = [str(row.get("record_name") or row.get("name")) for row in rows]
        raise RuntimeError(f"favorite {favorite_name!r} not found; available={names}")

    def count(self, favorite: dict, start: datetime, end: datetime) -> int:
        payload = build_payload(favorite, start, end)
        self.post("/apps/secvisual/log_query2/ksearch_log/on_open_index", payload)
        self.post("/apps/secvisual/log_query2/ksearch_log/on_search", payload)
        data = self.post("/apps/secvisual/log_query2/ksearch_log/get_total_count", payload)
        count = data.get("data", data.get("count", data.get("total")))
        if isinstance(count, dict):
            count = count.get("total") or count.get("count")
        if count is None:
            raise RuntimeError(f"cannot parse count response: {data}")
        return int(count)

    def export_segment(self, favorite: dict, segment: Segment, output_path: Path) -> str:
        payload = build_payload(favorite, segment.start, segment.end)
        payload["key_fields"] = DEFAULT_KEY_FIELDS
        data = self.post("/apps/secvisual/log_query2/ksearch_log/on_export", payload)
        server_file = data.get("data")
        if not server_file:
            raise RuntimeError(f"cannot parse export response: {data}")

        query = urlencode({"file": server_file, "xid": self.xid, "feature_id": "/logsearch"})
        download_url = f"{self.base_url}/apps/asset/branch_view/branch_view/on_download?{query}"
        result = self.page.evaluate(
            """
            async ({downloadUrl, xid}) => {
                const response = await fetch(downloadUrl, {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'xid': xid,
                        'feature_id': '/logsearch',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });
                const buffer = await response.arrayBuffer();
                const bytes = new Uint8Array(buffer);
                let binary = '';
                for (const byte of bytes) binary += String.fromCharCode(byte);
                return {
                    status: response.status,
                    ok: response.ok,
                    contentType: response.headers.get('content-type') || '',
                    bodyBase64: btoa(binary)
                };
            }
            """,
            {"downloadUrl": download_url, "xid": self.xid},
        )
        body = base64.b64decode(result["bodyBase64"])
        if not result["ok"]:
            raise RuntimeError(f"download failed: HTTP {result['status']} {body[:200]!r}")
        if not body.startswith(b"PK"):
            raise RuntimeError(f"download is not an xlsx file: {body[:80]!r}")
        output_path.write_bytes(body)
        return server_file


def make_context(browser, base_url: str, cookie_header: str) -> BrowserContext:
    parsed = urlparse(base_url)
    domain = parsed.hostname or "172.16.1.118"
    context = browser.new_context(ignore_https_errors=True, accept_downloads=True)
    context.add_cookies(parse_cookie_header(cookie_header, domain=domain))
    return context


def export_logs(args: argparse.Namespace) -> dict:
    start = parse_dt(args.start)
    end = parse_dt(args.end)
    cookie, xid, base_url = resolve_auth_args(args)
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
        try:
            context = make_context(browser, base_url, cookie)
            page = context.new_page()
            exporter = SangforExporter(page, base_url, xid)
            exporter.load()
            favorite = exporter.get_favorite(args.favorite_name)

            def counter(a: datetime, b: datetime) -> int:
                count = exporter.count(favorite, a, b)
                print(f"COUNT {a:%Y-%m-%d %H:%M:%S} -> {b:%Y-%m-%d %H:%M:%S}: {count}", flush=True)
                return count

            total_count = counter(start, end)

            def cached_counter(a: datetime, b: datetime) -> int:
                if a == start and b == end:
                    count = total_count
                    print(f"COUNT {a:%Y-%m-%d %H:%M:%S} -> {b:%Y-%m-%d %H:%M:%S}: {count}", flush=True)
                    return count
                return counter(a, b)

            segments = split_segments(start, end, cached_counter, limit=args.limit)
            segment_total_count = sum(segment.count for segment in segments)
            manifest_segments = []
            if not args.dry_run:
                for index, segment in enumerate(segments, start=1):
                    file_name = build_output_name(args.export_date, index)
                    output_path = output_dir / file_name
                    if output_path.exists() and not args.overwrite:
                        raise FileExistsError(f"refusing to overwrite {output_path}; pass --overwrite")
                    server_file = exporter.export_segment(favorite, segment, output_path)
                    manifest_segments.append(segment.to_manifest(file_name=file_name) | {"server_file": server_file})
                    print(f"EXPORTED {file_name}: {segment.count}", flush=True)
            else:
                manifest_segments = [segment.to_manifest() for segment in segments]

            manifest = {
                "base_url": base_url,
                "favorite_name": args.favorite_name,
                "query_string": favorite.get("query_string") or favorite.get("search_condition"),
                "requested_start": start.strftime(DATETIME_FORMAT),
                "requested_end": end.strftime(DATETIME_FORMAT),
                "limit": args.limit,
                "total_count": total_count,
                "segment_total_count": segment_total_count,
                "segment_count": len(segments),
                "export_date": args.export_date,
                "output_dir": str(output_dir),
                "dry_run": args.dry_run,
                "segments": manifest_segments,
                "generated_at": datetime.now().strftime(DATETIME_FORMAT),
            }
            manifest_path = output_dir / f"manifest-{sanitize_stamp(start)}-{sanitize_stamp(end)}.json"
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps(manifest, ensure_ascii=False, indent=2), flush=True)
            return manifest
        finally:
            browser.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--session-file", default=str(DEFAULT_SESSION_FILE), help="JSON file containing cookie, xid, and optional base_url")
    parser.add_argument("--cookie", help="Raw Cookie request header value")
    parser.add_argument("--cookie-file", help="File containing the raw Cookie request header value")
    parser.add_argument("--xid")
    parser.add_argument("--start", required=True, help="YYYY-MM-DD HH:MM:SS")
    parser.add_argument("--end", required=True, help="YYYY-MM-DD HH:MM:SS")
    parser.add_argument("--favorite-name", default="3")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--export-date", default=date.today().strftime("%Y-%m-%d"), help="YYYY-MM-DD used in output file names")
    parser.add_argument("--limit", type=int, default=10000)
    parser.add_argument("--dry-run", action="store_true", help="Count and split only; do not export files")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing output files")
    return parser


def main(argv: Iterable[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    default_session_missing = args.session_file == str(DEFAULT_SESSION_FILE) and not Path(args.session_file).exists()
    if default_session_missing and not args.cookie and not args.cookie_file:
        parser.error("one of --session-file, --cookie, or --cookie-file is required")
    try:
        export_logs(args)
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
