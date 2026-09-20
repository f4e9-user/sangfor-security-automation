#!/usr/bin/env python3
"""Export Sangfor SIP Ksearch logs by favorite query and time range."""
from __future__ import annotations

import argparse
import base64
import io
import json
import math
import os
import re
import time
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlencode, urlparse

from openpyxl import load_workbook
from playwright.sync_api import Error, BrowserContext, Page, sync_playwright

DEFAULT_BASE_URL = "https://sip.local"
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


def parse_cookie_header(raw: str, domain: str = "sip.local") -> list[dict]:
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


def effective_split_limit(export_limit: int) -> int:
    """Leave headroom for SIP's eventually consistent total-count endpoint."""
    if export_limit <= 0:
        raise ValueError("export limit must be positive")
    return max(1, int(export_limit * 0.95))


INVALID_XML_BYTES = re.compile(
    rb"[\x00-\x08\x0b\x0c\x0e-\x1f]"           # XML 1.0 禁止的 C0 控制字符
    rb"|\xef\xbf[\xbe\xbf]"                     # U+FFFE / U+FFFF
    rb"|\xef\xb7[\x90-\xaf]"                    # U+FDD0..U+FDEF（非字符）
    rb"|[\xf0-\xf4][\x80-\xbf]\xbf[\xbe\xbf]"   # 补充平面非字符（低 16 位为 FFFE/FFFF）
)
"""Bytes that XML 1.0 forbids. SIP 会把原始载荷按有损方式解码后写进 sharedStrings，
实测出现过 U+FFFF 与 U+FDD0..U+FDEF 非字符（2026-09-11 那次 export-logs 失败的真因）。"""
DOWNLOAD_TIMEOUT_MS = 900_000
DOWNLOAD_ATTEMPTS = int(os.environ.get("SANGFOR_EXPORT_ATTEMPTS", "3"))
DOWNLOAD_BACKOFF_SECONDS = (3, 10, 20)


def _xml_is_wellformed(data: bytes) -> str | None:
    """Return the parse error when the XML payload is not well-formed, else None."""
    try:
        parser = ET.iterparse(io.BytesIO(data))
        for _ in parser:
            pass
    except ET.ParseError as exc:
        return str(exc)
    return None


def workbook_problem(path: str | Path) -> str | None:
    """Return a human-readable reason when the downloaded workbook is unusable, else None."""
    path = Path(path)
    if not path.exists() or path.stat().st_size == 0:
        return "downloaded workbook is missing or empty"
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        return f"not a readable xlsx zip ({exc})"
    with archive:
        names = archive.namelist()
        if "xl/workbook.xml" not in names:
            return "downloaded workbook is incomplete: xl/workbook.xml is missing"
        if not any(name.startswith("xl/worksheets/") and name.endswith(".xml") for name in names):
            return "downloaded workbook is incomplete: no worksheet part"
        if "[Content_Types].xml" in names:
            declared = re.findall(
                r'PartName="([^"]+)"',
                archive.read("[Content_Types].xml").decode("utf-8", "replace"),
            )
            missing = [part for part in declared if part.lstrip("/") not in names]
            if missing:
                return f"downloaded workbook is incomplete: declared parts missing ({', '.join(missing[:3])})"
        broken = archive.testzip()
        if broken:
            return f"zip member is corrupt: {broken}"
        for name in names:
            if not (name.endswith(".xml") or name.endswith(".rels")):
                continue
            data = archive.read(name)
            if INVALID_XML_BYTES.search(data):
                return f"{name} contains bytes that XML 1.0 forbids"
            error = _xml_is_wellformed(data)
            if error:
                return f"{name} is not well-formed XML ({error})"
    return None


def repair_workbook_in_place(path: str | Path) -> list[str]:
    """Strip bytes that XML 1.0 forbids from every XML member. Returns the repaired member names."""
    path = Path(path)
    repaired: list[str] = []
    tmp_path = path.with_name(path.name + ".repairing")
    with zipfile.ZipFile(path) as source, zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as target:
        for item in source.infolist():
            data = source.read(item.filename)
            if item.filename.endswith(".xml"):
                hits = INVALID_XML_BYTES.findall(data)
                if hits:
                    data = INVALID_XML_BYTES.sub(b"", data)
                    repaired.append(f"{item.filename} ({len(hits)} 处非法字符)")
            target.writestr(item, data)
    if repaired:
        tmp_path.replace(path)
    else:
        tmp_path.unlink(missing_ok=True)
    return repaired


def ensure_readable_workbook(path: str | Path) -> str | None:
    """Validate the download; strip XML-invalid bytes in place when that is the only problem.

    Returns a note describing the repair, or None when the file was already clean.
    """
    problem = workbook_problem(path)
    if problem is None:
        return None
    try:
        repaired = repair_workbook_in_place(path)
    except Exception as exc:  # noqa: BLE001 - the zip itself is unreadable
        raise RuntimeError(f"downloaded workbook is unusable ({problem}) and cannot be repaired: {exc}") from exc
    problem_after = workbook_problem(path)
    if problem_after is not None:
        raise RuntimeError(
            f"downloaded workbook is still unusable after repair: {problem_after} (initial problem: {problem})"
        )
    return f"stripped XML-invalid bytes from {', '.join(repaired)}" if repaired else f"recovered from: {problem}"


def download_candidate_with_retry(
    export_candidate: Callable[[Segment, Path], str],
    segment: Segment,
    candidate_path: Path,
    *,
    attempts: int = DOWNLOAD_ATTEMPTS,
) -> str:
    """Download one segment, verifying the workbook; retry transient/corrupt downloads.

    Corrupt downloads are preserved next to the candidate as ``*.bad<N>.xlsx`` for forensics.
    """
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        candidate_path.unlink(missing_ok=True)
        try:
            server_file = export_candidate(segment, candidate_path)
            note = ensure_readable_workbook(candidate_path)
            if note:
                print(f"REPAIRED {segment.start:%Y-%m-%d %H:%M:%S} -> {segment.end:%Y-%m-%d %H:%M:%S}: {note}", flush=True)
            return server_file
        except Exception as exc:  # noqa: BLE001 - report and retry
            last_error = exc
            if candidate_path.exists():
                keep_path = candidate_path.with_name(f"{candidate_path.stem}.bad{attempt}.xlsx")
                candidate_path.replace(keep_path)
                print(
                    f"RETRY download {segment.start:%Y-%m-%d %H:%M:%S} -> {segment.end:%Y-%m-%d %H:%M:%S}: "
                    f"attempt {attempt}/{attempts} failed ({exc}); kept {keep_path.name}",
                    flush=True,
                )
            else:
                print(
                    f"RETRY download {segment.start:%Y-%m-%d %H:%M:%S} -> {segment.end:%Y-%m-%d %H:%M:%S}: "
                    f"attempt {attempt}/{attempts} failed ({exc})",
                    flush=True,
                )
            if attempt < attempts:
                time.sleep(DOWNLOAD_BACKOFF_SECONDS[min(attempt - 1, len(DOWNLOAD_BACKOFF_SECONDS) - 1)])
    raise RuntimeError(
        f"segment download failed after {attempts} attempts "
        f"({segment.start:%Y-%m-%d %H:%M:%S} -> {segment.end:%Y-%m-%d %H:%M:%S}): {last_error}"
    )


def count_export_rows(path: str | Path) -> int:
    """Count non-empty data rows below SIP's seven preamble rows and header."""
    ensure_readable_workbook(path)
    workbook = load_workbook(path, read_only=True, data_only=True)
    try:
        sheet = workbook.active
        return sum(1 for row in sheet.iter_rows(min_row=9, values_only=True) if any(value is not None for value in row))
    finally:
        workbook.close()


def adaptive_export_segments(
    segments: Iterable[Segment],
    *,
    export_candidate: Callable[[Segment, Path], str],
    row_counter: Callable[[Path], int],
    output_dir: Path,
    export_date: str | date,
    export_limit: int,
    overwrite: bool = False,
) -> list[dict]:
    """Export segments, recursively splitting any downloaded workbook that hits the hard limit."""
    pending = list(segments)
    exported: list[dict] = []
    candidate_path = output_dir / ".sangfor-export-candidate.xlsx"

    try:
        while pending:
            segment = pending.pop(0)
            server_file = download_candidate_with_retry(export_candidate, segment, candidate_path)
            actual_count = row_counter(candidate_path)

            if actual_count >= export_limit:
                candidate_path.unlink(missing_ok=True)
                duration_seconds = int((segment.end - segment.start).total_seconds())
                if duration_seconds < 1:
                    raise ValueError(
                        f"export segment reached export limit and cannot split further: "
                        f"{segment.start:%Y-%m-%d %H:%M:%S} -> {segment.end:%Y-%m-%d %H:%M:%S}"
                    )
                midpoint = segment.start + timedelta(seconds=duration_seconds // 2)
                pending[0:0] = [
                    Segment(segment.start, midpoint, 0),
                    Segment(midpoint + timedelta(seconds=1), segment.end, 0),
                ]
                print(
                    f"RETRY split {segment.start:%Y-%m-%d %H:%M:%S} -> "
                    f"{segment.end:%Y-%m-%d %H:%M:%S}: downloaded {actual_count} rows",
                    flush=True,
                )
                continue

            file_name = build_output_name(export_date, len(exported) + 1)
            output_path = output_dir / file_name
            if output_path.exists() and not overwrite:
                candidate_path.unlink(missing_ok=True)
                raise FileExistsError(f"refusing to overwrite {output_path}; pass --overwrite")
            candidate_path.replace(output_path)
            accepted = Segment(segment.start, segment.end, actual_count)
            exported.append(
                accepted.to_manifest(file_name=file_name)
                | {"actual_count": actual_count, "server_file": server_file}
            )
            print(f"EXPORTED {file_name}: {actual_count}", flush=True)
    finally:
        candidate_path.unlink(missing_ok=True)

    return exported


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
        # 在 Python 侧直接取字节：大段落经 page.evaluate 的 base64/CDP 传输会被截断，
        # 是 2026-09-11 那次 export-logs 失败的直接成因之一。
        # 注意：SIP 的 on_download 端点强制校验浏览器同源来源，缺 Referer 会返回
        # {"message":"CSRF Protection","success":false}（2026-09-11 实测：加 Referer 即恢复）。
        response = self.page.context.request.get(
            download_url,
            headers={
                "xid": self.xid,
                "feature_id": "/logsearch",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": f"{self.base_url}/ui/",
            },
            timeout=DOWNLOAD_TIMEOUT_MS,
            fail_on_status_code=False,
        )
        body = response.body()
        if response.status != 200:
            raise RuntimeError(f"download failed: HTTP {response.status} {body[:200]!r}")
        if not body.startswith(b"PK"):
            raise RuntimeError(f"download is not an xlsx file: {body[:80]!r}")
        output_path.write_bytes(body)
        return server_file


def launch_chromium(playwright, *, headless: bool = True):
    """启动 Chromium：优先用默认（headless shell），可执行文件缺失时回落到完整 chromium。

    2026-09-20 实测：本机 Playwright 1.61 默认要 `chromium_headless_shell-1228`，但只装了 1223 版，
    默认启动会直接 `Executable doesn't exist`；改用 `channel="chromium"`（完整 chromium-1228）
    无需额外下载即可正常运行，因此做成自动回落，避免导出阶段被浏览器版本卡死。
    """
    args = ["--ignore-certificate-errors"]
    try:
        return playwright.chromium.launch(headless=headless, args=args)
    except Error as exc:  # noqa: F821 - 由调用方导入的 playwright 错误类型
        if "Executable doesn't exist" not in str(exc):
            raise
        return playwright.chromium.launch(headless=headless, channel="chromium", args=args)


def make_context(browser, base_url: str, cookie_header: str) -> BrowserContext:
    parsed = urlparse(base_url)
    domain = parsed.hostname or "sip.local"
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
        browser = launch_chromium(playwright)
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

            split_limit = effective_split_limit(args.limit)
            segments = split_segments(start, end, cached_counter, limit=split_limit)
            manifest_segments = []
            if not args.dry_run:
                manifest_segments = adaptive_export_segments(
                    segments,
                    export_candidate=lambda segment, path: exporter.export_segment(favorite, segment, path),
                    row_counter=count_export_rows,
                    output_dir=output_dir,
                    export_date=args.export_date,
                    export_limit=args.limit,
                    overwrite=args.overwrite,
                )
            else:
                manifest_segments = [segment.to_manifest() for segment in segments]
            segment_total_count = sum(int(segment["count"]) for segment in manifest_segments)

            manifest = {
                "base_url": base_url,
                "favorite_name": args.favorite_name,
                "query_string": favorite.get("query_string") or favorite.get("search_condition"),
                "requested_start": start.strftime(DATETIME_FORMAT),
                "requested_end": end.strftime(DATETIME_FORMAT),
                "limit": args.limit,
                "split_limit": split_limit,
                "total_count": total_count,
                "segment_total_count": segment_total_count,
                "segment_count": len(manifest_segments),
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
