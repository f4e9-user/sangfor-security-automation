#!/usr/bin/env python3
import argparse
import http.client
import json
import signal
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


STOP = False
DEFAULT_STATUS_FILE = Path("state/sip_session.status.json")


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _handle_signal(signum, frame) -> None:
    global STOP
    STOP = True


def build_headers(host: str, cookie: str, xid: str) -> dict:
    return {
        "Host": host,
        "Connection": "keep-alive",
        "feature_id": "/logsearch",
        "sec-ch-ua-platform": '"Linux"',
        "sec-ch-ua": '"Chromium";v="145", "Not:A-Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "xid": xid,
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Origin": f"https://{host}",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": f"https://{host}/ui/",
        "Accept-Encoding": "identity",
        "Accept-Language": "en-US,en;q=0.9",
        "Cookie": cookie,
    }


def do_post(
    conn: http.client.HTTPSConnection,
    path: str,
    headers: dict,
    payload: dict,
    timeout_s: float,
    max_read_bytes: int,
):
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    conn.timeout = timeout_s

    conn.request("POST", path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read(max_read_bytes)
    return resp.status, resp.reason, data


def _try_decode_json(data: bytes):
    try:
        return json.loads(data.decode("utf-8", errors="strict"))
    except Exception:
        return None


def should_exit_after_response(status: int, obj, stop_on_need_login: bool) -> bool:
    if status == 302:
        return True
    return isinstance(obj, dict) and obj.get("data", {}).get("need_login") is True


def write_status(path, *, healthy: bool, need_login=None, session_file: str | None = None, error: str = "", status: int | None = None) -> None:
    status_path = Path(path).expanduser()
    status_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "healthy": healthy,
        "need_login": need_login,
        "timestamp": _now_iso(),
        "session_file": session_file or "",
        "error": error,
    }
    if status is not None:
        payload["status"] = status
    status_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def load_session_file(path) -> dict:
    session_path = Path(path)
    payload = json.loads(session_path.read_text(encoding="utf-8"))
    required = ["base_url", "cookie", "xid"]
    missing = [name for name in required if not isinstance(payload.get(name), str) or not payload[name].strip()]
    if missing:
        raise ValueError(f"{session_path} missing required field(s): {', '.join(missing)}")
    return {name: payload[name].strip() for name in required}


def _host_from_base_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    if not parsed.hostname:
        raise ValueError("session base_url must include a host")
    if parsed.port:
        return f"{parsed.hostname}:{parsed.port}"
    return parsed.hostname


def resolve_auth_args(args):
    if args.session_file:
        session = load_session_file(args.session_file)
        return _host_from_base_url(session["base_url"]), session["cookie"], session["xid"]
    missing = [name for name in ("cookie", "xid") if not getattr(args, name)]
    if missing:
        raise ValueError(f"missing required argument(s): {', '.join(missing)}; provide --session-file or explicit credentials")
    return args.host, args.cookie, args.xid


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Keep a Sangfor SIP Cookie alive by sending a log query request every N seconds (default 300)."
    )
    parser.add_argument("--session-file", help="Read base_url, cookie, and xid from a Sangfor SIP session JSON file")
    parser.add_argument("--host", default="172.16.1.118", help="API host used with explicit --cookie and --xid")
    parser.add_argument(
        "--path",
        default="/apps/secvisual/log_query2/ksearch_log/check_query_string",
        help="Request path",
    )
    parser.add_argument("--interval", type=int, default=300, help="Seconds between requests (default: 300)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout seconds (default: 10)")
    parser.add_argument("--max-read-bytes", type=int, default=1048576, help="Max bytes to read per response")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS cert verification (self-signed certs)")
    parser.add_argument("--stop-on-need-login", action="store_true", help="Deprecated: need_login responses always stop the keepalive")
    parser.add_argument("--status-file", default=str(DEFAULT_STATUS_FILE), help="Health status JSON output path")
    parser.add_argument("--xid", default=None, help="xid header value; required unless --session-file is provided")
    parser.add_argument("--cookie", default=None, help="Cookie header value; required unless --session-file is provided")
    parser.add_argument("--query", default="src_ip:1.1.1.1", help='query_string value (default: "src_ip:1.1.1.1")')
    parser.add_argument("--view-branch-id", type=int, default=0, help="view_branch_id value (default: 0)")
    args = parser.parse_args()

    try:
        host, cookie, xid = resolve_auth_args(args)
    except ValueError as exc:
        parser.error(str(exc))

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    payload = {"query_string": args.query, "view_branch_id": args.view_branch_id}
    headers = build_headers(host, cookie, xid)

    ctx = ssl._create_unverified_context() if args.insecure else ssl.create_default_context()

    conn = None
    next_t = time.monotonic()
    attempt = 0
    preserve_exit_status = False

    while not STOP:
        now = time.monotonic()
        if now < next_t:
            time.sleep(min(0.5, next_t - now))
            continue

        if conn is None:
            conn = http.client.HTTPSConnection(host, 443, context=ctx, timeout=args.timeout)

        attempt += 1
        try:
            status, reason, data = do_post(
                conn,
                args.path,
                headers,
                payload,
                args.timeout,
                args.max_read_bytes,
            )

            obj = _try_decode_json(data)
            if status == 302:
                write_status(args.status_file, healthy=False, need_login=None, session_file=args.session_file, error="redirect", status=status)
                sys.stdout.write(f"[{_now_iso()}] #{attempt} {status} {reason} redirect=true exiting\n")
                sys.stdout.flush()
                preserve_exit_status = True
                break
            if isinstance(obj, dict) and obj.get("data", {}).get("need_login") is True:
                msg = obj.get("message", "")
                href = obj.get("data", {}).get("href", "")
                write_status(args.status_file, healthy=False, need_login=True, session_file=args.session_file, error=msg or "need_login", status=status)
                sys.stdout.write(f"[{_now_iso()}] #{attempt} {status} {reason} need_login=true href={href} message={msg}\n")
                sys.stdout.flush()
                if should_exit_after_response(status, obj, args.stop_on_need_login):
                    preserve_exit_status = True
                    break
            else:
                write_status(args.status_file, healthy=status < 400, need_login=False, session_file=args.session_file, error="" if status < 400 else f"HTTP {status}", status=status)
                snippet = data[:300]
                sys.stdout.write(f"[{_now_iso()}] #{attempt} {status} {reason} body_snip={snippet!r}\n")
            sys.stdout.flush()

            next_t += args.interval
        except Exception as e:
            write_status(args.status_file, healthy=False, need_login=None, session_file=args.session_file, error=str(e))
            sys.stdout.write(f"[{_now_iso()}] #{attempt} ERROR: {e}\n")
            sys.stdout.flush()
            try:
                conn.close()
            except Exception:
                pass
            conn = None

            next_t = time.monotonic() + min(5.0, args.interval)

    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
    if not preserve_exit_status:
        write_status(args.status_file, healthy=True, need_login=False, session_file=args.session_file, error="stopped")
    sys.stdout.write(f"[{_now_iso()}] stopped\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
