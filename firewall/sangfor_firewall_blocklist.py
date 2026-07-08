#!/usr/bin/env python3
import argparse
import gzip
import hashlib
import http.client
import json
import re
import ssl
import sys
from datetime import date
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse

DEFAULT_BASE_URL = "https://172.16.1.116"
SESSION_FILE = Path("/home/user/.config/sangfor-firewall/session.json")
DEFAULT_CSRF_TOKEN = None
OUTPUT_DIR = Path("outputs")
EXPORT_RE = re.compile(rb"(/export/blacklist_[^\"'\s<>]+\.csv)")


def build_firewall_blacklist_output_path(output_dir=OUTPUT_DIR):
    return Path(output_dir) / "sangfor_firewall_blacklists.csv"


class HttpError(RuntimeError):
    pass


class HttpClientTransport:
    def __init__(self, verify_tls=False, timeout=20):
        self.timeout = timeout
        self.context = None
        if not verify_tls:
            self.context = ssl._create_unverified_context()

    def request(self, method, url, *, headers=None, data=None):
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        if parsed.scheme == "https":
            conn = http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=self.timeout, context=self.context)
        else:
            conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=self.timeout)
        try:
            conn.request(method, path, body=data, headers=headers or {})
            response = conn.getresponse()
            body = response.read()
            if body[:2] == b"\x1f\x8b":
                body = gzip.decompress(body)
            return response.status, dict(response.getheaders()), body
        finally:
            conn.close()


UrllibTransport = HttpClientTransport


def extract_export_file(body):
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None

    if payload is not None:
        found = _find_csv_path(payload)
        if found:
            return found

    match = EXPORT_RE.search(body)
    if match:
        return match.group(1).decode("utf-8")

    raise ValueError("导出接口响应中没有找到 /export/blacklist_*.csv")


def _find_csv_path(value):
    if isinstance(value, str):
        match = re.search(r"(/export/blacklist_[^\"'\s<>]+\.csv)", value)
        if match:
            return match.group(1)
        match = re.search(r"(blacklist_[^\"'\s<>]+\.csv)", value)
        return f"/export/{match.group(1)}" if match else None
    if isinstance(value, dict):
        for item in value.values():
            found = _find_csv_path(item)
            if found:
                return found
    if isinstance(value, list):
        for item in value:
            found = _find_csv_path(item)
            if found:
                return found
    return None


def build_entries(targets, description):
    entries = []
    seen = set()
    for target in targets:
        value = target.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        entries.append({"url": value, "description": description, "type": "BLACK"})
    return entries


def default_description(today=None):
    today = today or date.today()
    return f"{today.month}月封禁"


def csrf_token_from_cookie(cookie):
    match = re.search(r"(?:^|;\s*)SESSID=([^;]+)", cookie)
    if not match:
        raise ValueError("Cookie 中没有找到 SESSID，无法自动计算 _cftoken")
    token = match.group(1)
    for _ in range(3):
        token = hashlib.md5(token.encode("utf-8")).hexdigest()
    return token


def load_session_file(path=SESSION_FILE):
    session_path = Path(path)
    payload = json.loads(session_path.read_text(encoding="utf-8"))
    base_url = payload.get("base_url") or payload.get("host")
    cookie = payload.get("cookie") or payload.get("Cookie")
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError(f"{session_path} 中没有非空 base_url 字段")
    if not isinstance(cookie, str) or not cookie.strip():
        raise ValueError(f"{session_path} 中没有非空 cookie 字段")
    csrf = payload.get("csrf") if isinstance(payload.get("csrf"), dict) else {}
    csrf_token = payload.get("csrf_token") or payload.get("_cftoken") or csrf.get("_cftoken")
    return {
        "base_url": base_url.strip(),
        "cookie": cookie.strip(),
        "csrf_token": csrf_token.strip() if isinstance(csrf_token, str) and csrf_token.strip() else None,
    }


def load_cookie_from_session_file(path=SESSION_FILE):
    return load_session_file(path)["cookie"]


def resolve_cookie(cli_cookie=None, session_path=SESSION_FILE):
    if cli_cookie:
        return cli_cookie
    return load_cookie_from_session_file(session_path)


def resolve_auth_config(args):
    if args.session_file:
        session = load_session_file(args.session_file)
        return session["base_url"], session["cookie"], session["csrf_token"] or args.csrf_token
    if not args.cookie:
        raise ValueError("missing required cookie; provide --session-file or --cookie")
    return args.base_url, args.cookie, args.csrf_token


class BlacklistClient:
    def __init__(
        self,
        base_url=DEFAULT_BASE_URL,
        cookie=None,
        csrf_token=DEFAULT_CSRF_TOKEN,
        transport=None,
    ):
        self.base_url = base_url.rstrip("/")
        self.cookie = cookie
        self.csrf_token = csrf_token or csrf_token_from_cookie(cookie)
        self.transport = transport or UrllibTransport()

    def check_login(self):
        status, headers, body = self._request("GET", "/framework.php")
        content = body[:300].decode("utf-8", errors="replace")
        return status, headers, content

    def export_blacklist(self):
        payload = {
            "moduleName": "blacklist",
            "filter": [],
            "isAll": True,
            "exportType": "CSV",
        }
        status, _, body = self._request(
            "POST",
            "/api/v1/namespaces/public/export",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            extra_headers=self._ajax_headers(),
        )
        if status >= 400:
            raise HttpError(f"导出黑名单失败，HTTP {status}")
        return extract_export_file(body)

    def download_export(self, export_file, output_dir=OUTPUT_DIR):
        status, _, body = self._request(
            "POST",
            f"/php/loadfile.php?file={export_file}",
            data=b"",
            extra_headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.base_url,
                "Referer": f"{self.base_url}/framework.php",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "iframe",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-User": "?1",
                "Priority": "u=4",
            },
        )
        if status >= 400:
            raise HttpError(f"下载导出文件失败，HTTP {status}")
        output_dir_path = Path(output_dir)
        output_dir_path.mkdir(parents=True, exist_ok=True)
        for old_file in output_dir_path.glob("blacklist*.csv"):
            old_file.unlink()
        output_path = build_firewall_blacklist_output_path(output_dir)
        output_path.write_bytes(body)
        return output_path

    def block(self, targets, description):
        entries = build_entries(targets, description)
        if not entries:
            raise ValueError("没有可封禁的目标")
        data = json.dumps(entries, ensure_ascii=False).encode("utf-8")
        status, headers, body = self._request(
            "POST",
            "/api/batch/v1/namespaces/public/whiteblacklist?override=SKIPBACK",
            data=data,
            extra_headers=self._ajax_headers(),
        )
        if status >= 400:
            detail = body[:500].decode("utf-8", errors="replace")
            raise HttpError(f"封禁请求失败，HTTP {status}: {detail}")
        return status, headers, body

    def _request(self, method, path, *, data=None, extra_headers=None):
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.5",
            "Cookie": self.cookie,
        }
        if extra_headers:
            headers.update(extra_headers)
        url = urljoin(f"{self.base_url}/", path.lstrip("/"))
        try:
            return self.transport.request(method, url, headers=headers, data=data)
        except HTTPError as exc:
            return exc.code, dict(exc.headers.items()), exc.read()
        except URLError as exc:
            raise HttpError(f"请求 {url} 失败: {exc.reason}") from exc

    def _ajax_headers(self, include_cftoken=True):
        headers = {
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": self.base_url,
            "Referer": f"{self.base_url}/framework.php",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Priority": "u=0",
        }
        if include_cftoken:
            headers["_cftoken"] = self.csrf_token
        return headers


def read_targets(args):
    targets = list(args.targets or [])
    if args.file:
        targets.extend(Path(args.file).read_text(encoding="utf-8").splitlines())
    return targets


def parse_args(argv):
    parser = argparse.ArgumentParser(description="自动导出黑名单并批量封禁恶意域名/IP")
    parser.add_argument("targets", nargs="*", help="要封禁的域名或 IP")
    parser.add_argument("-f", "--file", help="从文件读取目标，每行一个")
    parser.add_argument("--session-file", default=None, help=f"读取防火墙 session JSON 文件，默认可用 {SESSION_FILE}")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--cookie", default=None, help="Cookie header value; required unless --session-file is provided")
    parser.add_argument("--csrf-token", default=DEFAULT_CSRF_TOKEN, help="不传则自动用 Cookie 里的 SESSID 计算")
    parser.add_argument("--desc", "--description", dest="description", default=default_description(), help="封禁说明，默认当前月份+封禁")
    parser.add_argument("--output-dir", default=str(OUTPUT_DIR))
    parser.add_argument("--verify-tls", action="store_true", help="校验 HTTPS 证书")
    parser.add_argument("--check-login", action="store_true", help="只检查 Cookie 是否可访问首页")
    parser.add_argument("--export", action="store_true", help="导出并下载当前黑名单")
    parser.add_argument("--execute", action="store_true", help="真正提交封禁；不加则只 dry-run")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    try:
        base_url, cookie, csrf_token = resolve_auth_config(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    client = BlacklistClient(
        base_url=base_url,
        cookie=cookie,
        csrf_token=csrf_token,
        transport=UrllibTransport(verify_tls=args.verify_tls),
    )

    if args.check_login:
        status, _, preview = client.check_login()
        print(f"check-login HTTP {status}")
        print(preview)
        return 0 if status < 400 else 1

    if args.export:
        export_file = client.export_blacklist()
        output_path = client.download_export(export_file, args.output_dir)
        print(f"export_file={export_file}")
        print(f"downloaded={output_path}")

    targets = read_targets(args)
    entries = build_entries(targets, args.description)
    if entries:
        print(json.dumps(entries, ensure_ascii=False, indent=2))
        if args.execute:
            status, _, body = client.block(targets, args.description)
            print(f"block HTTP {status}")
            print(body[:1000].decode("utf-8", errors="replace"))
        else:
            print("dry-run: 加 --execute 才会真正提交封禁")
    elif not args.export:
        print("没有提供封禁目标。可传入参数或使用 --file。", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
