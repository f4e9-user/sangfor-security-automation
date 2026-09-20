from __future__ import annotations

import http.client
import json
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class MissingSessionError(RuntimeError):
    pass


@dataclass(frozen=True)
class SessionStatus:
    path: Path
    ok: bool
    fields: tuple[str, ...]


def validate_sip_session(path: str | Path) -> SessionStatus:
    data = _load_session(path)
    _require(data, ("cookie", "xid"), Path(path))
    return SessionStatus(path=Path(path), ok=True, fields=tuple(sorted(data.keys())))


def validate_firewall_session(path: str | Path) -> SessionStatus:
    data = _load_session(path)
    _require(data, ("cookie",), Path(path))
    return SessionStatus(path=Path(path), ok=True, fields=tuple(sorted(data.keys())))


def check_sip_session_health(path: str | Path, *, timeout: float = 10.0) -> dict[str, Any]:
    session_path = Path(path).expanduser()
    try:
        data = _load_session(session_path)
        _require(data, ("base_url", "cookie", "xid"), session_path)
        parsed = urlparse(str(data["base_url"]).strip())
        if not parsed.hostname:
            raise MissingSessionError("SIP session base_url must include a host")
        host_header = f"{parsed.hostname}:{parsed.port}" if parsed.port else parsed.hostname
        conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        conn_kwargs: dict[str, Any] = {"timeout": timeout}
        if parsed.scheme == "https":
            conn_kwargs["context"] = ssl._create_unverified_context()
        conn = conn_cls(parsed.hostname, parsed.port, **conn_kwargs)
        body = json.dumps({"query_string": "src_ip:1.1.1.1", "view_branch_id": 0}, separators=(",", ":")).encode("utf-8")
        headers = {
            "Host": host_header,
            "Cookie": str(data["cookie"]),
            "xid": str(data["xid"]),
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/json",
            "Accept": "application/json,*/*",
            # 2026-09-20 实测：缺这个头时 SIP 对任何请求一律回
            # `{"success":false,"message":"您没有权限进行此操作"}`（HTTP 200），
            # 于是健康检查把「会话已失效」误判成健康（构造性假健康）。
            # 带上 feature_id 才会走真正的会话校验并返回 `data.need_login`。
            "feature_id": "/logsearch",
        }
        try:
            conn.request("POST", "/apps/secvisual/log_query2/ksearch_log/check_query_string", body=body, headers=headers)
            response = conn.getresponse()
            payload = response.read(4096)
        finally:
            conn.close()
        obj = _try_json(payload)
        status = response.status
        body = obj if isinstance(obj, dict) else {}
        need_login = bool((body.get("data") or {}).get("need_login") is True)
        denied = body.get("success") is False and not need_login
        healthy = status < 400 and status != 302 and not need_login and not denied
        if need_login:
            error = "SIP session expired: 用户未登录或会话已过期"
        elif denied:
            error = f"SIP query rejected: {body.get('message') or 'success=false'}"
        elif not healthy:
            error = f"SIP query failed: HTTP {status}"
        else:
            error = ""
        return {
            "healthy": healthy,
            "need_login": need_login,
            "status": status,
            "session_file": str(session_path),
            "error": error,
        }
    except Exception as exc:
        return {"healthy": False, "need_login": None, "session_file": str(session_path), "error": str(exc)}


def check_firewall_session_health(path: str | Path, *, timeout: float = 10.0) -> dict[str, Any]:
    session_path = Path(path).expanduser()
    try:
        data = _load_session(session_path)
        _require(data, ("base_url", "cookie"), session_path)
        parsed = urlparse(str(data["base_url"]).strip().rstrip("/"))
        if not parsed.hostname:
            raise MissingSessionError("firewall session base_url must include a host")
        conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        conn_kwargs: dict[str, Any] = {"timeout": timeout}
        if parsed.scheme == "https":
            conn_kwargs["context"] = ssl._create_unverified_context()
        conn = conn_cls(parsed.hostname, parsed.port, **conn_kwargs)
        try:
            conn.request("GET", "/framework.php", headers={"Cookie": str(data["cookie"]), "Accept": "text/html,*/*"})
            response = conn.getresponse()
            body = response.read(4096).decode("utf-8", errors="replace")
            location = dict(response.getheaders()).get("Location", "")
        finally:
            conn.close()
        login_page = _looks_like_login_page(body, location)
        healthy = response.status < 400 and response.status not in {301, 302, 303, 307, 308} and not login_page
        return {
            "healthy": healthy,
            "login_page": login_page,
            "status": response.status,
            "session_file": str(session_path),
            "error": "" if healthy else "firewall framework page redirected to login or failed",
        }
    except Exception as exc:
        return {"healthy": False, "login_page": None, "session_file": str(session_path), "error": str(exc)}


def _load_session(path: str | Path) -> dict[str, Any]:
    session_path = Path(path).expanduser()
    if not session_path.exists():
        raise MissingSessionError(f"session file missing: {session_path}")
    try:
        data = json.loads(session_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise MissingSessionError(f"session file is not valid JSON: {session_path}") from exc
    if not isinstance(data, dict):
        raise MissingSessionError(f"session file must contain a JSON object: {session_path}")
    return data


def _require(data: dict[str, Any], keys: tuple[str, ...], path: Path) -> None:
    missing = [key for key in keys if not data.get(key)]
    if missing:
        raise MissingSessionError(f"session file {path} missing required field(s): {', '.join(missing)}")


def _try_json(data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except Exception:
        return None


def _looks_like_login_page(body: str, location: str) -> bool:
    haystack = f"{location}\n{body}".lower()
    return any(marker in haystack for marker in ("login.php", "欢迎登录", "password", "captcha", "验证码"))
