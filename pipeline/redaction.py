from __future__ import annotations

import re
from typing import Any

SECRET_KEYS = {
    "cookie",
    "xid",
    "csrf",
    "_cftoken",
    "gcs_csrf",
    "password",
    "token",
    "api_key",
    "secret",
    "authorization",
    "set-cookie",
    "base_url",
    "url_base",
    "host",
}

_HEADER_RE = re.compile(r"(?im)^(\s*(?:Cookie|Authorization|Set-Cookie)\s*:\s*)([^\r\n]*)")
_JSON_FIELD_RE = re.compile(
    r'(?i)("(?:cookie|xid|csrf|_cftoken|gcs_csrf|password|token|api_key|secret|authorization|base_url|url_base|host)"\s*:\s*)'
    r'(?:("(?:\\.|[^"\\])*")|(\{[^\n{}]*(?:\{[^\n{}]*\}[^\n{}]*)*\})|([^,}\n]+))'
)
_CLI_RE = re.compile(r"(?i)(--(?:cookie|xid|csrf-token|password|base-url|host)\s+)(\S+)")
_KV_RE = re.compile(r"(?i)\b(cookie|xid|csrf|_cftoken|gcs_csrf|password|token|api_key|secret|base_url|host)=([^\s;&,]+)")
_BEARER_RE = re.compile(r"(?i)(Bearer\s+)([A-Za-z0-9._~+/=-]+)")
_URL_RE = re.compile(r"(?i)\bhttps?://[^\s\"'<>]+")
_PRIVATE_URL_RE = re.compile(
    r"(?i)\bhttps?://(?:10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})(?::\d+)?(?:/[^\s\"'<>]*)?"
)
_PRIVATE_IP_RE = re.compile(r"\b(?:10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})\b")


def redact_secrets(value: Any) -> str:
    text = str(value)
    text = _HEADER_RE.sub(lambda match: match.group(1) + "[REDACTED]", text)
    text = _BEARER_RE.sub(lambda match: match.group(1) + "[REDACTED]", text)
    text = _JSON_FIELD_RE.sub(lambda match: match.group(1) + '"[REDACTED]"', text)
    text = _CLI_RE.sub(lambda match: match.group(1) + "[REDACTED]", text)
    text = _KV_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = _PRIVATE_URL_RE.sub("[REDACTED_URL]", text)
    text = _URL_RE.sub("[REDACTED_URL]", text)
    text = _PRIVATE_IP_RE.sub("[REDACTED_IP]", text)
    return text


def redact_data(value: Any) -> Any:
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if str(key).lower() in SECRET_KEYS:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_data(item)
        return redacted
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, tuple):
        return [redact_data(item) for item in value]
    if isinstance(value, str):
        return redact_secrets(value)
    return value
