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
}

_HEADER_RE = re.compile(r"(?im)^(\s*(?:Cookie|Authorization|Set-Cookie)\s*:\s*)([^\r\n]*)")
_JSON_FIELD_RE = re.compile(
    r'(?i)("(?:cookie|xid|csrf|_cftoken|gcs_csrf|password|token|api_key|secret|authorization)"\s*:\s*)'
    r'(?:("(?:\\.|[^"\\])*")|(\{[^\n{}]*(?:\{[^\n{}]*\}[^\n{}]*)*\})|([^,}\n]+))'
)
_CLI_RE = re.compile(r"(?i)(--(?:cookie|xid|csrf-token|password)\s+)(\S+)")
_KV_RE = re.compile(r"(?i)\b(cookie|xid|csrf|_cftoken|gcs_csrf|password|token|api_key|secret)=([^\s;&,]+)")
_BEARER_RE = re.compile(r"(?i)(Bearer\s+)([A-Za-z0-9._~+/=-]+)")


def redact_secrets(value: Any) -> str:
    text = str(value)
    text = _HEADER_RE.sub(lambda match: match.group(1) + "[REDACTED]", text)
    text = _BEARER_RE.sub(lambda match: match.group(1) + "[REDACTED]", text)
    text = _JSON_FIELD_RE.sub(lambda match: match.group(1) + '"[REDACTED]"', text)
    text = _CLI_RE.sub(lambda match: match.group(1) + "[REDACTED]", text)
    text = _KV_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
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
