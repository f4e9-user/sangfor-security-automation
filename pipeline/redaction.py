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

# Credential-like keys: always redacted, even when URLs are kept for readability.
_CRED_KEYS = "cookie|xid|csrf|_cftoken|gcs_csrf|password|token|api_key|secret|authorization"
# Location-like keys (base_url / host): redacted only in strict mode; kept visible
# in error logs so troubleshooting can show which device URL was reached.
_LOC_KEYS = "base_url|url_base|host"

_HEADER_RE = re.compile(r"(?im)^(\s*(?:Cookie|Authorization|Set-Cookie)\s*:\s*)([^\r\n]*)")
_BEARER_RE = re.compile(r"(?i)(Bearer\s+)([A-Za-z0-9._~+/=-]+)")
_JSON_CRED_RE = re.compile(
    r'(?i)("(?:' + _CRED_KEYS + r')"\s*:\s*)'
    r'(?:("(?:\\.|[^"\\])*")|(\{[^\n{}]*(?:\{[^\n{}]*\}[^\n{}]*)*\})|([^,}\n]+))'
)
_JSON_LOC_RE = re.compile(
    r'(?i)("(?:' + _LOC_KEYS + r')"\s*:\s*)(?:("(?:\\.|[^"\\])*")|([^,}\n]+))'
)
_CLI_CRED_RE = re.compile(r"(?i)(--(?:cookie|xid|csrf-token|password)\s+)(\S+)")
_CLI_LOC_RE = re.compile(r"(?i)(--(?:base-url|host)\s+)(\S+)")
_KV_CRED_RE = re.compile(r"(?i)\b(" + _CRED_KEYS + r")=([^\s;&,]+)")
_KV_LOC_RE = re.compile(r"(?i)\b(" + _LOC_KEYS + r")=([^\s;&,]+)")
_URL_RE = re.compile(r"(?i)\bhttps?://[^\s\"'<>]+")
_PRIVATE_URL_RE = re.compile(
    r"(?i)\bhttps?://(?:10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})(?::\d+)?(?:/[^\s\"'<>]*)?"
)
_PRIVATE_IP_RE = re.compile(r"\b(?:10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})\b")


def redact_secrets(value: Any, *, keep_urls: bool = False) -> str:
    """Redact credentials from ``value``.

    Credentials (cookies, tokens, passwords, xid, csrf, bearer tokens) are
    always redacted. By default (strict mode) URLs, private IPs, and
    base_url/host values are also redacted — this is used for manifests, events
    and reports that may be shared. When ``keep_urls`` is true, URLs/IPs and
    base_url/host are left visible so subprocess error logs stay useful for
    troubleshooting (e.g. ``net::ERR_EMPTY_RESPONSE at https://192.0.2.118``).
    """
    text = str(value)
    text = _HEADER_RE.sub(lambda match: match.group(1) + "[REDACTED]", text)
    text = _BEARER_RE.sub(lambda match: match.group(1) + "[REDACTED]", text)
    text = _JSON_CRED_RE.sub(lambda match: match.group(1) + '"[REDACTED]"', text)
    text = _CLI_CRED_RE.sub(lambda match: match.group(1) + "[REDACTED]", text)
    text = _KV_CRED_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    if not keep_urls:
        text = _JSON_LOC_RE.sub(lambda match: match.group(1) + '"[REDACTED]"', text)
        text = _CLI_LOC_RE.sub(lambda match: match.group(1) + "[REDACTED]", text)
        text = _KV_LOC_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
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