from __future__ import annotations

import hashlib
import json
import mimetypes
import secrets
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Any

CHAOJIYING_UPLOAD_URL = "https://upload.chaojiying.net/Upload/Processing.php"


class ChaojiyingError(RuntimeError):
    pass


@dataclass(frozen=True)
class ChaojiyingCredentials:
    username: str
    password: str
    softid: str = ""
    codetype: str = "1004"


@dataclass(frozen=True)
class LoginCredentials:
    username: str
    password: str
    chaojiying: ChaojiyingCredentials | None = None


def chaojiying_pass2(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def decrypt_credentials_file(path: str | Path) -> dict[str, Any]:
    credentials_path = Path(path).expanduser()
    result = subprocess.run(
        ["gpg", "--quiet", "--batch", "--decrypt", str(credentials_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"failed to decrypt credentials file: {credentials_path}: {result.stderr.strip()}")
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict):
        raise ValueError("credentials file must decrypt to a JSON object")
    return payload


def load_login_credentials(path: str | Path, service: str) -> LoginCredentials:
    payload = decrypt_credentials_file(path)
    section = payload.get(service)
    if not isinstance(section, dict):
        raise ValueError(f"missing {service} credentials")
    username = str(section.get("username") or "").strip()
    password = str(section.get("password") or "")
    if not username or not password:
        raise ValueError(f"{service} credentials require username and password")

    chaojiying = None
    raw_captcha = payload.get("chaojiying")
    if isinstance(raw_captcha, dict):
        cy_username = str(raw_captcha.get("username") or "").strip()
        cy_password = str(raw_captcha.get("password") or "")
        if cy_username and cy_password:
            chaojiying = ChaojiyingCredentials(
                username=cy_username,
                password=cy_password,
                softid=str(raw_captcha.get("softid") or ""),
                codetype=str(raw_captcha.get("codetype") or "1004"),
            )
    return LoginCredentials(username=username, password=password, chaojiying=chaojiying)


def recognize_captcha_with_chaojiying(
    image_path: str | Path,
    *,
    username: str,
    password: str,
    softid: str = "",
    codetype: str = "1004",
    timeout: float = 30.0,
    urlopen: Callable[..., Any] = urllib.request.urlopen,
) -> str:
    path = Path(image_path).expanduser()
    fields = {
        "user": username,
        "pass2": chaojiying_pass2(password),
        "softid": softid,
        "codetype": codetype,
    }
    body, content_type = _multipart_form_data(fields, "userfile", path)
    request = urllib.request.Request(
        CHAOJIYING_UPLOAD_URL,
        data=body,
        headers={"Content-Type": content_type, "User-Agent": "sangfor-security-automation/1.0"},
        method="POST",
    )
    with urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read().decode("utf-8"))
    if int(data.get("err_no", -1)) != 0:
        raise ChaojiyingError(str(data.get("err_str") or data))
    result = str(data.get("pic_str") or "").strip()
    if not result:
        raise ChaojiyingError("empty captcha result")
    return result


def _multipart_form_data(fields: dict[str, str], file_field: str, file_path: Path) -> tuple[bytes, str]:
    boundary = "----sangfor-" + secrets.token_hex(16)
    parts: list[bytes] = []
    for name, value in fields.items():
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode("utf-8")
        )
    filename = file_path.name
    content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    parts.append(
        (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"{file_field}\"; filename=\"{filename}\"\r\n"
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode("utf-8")
    )
    parts.append(file_path.read_bytes())
    parts.append(f"\r\n--{boundary}--\r\n".encode("utf-8"))
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"
