from __future__ import annotations

from pathlib import Path


def find_cached_chromium_executable(cache_dir: str | Path | None = None) -> Path | None:
    root = Path(cache_dir).expanduser() if cache_dir else Path.home() / ".cache" / "ms-playwright"
    if not root.exists():
        return None
    candidates: list[tuple[int, Path]] = []
    for path in root.glob("chromium-*/chrome-linux64/chrome"):
        if not path.is_file():
            continue
        try:
            revision = int(path.parents[1].name.split("-", 1)[1])
        except (IndexError, ValueError):
            revision = 0
        candidates.append((revision, path))
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: item[0], reverse=True)[0][1]


def chromium_launch_options(
    *,
    headless: bool,
    executable_path: str | Path | None = None,
    browser_cache_dir: str | Path | None = None,
) -> dict:
    options: dict = {"headless": headless, "args": ["--ignore-certificate-errors", "--no-sandbox"]}
    executable = Path(executable_path).expanduser() if executable_path else find_cached_chromium_executable(browser_cache_dir)
    if executable is not None:
        options["executable_path"] = str(executable)
    return options
