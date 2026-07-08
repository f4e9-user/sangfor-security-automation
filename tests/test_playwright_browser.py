from pathlib import Path

from pipeline.playwright_browser import chromium_launch_options, find_cached_chromium_executable


def test_find_cached_chromium_executable_picks_highest_revision(tmp_path):
    old = tmp_path / "chromium-1000" / "chrome-linux64" / "chrome"
    new = tmp_path / "chromium-1228" / "chrome-linux64" / "chrome"
    old.parent.mkdir(parents=True)
    new.parent.mkdir(parents=True)
    old.write_text("old", encoding="utf-8")
    new.write_text("new", encoding="utf-8")
    old.chmod(0o755)
    new.chmod(0o755)

    assert find_cached_chromium_executable(tmp_path) == new


def test_chromium_launch_options_uses_explicit_executable_path():
    options = chromium_launch_options(headless=True, executable_path="/tmp/chrome")

    assert options["headless"] is True
    assert options["executable_path"] == "/tmp/chrome"
    assert "--ignore-certificate-errors" in options["args"]


def test_chromium_launch_options_uses_cached_full_chromium_when_available(tmp_path):
    chrome = tmp_path / "chromium-1228" / "chrome-linux64" / "chrome"
    chrome.parent.mkdir(parents=True)
    chrome.write_text("chrome", encoding="utf-8")
    chrome.chmod(0o755)

    options = chromium_launch_options(headless=True, browser_cache_dir=tmp_path)

    assert options["executable_path"] == str(chrome)
