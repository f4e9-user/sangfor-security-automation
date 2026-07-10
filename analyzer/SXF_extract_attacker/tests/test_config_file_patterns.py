import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.config import SIP_FILE_PATTERN, load_excluded_ips


def test_sip_file_pattern_accepts_export_date_plus_sequence():
    assert re.fullmatch(SIP_FILE_PATTERN, "sangfor-sip-report-KsearchLog-2026070701.xlsx")


def test_sip_file_pattern_still_accepts_legacy_timestamp():
    assert re.fullmatch(SIP_FILE_PATTERN, "sangfor-sip-report-KsearchLog-20260707123456.xlsx")


def test_load_excluded_ips_uses_override_path(tmp_path):
    wl = tmp_path / "ip_whitelist.txt"
    wl.write_text(
        "1.2.3.4,出口IP\n5.6.7.8,百度爬虫\n# comment\n9.9.9.9,返回 404\n",
        encoding="utf-8",
    )
    excluded = load_excluded_ips(str(wl))
    assert excluded == {"1.2.3.4": "出口IP", "5.6.7.8": "百度爬虫", "9.9.9.9": "返回 404"}


def test_load_excluded_ips_missing_file_returns_empty(tmp_path):
    assert load_excluded_ips(str(tmp_path / "nope.txt")) == {}