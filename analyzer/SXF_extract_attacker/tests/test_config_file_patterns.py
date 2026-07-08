import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.config import SIP_FILE_PATTERN


def test_sip_file_pattern_accepts_export_date_plus_sequence():
    assert re.fullmatch(SIP_FILE_PATTERN, "sangfor-sip-report-KsearchLog-2026070701.xlsx")


def test_sip_file_pattern_still_accepts_legacy_timestamp():
    assert re.fullmatch(SIP_FILE_PATTERN, "sangfor-sip-report-KsearchLog-20260707123456.xlsx")