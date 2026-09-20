"""Regression tests for the SIP export download validation/repair helpers.

Context: the 2026-09-11 export-logs stage died inside ``adaptive_export_segments`` because a
downloaded segment workbook was not parseable (openpyxl raised
``xml.etree.ElementTree.ParseError: not well-formed (invalid token)`` on ``xl/sharedStrings.xml``).
These tests pin the guards added for that failure: validate every download, repair XML-invalid
bytes in place, retry (and keep a forensic copy) when the workbook is not repairable.
"""
from __future__ import annotations

import importlib.util
import sys
import zipfile
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "situation-awareness" / "sangfor_log_export.py"
DASH = "sle_export_under_test"
_spec = importlib.util.spec_from_file_location(DASH, MODULE_PATH)
sle = importlib.util.module_from_spec(_spec)
sys.modules[DASH] = sle
assert _spec.loader is not None
_spec.loader.exec_module(sle)

CONTENT_TYPES = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"""
WORKBOOK = b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="sheet1" sheetId="1"/></sheets></workbook>'
SHARED_STRINGS = b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1"><si><t>attack-log</t></si></sst>'
SHEET = b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>'


def build_workbook(path: Path, *, shared_strings: bytes = SHARED_STRINGS, drop_shared_strings: bool = False) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", CONTENT_TYPES)
        archive.writestr("xl/workbook.xml", WORKBOOK)
        if not drop_shared_strings:
            archive.writestr("xl/sharedStrings.xml", shared_strings)
        archive.writestr("xl/worksheets/sheet1.xml", SHEET)
    return path


def test_clean_workbook_passes(tmp_path: Path) -> None:
    path = build_workbook(tmp_path / "clean.xlsx")
    assert sle.workbook_problem(path) is None
    assert sle.ensure_readable_workbook(path) is None


def test_xml_invalid_bytes_are_detected_and_repaired(tmp_path: Path) -> None:
    dirty = SHARED_STRINGS.replace(b"</sst>", b"\x0b\x00</sst>")
    path = build_workbook(tmp_path / "dirty.xlsx", shared_strings=dirty)
    problem = sle.workbook_problem(path)
    assert problem is not None and "sharedStrings.xml" in problem
    note = sle.ensure_readable_workbook(path)
    assert note is not None and "stripped XML-invalid bytes" in note
    assert sle.workbook_problem(path) is None
    assert sle.INVALID_XML_BYTES.search(zipfile.ZipFile(path).read("xl/sharedStrings.xml")) is None


def test_noncharacter_bytes_are_detected_and_repaired(tmp_path: Path) -> None:
    """SIP 实测会把 U+FFFF / U+FDD0..U+FDEF 写进 sharedStrings（合法 UTF-8、非法 XML 字符）。"""
    dirty = SHARED_STRINGS.replace(b"</sst>", "\uffff\ufdd0</sst>".encode("utf-8"))
    path = build_workbook(tmp_path / "nonchar.xlsx", shared_strings=dirty)
    problem = sle.workbook_problem(path)
    assert problem is not None and "sharedStrings.xml" in problem
    note = sle.ensure_readable_workbook(path)
    assert note is not None and "2 处非法字符" in note
    assert sle.workbook_problem(path) is None
    assert sle.INVALID_XML_BYTES.search(zipfile.ZipFile(path).read("xl/sharedStrings.xml")) is None


def test_missing_declared_part_is_reported(tmp_path: Path) -> None:
    path = build_workbook(tmp_path / "half.xlsx", drop_shared_strings=True)
    problem = sle.workbook_problem(path)
    assert problem is not None and "incomplete" in problem


def test_truncated_archive_is_reported(tmp_path: Path) -> None:
    path = build_workbook(tmp_path / "trunc.xlsx")
    with path.open("r+b") as handle:
        handle.truncate(path.stat().st_size - 60)
    problem = sle.workbook_problem(path)
    assert problem is not None
    with pytest.raises(RuntimeError):
        sle.ensure_readable_workbook(path)


def test_retry_recovers_and_keeps_forensic_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sle, "DOWNLOAD_BACKOFF_SECONDS", (0, 0, 0))
    good = build_workbook(tmp_path / "good.xlsx")
    attempts: list[int] = []

    def fake_export(segment, path: Path) -> str:
        attempts.append(1)
        if len(attempts) == 1:
            path.write_bytes(b"PK\x03\x04 truncated")
        elif len(attempts) == 2:
            build_workbook(path, shared_strings=SHARED_STRINGS.replace(b"</sst>", b"\x0b</sst>"))
        else:
            path.write_bytes(good.read_bytes())
        return f"server-{len(attempts)}.xlsx"

    segment = sle.Segment(sle.parse_dt("2026-08-28 17:30:00"), sle.parse_dt("2026-08-29 17:30:00"), 0)
    candidate = tmp_path / ".candidate.xlsx"
    # 第 1 次截断 → 重下；第 2 次带 XML 非法字节 → 原地修复后通过（无需第 3 次）
    assert sle.download_candidate_with_retry(fake_export, segment, candidate, attempts=3) == "server-2.xlsx"
    assert len(attempts) == 2
    assert sle.workbook_problem(candidate) is None
    assert [p.name for p in tmp_path.glob("*.bad*.xlsx")] == [".candidate.bad1.xlsx"]


def test_retry_gives_up_after_configured_attempts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sle, "DOWNLOAD_BACKOFF_SECONDS", (0, 0, 0))
    calls: list[int] = []

    def always_truncated(segment, path: Path) -> str:
        calls.append(1)
        path.write_bytes(b"PK\x03\x04 still truncated")
        return "server-file.xlsx"

    segment = sle.Segment(sle.parse_dt("2026-08-28 17:30:00"), sle.parse_dt("2026-08-29 17:30:00"), 0)
    with pytest.raises(RuntimeError, match="after 2 attempts"):
        sle.download_candidate_with_retry(always_truncated, segment, tmp_path / ".candidate.xlsx", attempts=2)
    assert len(calls) == 2
