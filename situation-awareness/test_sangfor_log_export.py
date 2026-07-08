import json
from datetime import datetime, timedelta
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sangfor_log_export import (
    Segment,
    build_output_name,
    build_payload,
    load_session_file,
    parse_cookie_header,
    resolve_auth_args,
    sanitize_stamp,
    split_segments,
    timestamp,
)


def test_parse_cookie_header_splits_cookie_pairs():
    cookies = parse_cookie_header("a=1; sess_id=abc; flag=x=y")
    assert cookies == [
        {"name": "a", "value": "1", "domain": "sip.local", "path": "/", "secure": True, "httpOnly": False, "sameSite": "Lax"},
        {"name": "sess_id", "value": "abc", "domain": "sip.local", "path": "/", "secure": True, "httpOnly": False, "sameSite": "Lax"},
        {"name": "flag", "value": "x=y", "domain": "sip.local", "path": "/", "secure": True, "httpOnly": False, "sameSite": "Lax"},
    ]


def test_timestamp_uses_local_cst_datetime():
    assert timestamp("2026-06-26 17:30:00") == 1782466200
    assert timestamp("2026-07-03 07:30:00") == 1783035000
    assert timestamp("2026-07-03 17:30:00") == 1783071000


def test_sanitize_stamp_for_filename():
    assert sanitize_stamp("2026-06-26 17:30:00") == "20260626_173000"


def test_build_payload_uses_favorite_but_overrides_time():
    favorite = {
        "index": "ngfw.security",
        "range_type": "security_log:all",
        "range_name": "安全检测日志",
        "direction_type": "outside",
        "direction_name": "外部",
        "query_string": "abc",
        "search_condition": "abc",
        "filter": {"filter_op": "AND"},
        "start_time": 1,
        "end_time": 2,
    }
    payload = build_payload(favorite, "2026-06-26 17:30:00", "2026-07-03 07:30:00")
    assert payload["index"] == "ngfw.security"
    assert payload["query_string"] == "abc"
    assert payload["start_time"] == 1782466200
    assert payload["end_time"] == 1783035000


def test_split_segments_keeps_full_coverage_under_limit():
    start = datetime(2026, 6, 26, 17, 30)
    end = datetime(2026, 7, 3, 7, 30)
    total_seconds = int((end - start).total_seconds())
    total_count = 24204

    def counter(a, b):
        return round(total_count * int((b - a).total_seconds()) / total_seconds)

    segments = split_segments(start, end, counter, limit=10000)
    assert segments[0].start == start
    assert segments[-1].end == end
    assert all(s.count <= 10000 for s in segments)
    assert all(left.end + timedelta(seconds=1) == right.start for left, right in zip(segments, segments[1:]))


def test_split_segments_targets_limit_sized_chunks_when_counts_are_linear():
    start = datetime(2026, 6, 26, 17, 30)
    end = datetime(2026, 7, 3, 17, 30)
    total_seconds = int((end - start).total_seconds())
    total_count = 25737

    def counter(a, b):
        return round(total_count * int((b - a).total_seconds()) / total_seconds)

    segments = split_segments(start, end, counter, limit=10000)
    assert len(segments) == 3
    assert all(s.count <= 10000 for s in segments)
    assert segments[0].count >= 9800
    assert segments[1].count >= 9800
    assert abs(sum(s.count for s in segments) - total_count) <= 1
    assert segments[0].start == start
    assert segments[-1].end == end


def test_build_output_name_uses_export_date_and_sequence():
    assert build_output_name("2026-07-04", 1) == "sangfor-sip-report-KsearchLog-2026070401.xlsx"
    assert build_output_name("2026-07-04", 12) == "sangfor-sip-report-KsearchLog-2026070412.xlsx"


def test_load_session_file_reads_cookie_xid_and_base_url(tmp_path):
    session_path = tmp_path / "session.json"
    session_path.write_text(
        json.dumps(
            {
                "base_url": "https://sip.local",
                "cookie": "sess_id=abc; token=def",
                "xid": "x-123",
                "created_at": "2026-07-04 10:00:00",
            }
        ),
        encoding="utf-8",
    )

    session = load_session_file(session_path)

    assert session == {
        "base_url": "https://sip.local",
        "cookie": "sess_id=abc; token=def",
        "xid": "x-123",
        "created_at": "2026-07-04 10:00:00",
    }


def test_load_session_file_rejects_missing_cookie(tmp_path):
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps({"xid": "x-123"}), encoding="utf-8")

    try:
        load_session_file(session_path)
    except ValueError as exc:
        assert "cookie" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_resolve_auth_args_prefers_session_file(tmp_path):
    session_path = tmp_path / "session.json"
    session_path.write_text(
        json.dumps({"base_url": "https://device.local", "cookie": "sess_id=abc", "xid": "x-123"}),
        encoding="utf-8",
    )

    class Args:
        session_file = str(session_path)
        base_url = "https://override.local"
        cookie = None
        cookie_file = None
        xid = None

    cookie, xid, base_url = resolve_auth_args(Args())

    assert cookie == "sess_id=abc"
    assert xid == "x-123"
    assert base_url == "https://device.local"
