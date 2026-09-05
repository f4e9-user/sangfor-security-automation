import json
import re
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

from pipeline.review import (
    is_auto_blocked,
    is_ipv4,
    load_blacklist,
    load_whitelist,
    review_auto_blocked,
    BlacklistEntry,
)
from test_merge_logs import make_run, attack_row, NOW


BLACKLIST_HEADER = [
    "#####封堵名单地址,描述,添加时间",
    "\"#首个字符如为单引号“'”表示后续内容为文本，导入时忽略此单引号\"",
]


def write_blacklist(path: Path, entries: list[tuple[str, str, str]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = list(BLACKLIST_HEADER)
    for addr, desc, added in entries:
        lines.append(f"\"'{addr}\",\"'{desc}\",\"'{added}\"")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_load_blacklist_strips_quote_prefix():
    entries = load_blacklist(_make_blacklist_file(
        [("1.1.1.1", "8月自动封禁", "2026-07-15 10:00:00")],
    ))
    assert len(entries) == 1
    assert entries[0].address == "1.1.1.1"
    assert entries[0].description == "8月自动封禁"
    assert entries[0].added_at == "2026-07-15 10:00:00"


def test_is_auto_blocked_and_is_ipv4():
    # 新版模板：N月自动封禁
    assert is_auto_blocked(BlacklistEntry("1.1.1.1", "9月自动封禁", "2026-09-02"))
    assert is_auto_blocked(BlacklistEntry("1.1.1.1", "8月自动封禁", "2026-08-01"))
    # 旧版模板：N月封禁（同样按月批量自动封禁写入）
    assert is_auto_blocked(BlacklistEntry("1.1.1.1", "6月封禁", "2026-06-15"))
    assert is_auto_blocked(BlacklistEntry("1.1.1.1", "12月封禁", "2025-12-01"))
    # 手动/其他来源 → 不匹配
    assert not is_auto_blocked(BlacklistEntry("1.1.1.1", "virut家族感染型病毒", "2021-01-01"))
    assert not is_auto_blocked(BlacklistEntry("1.1.1.1", "[自定义]从业务安全中添加到永久封锁名单", "2026-01-01"))
    assert not is_auto_blocked(BlacklistEntry("1.1.1.1", "8月封禁[自定义]", "2026-08-01"))
    # is_auto_blocked 只看描述；域名/非法 IP 由 is_ipv4 单独过滤
    assert is_auto_blocked(BlacklistEntry("a.com", "9月自动封禁", "2026-09-02"))
    assert is_ipv4("1.1.1.1")
    assert not is_ipv4("a.com")
    assert not is_ipv4("256.1.1.1")


def test_load_whitelist_parses_ip_reason_and_comments(tmp_path):
    wl = tmp_path / "whitelist.txt"
    wl.write_text("# comment\n123.120.49.172,返回 404\n27.37.67.7,出口IP\n\n9.9.9.9\n", encoding="utf-8")
    assert load_whitelist(wl) == {"123.120.49.172", "27.37.67.7", "9.9.9.9"}
    assert load_whitelist(None) == set()


def test_review_cached_selects_only_idle_auto_blocked(tmp_path):
    # 近 30 天有攻击流量的 run（供 merge_recent_logs 生成 recent 集合）
    make_run(
        tmp_path, "20260815_120000",
        "2026-08-10 00:00:00", "2026-08-20 23:59:59",
        [
            attack_row("2026-08-12 10:00:00", "1.1.1.1"),
            attack_row("2026-08-15 10:00:00", "2.2.2.2"),
        ],
    )
    # 最近一份黑名单（独立 run 目录，避免被 merge 选中）
    bl_run = tmp_path / "runs" / "20260903_000000"
    write_blacklist(
        bl_run / "blacklist" / "sangfor_firewall_blacklists.csv",
        [
            ("1.1.1.1", "8月自动封禁", "2026-07-15 10:00:00"),   # 近期有流量 → still_active
            ("2.2.2.2", "8月自动封禁", "2026-07-15 10:00:00"),   # 近期有流量 → still_active
            ("3.3.3.3", "8月自动封禁", "2026-07-15 10:00:00"),   # 无流量 → candidate
            ("4.4.4.4", "9月自动封禁", "2026-09-02 15:57:00"),   # 封禁未满30天 → too_recent
            ("5.5.5.5", "virut家族感染型病毒", "2021-01-01 10:00:00"),  # 手动 → 忽略
            ("6.6.6.6", "8月自动封禁", "2026-07-15 10:00:00"),   # 白名单 → in_whitelist
            ("7.7.7.7", "6月封禁", "2026-06-15 10:00:00"),        # 旧版模板、无流量 → candidate
        ],
    )
    wl = tmp_path / "whitelist.txt"
    wl.write_text("6.6.6.6,用户指定\n", encoding="utf-8")

    out = tmp_path / "review_out"
    summary = review_auto_blocked(
        tmp_path / "runs",
        days=30,
        min_block_age_days=30,
        whitelist_file=wl,
        output_dir=out,
        now=NOW,
    )

    assert summary["apply_executed"] is False
    assert summary["auto_blocked_ips"] == 6
    assert summary["eligible_after_age"] == 5
    assert summary["still_active_count"] == 2
    assert summary["whitelisted_ips"] == 1
    assert summary["blocked_too_recent_count"] == 1
    assert summary["candidates_count"] == 2

    candidates = pd.read_csv(out / "unblock_candidates_30d.csv", encoding="utf-8-sig")
    assert candidates["IP"].tolist() == ["3.3.3.3", "7.7.7.7"]
    still_active = pd.read_csv(out / "still_active_30d.csv", encoding="utf-8-sig")
    assert set(still_active["IP"]) == {"1.1.1.1", "2.2.2.2"}
    in_wl = pd.read_csv(out / "in_whitelist_30d.csv", encoding="utf-8-sig")
    assert in_wl["IP"].tolist() == ["6.6.6.6"]
    too_recent = pd.read_csv(out / "blocked_too_recent_30d.csv", encoding="utf-8-sig")
    assert too_recent["IP"].tolist() == ["4.4.4.4"]

    assert (out / "review_30d.json").is_file()
    assert (out / "review_30d.md").is_file()


def test_review_cached_without_whitelist_keeps_idle_candidate(tmp_path):
    make_run(
        tmp_path, "20260815_120000",
        "2026-08-10 00:00:00", "2026-08-20 23:59:59",
        [attack_row("2026-08-12 10:00:00", "1.1.1.1")],
    )
    bl_run = tmp_path / "runs" / "20260903_000000"
    write_blacklist(
        bl_run / "blacklist" / "sangfor_firewall_blacklists.csv",
        [("1.1.1.1", "8月自动封禁", "2026-07-15 10:00:00"),
         ("3.3.3.3", "8月自动封禁", "2026-07-15 10:00:00")],
    )
    summary = review_auto_blocked(
        tmp_path / "runs", days=30, min_block_age_days=30,
        whitelist_file=None, output_dir=tmp_path / "out", now=NOW,
    )
    candidates = pd.read_csv(tmp_path / "out" / "unblock_candidates_30d.csv", encoding="utf-8-sig")
    assert candidates["IP"].tolist() == ["3.3.3.3"]


def _make_blacklist_file(entries: list[tuple[str, str, str]]) -> Path:
    import tempfile
    f = Path(tempfile.mkdtemp()) / "bl.csv"
    write_blacklist(f, entries)
    return f