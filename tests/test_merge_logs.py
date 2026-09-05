import csv
import json
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import pytest

from pipeline.merge_logs import (
    DEDUP_COLUMNS,
    KEEP_COLUMNS,
    collect_run_exports,
    merge_recent_logs,
    read_run_frame,
)

COLUMNS = [
    "序号", "标记", "时间", "描述", "日志类型", "攻击类型", "源IP", "源所属类型", "源端口",
    "目的IP", "目的所属类型", "目的端口", "严重等级", "动作", "状态码", "数据来源",
    "探针物理端口", "攻击结果", "命中白名单", "X-Forwarded-For", "数据包",
]


def write_export_segment(path: Path, rows: list[dict]):
    """按 SIP 导出格式写 xlsx：前 7 行填充空行，第 8 行表头。"""
    frame = pd.DataFrame(rows, columns=COLUMNS)
    frame.to_excel(path, index=False, startrow=7)


def make_run(root: Path, run_id: str, start: str, end: str, rows: list[dict], *, run_status: str = "completed", export_status: str = "completed", limit: int = 10000):
    run_dir = root / "runs" / run_id
    exports_dir = run_dir / "exports"
    exports_dir.mkdir(parents=True, exist_ok=True)
    run_dir.joinpath("manifest.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "status": run_status,
                "args": {"command": "full", "start": start, "end": end},
                "stages": {
                    "export-logs": {"status": export_status},
                    "export-firewall-blacklist": {"status": "completed" if run_status == "completed" else "failed"},
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    segment = exports_dir / f"sangfor-sip-report-KsearchLog-{run_id[-6:]}01.xlsx"
    write_export_segment(segment, rows)
    exports_dir.joinpath("manifest-20260101_000000-20260102_000000.json").write_text(
        json.dumps(
            {
                "requested_start": start,
                "requested_end": end,
                "limit": limit,
                "split_limit": 9500,
                "segments": [
                    {"start": start, "end": end, "count": len(rows), "actual_count": len(rows), "file_name": segment.name}
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return run_dir


def attack_row(ts: str, src_ip: str, *, attack_type: str = "漏洞攻击", desc: str = "测试攻击"):
    return {
        "序号": 1, "标记": "未标记", "时间": ts, "描述": desc, "日志类型": "漏洞攻击",
        "攻击类型": attack_type, "源IP": src_ip, "源所属类型": "互联网", "源端口": 12345,
        "目的IP": "198.51.100.41", "目的所属类型": "服务器", "目的端口": 80, "严重等级": "中危",
        "动作": "拒绝", "状态码": "-", "数据来源": "af(192.0.2.116)", "探针物理端口": "-",
        "攻击结果": "尝试", "命中白名单": "否", "X-Forwarded-For": "-", "数据包": "REQUEST:...",
    }


NOW = datetime(2026, 9, 2, 12, 0, 0)


def test_collect_run_exports_selects_only_overlapping_windows(tmp_path):
    inside = make_run(
        tmp_path, "20260902_160318",
        "2026-08-21 17:30:00", "2026-08-28 17:30:00",
        [attack_row("2026-08-25 10:00:00", "1.1.1.1")],
    )
    outside = make_run(
        tmp_path, "20260710_172704",
        "2026-07-08 10:30:00", "2026-07-10 17:30:00",
        [attack_row("2026-07-09 10:00:00", "2.2.2.2")],
    )
    failed = make_run(
        tmp_path, "20260902_150830",
        "2026-08-07 17:00:00", "2026-08-31 17:30:00",
        [attack_row("2026-08-20 10:00:00", "3.3.3.3")],
        run_status="failed",
        export_status="completed",
    )

    cutoff = NOW - timedelta(days=30)
    selected, skipped = collect_run_exports(tmp_path / "runs", cutoff, NOW)

    run_ids = {item.run_id for item in selected}
    assert run_ids == {"20260902_160318", "20260902_150830"}  # 整体失败的 run 只要 export-logs 完成也入选
    skip_reasons = {item["run_id"]: item["reason"] for item in skipped}
    assert skip_reasons["20260710_172704"] == "window outside range"
    assert "20260902_150830" not in skip_reasons


def test_read_run_frame_skips_padding_and_keeps_data(tmp_path):
    rows = [attack_row("2026-08-25 10:00:00", "1.1.1.1"), attack_row("2026-08-25 11:00:00", "2.2.2.2")]
    run_dir = make_run(tmp_path, "20260902_160318", "2026-08-21 17:30:00", "2026-08-28 17:30:00", rows)
    frame = read_run_frame(run_dir / "exports")
    assert len(frame) == 2
    assert list(frame.columns) == COLUMNS
    assert frame["源IP"].tolist() == ["1.1.1.1", "2.2.2.2"]


def test_merge_recent_logs_filters_dedupes_and_writes_outputs(tmp_path):
    # 两个 run 窗口部分重叠，同一攻击事件在两次导出里都出现 → 应去重为 1 行
    dup_row = attack_row("2026-08-25 10:00:00", "1.1.1.1")
    make_run(
        tmp_path, "20260902_155416",
        "2026-08-07 17:00:00", "2026-08-14 17:30:00",
        [dup_row, attack_row("2026-08-10 09:00:00", "2.2.2.2")],
    )
    make_run(
        tmp_path, "20260902_160318",
        "2026-08-21 17:30:00", "2026-08-28 17:30:00",
        [dup_row, attack_row("2026-08-25 12:00:00", "3.3.3.3")],
    )
    # 窗口在 30 天之外 → 不入选
    make_run(
        tmp_path, "20260717_173927",
        "2026-07-10 17:30:00", "2026-07-17 17:30:00",
        [attack_row("2026-07-12 09:00:00", "4.4.4.4")],
    )

    out_dir = tmp_path / "outputs"
    coverage = merge_recent_logs(tmp_path / "runs", out_dir, days=30, now=NOW)

    assert coverage["total_rows"] == 3  # 1.1.1.1 去重后只剩 1 行
    assert coverage["unique_source_ips"] == 3
    assert coverage["covered_start"] == "2026-08-10 09:00:00"
    assert coverage["covered_end"] == "2026-08-25 12:00:00"
    assert len(coverage["runs_used"]) == 2
    assert coverage["stale_days"] is not None and coverage["stale_days"] > 0

    merged = pd.read_csv(out_dir / "merged_attack_logs_30d.csv", encoding="utf-8-sig")
    assert len(merged) == 3
    assert "数据包" not in merged.columns
    assert merged["源IP"].nunique() == 3
    # 时间列被过滤到 [cutoff, now] 内
    parsed = pd.to_datetime(merged["时间"])
    assert parsed.min() >= NOW - timedelta(days=30)

    attackers = pd.read_csv(out_dir / "attackers_last_seen_30d.csv", encoding="utf-8-sig")
    assert set(attackers.columns) == {"源IP", "最后攻击时间", "攻击次数"}
    assert len(attackers) == 3
    assert attackers["攻击次数"].sum() == 3

    assert (out_dir / "coverage_30d.json").is_file()
    assert (out_dir / "coverage_30d.md").is_file()


def test_merge_recent_logs_no_runs_raises(tmp_path):
    with pytest.raises(ValueError, match="没有可用的日志导出"):
        merge_recent_logs(tmp_path / "runs", tmp_path / "outputs", days=30, now=NOW)


def test_truncation_flag_on_segment_at_limit(tmp_path):
    rows = [attack_row("2026-08-25 10:00:00", f"1.1.1.{i}") for i in range(3)]
    run_dir = make_run(tmp_path, "20260902_160318", "2026-08-21 17:30:00", "2026-08-28 17:30:00", rows, limit=3)
    # 改写清单：末段达到 limit/split_limit → 标记可能截断
    manifest_path = next(run_dir.glob("exports/manifest-*.json"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["limit"] = 3
    manifest["split_limit"] = 3
    manifest["segments"][0]["actual_count"] = 3
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")

    cutoff = NOW - timedelta(days=30)
    selected, _ = collect_run_exports(tmp_path / "runs", cutoff, NOW)
    assert len(selected) == 1
    assert selected[0].possibly_truncated is True