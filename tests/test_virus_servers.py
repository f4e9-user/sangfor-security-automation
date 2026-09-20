"""virus_servers 模块测试：病毒日志导出 → 内网服务器 TOP N + 外联 IP。"""
from __future__ import annotations

import json
from pathlib import Path

from openpyxl import Workbook

from pipeline.virus_servers import (
    COLUMNS,
    analyze,
    classify_side,
    is_private_ip,
    load_export,
    write_outputs,
)

QUERY = "module_type:209 AND (NOT ((module_type:209 AND attack_type:6)))"


def write_export(path: Path, rows: list[dict], *, query: str = QUERY,
                 time_range: str = "2026-09-01 00:00:00 - 2026-09-08 00:00:00",
                 direction: str = "外部") -> Path:
    """构造与真实 SIP 导出同形的 xlsx（7 行元信息 + 表头 + 数据）。"""
    wb = Workbook()
    ws = wb.active if wb.active is not None else wb.create_sheet()
    ws.append(["日志检索高级模式"])
    ws.append(["过滤条件"])
    ws.append(["时间范围:", time_range])
    ws.append(["日志范围", "安全检测日志"])
    ws.append(["搜索条件", query])
    ws.append(["访问方向", direction])
    ws.append(["查询结果"])
    ws.append(COLUMNS)
    for row in rows:
        ws.append([row.get(c, "") for c in COLUMNS])
    path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(path)
    return path


def row(src, dst, *, src_type="互联网", dst_type="内网", time="2026-09-02 10:00:00",
        desc="木马后门通信", log_type="病毒", attack_type="恶意软件", severity="高", sport="50000", dport="443"):
    return {
        "序号": "1", "标记": "未标记", "时间": time, "描述": desc, "日志类型": log_type,
        "攻击类型": attack_type, "源IP": src, "源所属类型": src_type, "源端口": sport,
        "目的IP": dst, "目的所属类型": dst_type, "目的端口": dport, "严重等级": severity,
    }


# ------------------------------------------------------------------ 基础判定
def test_is_private_ip_and_classify_side():
    assert is_private_ip("10.1.2.3")
    assert is_private_ip("198.51.100.5")
    assert is_private_ip("192.168.1.10")
    assert is_private_ip("100.64.3.4")          # CGNAT
    assert not is_private_ip("8.8.8.8")
    assert not is_private_ip("not-an-ip")

    assert classify_side("10.0.0.5", "") == "internal"           # 回落私有地址
    assert classify_side("1.2.3.4", "") == "external"
    assert classify_side("1.2.3.4", "内网") == "internal"        # SIP 标注优先
    assert classify_side("10.0.0.5", "互联网") == "external"


# ------------------------------------------------------------------ 读导出
def test_load_export_meta_and_rows(tmp_path: Path):
    p = write_export(tmp_path / "e.xlsx", [row("45.1.2.3", "10.0.0.9")])
    meta, rows = load_export(p)
    assert meta.query_string == QUERY
    assert meta.log_range == "安全检测日志"
    assert meta.direction == "外部"
    assert "2026-09-01" in meta.time_range
    assert len(rows) == 1 and rows[0]["源IP"] == "45.1.2.3" and meta.total_rows == 1


# ------------------------------------------------------------------ TOP 与外联
def test_top_ranking_and_external_peers(tmp_path: Path):
    rows = [
        # 10.0.0.5：3 次外联（2 个不同外网 IP）
        row("10.0.0.5", "8.8.8.8", src_type="内网", dst_type="互联网", dport="4444"),
        row("10.0.0.5", "8.8.8.8", src_type="内网", dst_type="互联网", dport="4444"),
        row("10.0.0.5", "1.1.1.1", src_type="内网", dst_type="互联网", dport="443"),
        # 10.0.0.7：2 次（外网主动打进来的记录，方向相反）
        row("9.9.9.9", "10.0.0.7"),
        row("9.9.9.9", "10.0.0.7"),
        # 10.0.0.9：1 次
        row("10.0.0.9", "2.2.2.2", src_type="内网", dst_type="互联网"),
    ]
    p = write_export(tmp_path / "e.xlsx", rows)
    meta, parsed = load_export(p)
    report = analyze(parsed, top=10)

    assert report["servers_total"] == 3
    top = report["servers"]
    assert [s["ip"] for s in top] == ["10.0.0.5", "10.0.0.7", "10.0.0.9"]
    assert top[0]["events"] == 3 and top[0]["direction"] == "主动外联"
    assert {p_["ip"] for p_ in top[0]["external_peers"]} == {"8.8.8.8", "1.1.1.1"}
    peer = next(p_ for p_ in top[0]["external_peers"] if p_["ip"] == "8.8.8.8")
    assert peer["events"] == 2 and "4444" in peer["ports"]
    # 外网打进来的主机：方向为被动，且其“对端”是外网源 IP
    assert top[1]["direction"] == "被动（外部对内）"
    assert [p_["ip"] for p_ in top[1]["external_peers"]] == ["9.9.9.9"]


def test_top_limit_and_top_peers(tmp_path: Path):
    rows = [row(f"10.0.0.{i}", f"8.8.8.{i}", src_type="内网", dst_type="互联网") for i in range(1, 6)]
    p = write_export(tmp_path / "e.xlsx", rows)
    _, parsed = load_export(p)
    report = analyze(parsed, top=2, top_peers=1)
    assert len(report["servers"]) == 2
    assert all(len(s["external_peers"]) == 1 for s in report["servers"])


def test_rows_without_internal_are_skipped(tmp_path: Path):
    rows = [row("45.1.1.1", "46.1.1.1", src_type="互联网", dst_type="互联网")]
    p = write_export(tmp_path / "e.xlsx", rows)
    _, parsed = load_export(p)
    report = analyze(parsed)
    assert report["servers_total"] == 0
    assert report["rows_skipped_no_internal"] == 1


def test_internal_to_internal_counts_both_sides(tmp_path: Path):
    rows = [row("10.0.0.1", "10.0.0.2", src_type="内网", dst_type="内网")]
    p = write_export(tmp_path / "e.xlsx", rows)
    _, parsed = load_export(p)
    report = analyze(parsed)
    assert {s["ip"] for s in report["servers"]} == {"10.0.0.1", "10.0.0.2"}
    assert all(s["direction"] == "仅内网互访" for s in report["servers"])


# ------------------------------------------------------------------ 输出
def test_write_outputs_files(tmp_path: Path):
    rows = [row("10.0.0.5", "8.8.8.8", src_type="内网", dst_type="互联网")]
    p = write_export(tmp_path / "e.xlsx", rows)
    meta, parsed = load_export(p)
    report = analyze(parsed, top=10)
    paths = write_outputs(tmp_path / "out", meta, report)

    for key in ("json", "servers_csv", "peers_csv", "markdown"):
        assert Path(paths[key]).exists(), key
    payload = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert payload["meta"]["query_string"] == QUERY
    assert payload["report"]["servers"][0]["ip"] == "10.0.0.5"
    md = Path(paths["markdown"]).read_text(encoding="utf-8")
    assert "10.0.0.5" in md and "8.8.8.8" in md and "外联服务器 IP" in md
    csv_text = Path(paths["peers_csv"]).read_text(encoding="utf-8-sig")
    assert "10.0.0.5" in csv_text and "8.8.8.8" in csv_text
