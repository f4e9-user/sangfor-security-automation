from __future__ import annotations

import csv
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd

from .merge_logs import merge_recent_logs

# 月度自动封禁的描述签名，兼容两种历史模板：
#   - 新版 pipeline block 阶段：config.blocking.description_template = "{month}月自动封禁"
#     （"9月自动封禁"）
#   - 旧版防火墙脚本默认描述：default_description() = "{month}月封禁"
#     （"6月封禁"、"11月封禁"、"3月封禁" 等，同为按月批量自动封禁写入）
# 仅匹配这类机器生成的月度封禁条目才考虑自动解除；手动条目（病毒家族、自定义等）不碰。
AUTO_BLOCK_PATTERN = r"^\d+月(?:自动)?封禁$"

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


@dataclass(frozen=True)
class BlacklistEntry:
    address: str
    description: str
    added_at: str


@dataclass(frozen=True)
class ReviewCandidate:
    address: str
    description: str
    added_at: str
    last_seen: str | None = None
    attack_count: int | None = None


def load_blacklist(path: str | Path) -> list[BlacklistEntry]:
    """解析防火墙黑名单导出 CSV（地址/描述/添加时间）。

    真实导出每个字段用双引号包裹且以单引号 ``'`` 开头，前两行是说明，均在此剥离/跳过。
    """
    entries: list[BlacklistEntry] = []
    with Path(path).open(encoding="utf-8") as handle:
        for index, row in enumerate(csv.reader(handle)):
            if index < 2 or len(row) < 3:
                continue
            address = row[0].strip().lstrip("'").strip('"')
            description = row[1].strip().lstrip("'").strip('"')
            added_at = row[2].strip().lstrip("'").strip('"')
            if address and description:
                entries.append(BlacklistEntry(address, description, added_at))
    return entries


def is_auto_blocked(entry: BlacklistEntry, pattern: str = AUTO_BLOCK_PATTERN) -> bool:
    return re.match(pattern, entry.description.strip()) is not None


def is_ipv4(addr: str) -> bool:
    if not IPV4_RE.match(addr.strip()):
        return False
    try:
        ipaddress.ip_address(addr.strip())
        return True
    except ValueError:
        return False


def load_whitelist(path: str | Path | None) -> set[str]:
    """加载白名单 IP 集合。每行 ``IP,原因``（取第一个逗号前的 IP），支持纯 IP 行，
    忽略空行与 ``#`` 注释。"""
    if not path:
        return set()
    whitelist: set[str] = set()
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        ip = line.split(",", 1)[0].strip()
        if ip:
            whitelist.add(ip)
    return whitelist


def find_latest_blacklist(runs_dir: str | Path) -> Path:
    """扫描 runs 下所有 run 的黑名单导出，返回最新一份。"""
    runs_path = Path(runs_dir)
    candidates = sorted(
        runs_path.glob("*/blacklist/sangfor_firewall_blacklists.csv"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        raise FileNotFoundError(f"run 目录下没有黑名单导出（{runs_path}/<run>/blacklist/sangfor_firewall_blacklists.csv）")
    return candidates[0]


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return pd.to_datetime(value, errors="coerce").to_pydatetime()
    except (TypeError, ValueError):
        return None


def review_auto_blocked(
    runs_dir: str | Path,
    *,
    days: int = 30,
    min_block_age_days: int = 30,
    whitelist_file: str | Path | None = None,
    output_dir: str | Path | None = None,
    now: datetime | None = None,
    blacklist_pattern: str = AUTO_BLOCK_PATTERN,
) -> dict[str, Any]:
    """cached 模式：复用最近 N 天已导出的日志与最近一份黑名单，复查自动封禁 IP。

    候选解除 = 自动封禁 IP 且（近 N 天无攻击流量）且（封禁已满 min_block_age_days）
    且（不在白名单）。纯本地只读，不访问设备，不执行解除（解除需防火墙 API）。

    NOTE：近 N 天攻击流量由 merge_recent_logs 从各 run 的导出重算，覆盖不足或数据偏旧
    会在它的 coverage 提示里体现；若近 N 天没有任何可用导出则直接报错（不臆造"无流量"）。
    """
    runs_path = Path(runs_dir)
    current = now or datetime.now()

    # 1) 近 N 天有攻击流量的源 IP 集合（复用合并后的日志导出）
    coverage = merge_recent_logs(runs_path, days=days, now=current)
    attackers_csv = Path(coverage["outputs"]["attackers_last_seen_csv"])
    attackers = pd.read_csv(attackers_csv, encoding="utf-8-sig")
    recent_ips = {str(ip) for ip in attackers["源IP"].tolist()}
    last_seen = {str(ip): last for ip, last in zip(attackers["源IP"].tolist(), attackers["最后攻击时间"].tolist())}
    attack_counts = {str(ip): int(c) for ip, c in zip(attackers["源IP"].tolist(), attackers["攻击次数"].tolist())}

    # 2) 最近一份黑名单 → 过滤自动封禁条目
    blacklist_csv = find_latest_blacklist(runs_path)
    all_entries = load_blacklist(blacklist_csv)
    auto_blocked = [e for e in all_entries if is_auto_blocked(e, blacklist_pattern) and is_ipv4(e.address)]

    # 3) 最长封禁期过滤 + 白名单 + 近期流量
    whitelist = load_whitelist(whitelist_file)
    eligible: list[ReviewCandidate] = []
    too_recent: list[ReviewCandidate] = []
    for entry in auto_blocked:
        added = _parse_ts(entry.added_at)
        candidate = ReviewCandidate(
            address=entry.address,
            description=entry.description,
            added_at=entry.added_at,
            last_seen=last_seen.get(entry.address),
            attack_count=attack_counts.get(entry.address),
        )
        if added is None or (current - added).days < min_block_age_days:
            too_recent.append(candidate)
        else:
            eligible.append(candidate)

    candidates = [c for c in eligible if c.address not in recent_ips and c.address not in whitelist]
    still_active = [c for c in eligible if c.address in recent_ips]
    in_whitelist = [c for c in eligible if c.address in whitelist]

    # 4) 写产物
    output_path = Path(output_dir) if output_dir else runs_path.parent / "outputs" / "blacklist_review"
    output_path.mkdir(parents=True, exist_ok=True)
    candidates_csv = output_path / f"unblock_candidates_{days}d.csv"
    still_active_csv = output_path / f"still_active_{days}d.csv"
    in_whitelist_csv = output_path / f"in_whitelist_{days}d.csv"
    too_recent_csv = output_path / f"blocked_too_recent_{days}d.csv"
    report_json = output_path / f"review_{days}d.json"
    report_md = output_path / f"review_{days}d.md"

    _write_candidates(candidates_csv, candidates)
    _write_candidates(still_active_csv, still_active)
    _write_candidates(in_whitelist_csv, in_whitelist)
    _write_candidates(too_recent_csv, too_recent)

    summary = {
        "generated_at": current.strftime("%Y-%m-%d %H:%M:%S"),
        "mode": "cached",
        "days": days,
        "min_block_age_days": min_block_age_days,
        "blacklist_source": str(blacklist_csv),
        "blacklist_total_entries": len(all_entries),
        "auto_blocked_ips": len(auto_blocked),
        "eligible_after_age": len(eligible),
        "recent_attack_ips": len(recent_ips),
        "whitelisted_ips": len(in_whitelist),
        "still_active_count": len(still_active),
        "blocked_too_recent_count": len(too_recent),
        "candidates_count": len(candidates),
        "apply_executed": False,
        "apply_note": "解除封禁需防火墙 API，本次未执行；仅输出候选列表供复核",
        "coverage": coverage,
        "outputs": {
            "candidates": str(candidates_csv),
            "still_active": str(still_active_csv),
            "in_whitelist": str(in_whitelist_csv),
            "blocked_too_recent": str(too_recent_csv),
            "report_json": str(report_json),
            "report_md": str(report_md),
        },
    }
    report_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    report_md.write_text(_render_review_md(summary, candidates, still_active, in_whitelist), encoding="utf-8")
    return summary


def _write_candidates(path: Path, items: list[ReviewCandidate]) -> None:
    rows = []
    for item in items:
        rows.append(
            {
                "IP": item.address,
                "描述": item.description,
                "添加时间": item.added_at,
                "近30天最后攻击时间": item.last_seen or "",
                "近30天攻击次数": item.attack_count if item.attack_count is not None else "",
            }
        )
    pd.DataFrame(rows).to_csv(path, index=False, encoding="utf-8-sig")


def _render_review_md(summary: dict, candidates, still_active, in_whitelist) -> str:
    lines = [
        "# 自动封禁黑名单复查报告（cached 模式）",
        "",
        f"- 生成时间：{summary['generated_at']}",
        f"- 检查窗口：近 {summary['days']} 天攻击流量",
        f"- 黑名单来源：{summary['blacklist_source']}",
        f"- 黑名单总条目：{summary['blacklist_total_entries']}；自动封禁 IP：{summary['auto_blocked_ips']}",
        f"- 封禁满 {summary['min_block_age_days']} 天进入评估：{summary['eligible_after_age']}",
        f"- 近期仍有攻击：{summary['still_active_count']}；命中白名单：{summary['whitelisted_ips']}；封禁期不满：{summary['blocked_too_recent_count']}",
        "",
        f"## 候选解除（{summary['candidates_count']}）",
        "",
        "| IP | 描述 | 添加时间 | 近30天最后攻击时间 | 近30天攻击次数 |",
        "|---|---|---|---|---|",
    ]
    for item in candidates:
        lines.append(f"| {item.address} | {item.description} | {item.added_at} | {item.last_seen or '-'} | {item.attack_count if item.attack_count is not None else '-'} |")
    lines.append("")
    lines.append("## 近期仍有攻击流量（不解封）")
    lines.append("")
    lines.append("| IP | 近30天最后攻击时间 | 攻击次数 |")
    lines.append("|---|---|---|")
    for item in still_active:
        lines.append(f"| {item.address} | {item.last_seen or '-'} | {item.attack_count or 0} |")
    lines.append("")
    lines.append("## 命中白名单（需人工确认）")
    lines.append("")
    if in_whitelist:
        for item in in_whitelist:
            lines.append(f"- {item.address}（{item.description}，{item.added_at}）")
    else:
        lines.append("- 无")
    lines.append("")
    lines.append("> 本次未执行任何解除封禁操作。解除需防火墙删除接口，待后续实现。")
    return "\n".join(lines)