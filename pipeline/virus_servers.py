#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""病毒日志（收藏夹）→ 内网服务器 TOP N → 外联 IP 分析。

数据来源：SIP「日志检索」收藏夹导出的 xlsx（与 `export-logs --favorite-name <名字>` 同格式）。
典型收藏条件（用户 2026-09-20 收藏，名称「病毒」）：
    module_type:209 AND (NOT ((module_type:209 AND attack_type:6)))

导出文件结构（实测）：
    row 0  日志检索高级模式
    row 1  过滤条件
    row 2  时间范围:  <start> - <end>
    row 3  日志范围   安全检测日志
    row 4+ 搜索条件   <query_string>（可能跨列/跨行）
    row ?  访问方向   外部
    row ?  查询结果
    row 7  表头：序号,标记,时间,描述,日志类型,攻击类型,源IP,源所属类型,源端口,目的IP,
                目的所属类型,目的端口,严重等级,动作,状态码,数据来源,探针物理端口,攻击结果,
                命中白名单,X-Forwarded-For,数据包
    row 8+ 数据

内外网判定优先用「源所属类型 / 目的所属类型」（SIP 自带标注），缺失时回落到私有地址判断。
本模块纯本地只读，不接触设备。
"""
from __future__ import annotations

import csv
import ipaddress
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

META_ROWS = 7
COLUMNS = [
    "序号", "标记", "时间", "描述", "日志类型", "攻击类型", "源IP", "源所属类型", "源端口",
    "目的IP", "目的所属类型", "目的端口", "严重等级", "动作", "状态码", "数据来源",
    "探针物理端口", "攻击结果", "命中白名单", "X-Forwarded-For", "数据包",
]
INTERNAL_HINTS = ("内网", "局域网", "办公", "私有", "内部", "专线", "终端", "vpn", "VPN")
EXTERNAL_HINTS = ("互联网", "公网", "外网", "Internet", "INTERNET", "internet")


# --------------------------------------------------------------------- 基础工具
def is_private_ip(value: str) -> bool:
    """私有/保留地址判定（含 100.64/10 CGNAT 与 169.254/16 链路本地）。"""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip in ipaddress.ip_network("100.64.0.0/10")
    )


def classify_side(ip: str, ip_type: str | None) -> str:
    """返回 'internal' / 'external'。

    先看 SIP 的所属类型标注，未标注或标注无法识别时回落到私有地址判断。
    """
    t = str(ip_type or "").strip()
    if t:
        if any(h in t for h in INTERNAL_HINTS):
            return "internal"
        if any(h in t for h in EXTERNAL_HINTS):
            return "external"
    return "internal" if is_private_ip(ip) else "external"


def _norm(value: Any) -> str:
    """规范化单元格：None/NaN 与 SIP 的 "-"、"-1" 占位一律视为空。"""
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))          # calamine 把数字列读成 float：5178.0 -> "5178"
    s = str(value).strip()
    return "" if s.lower() in ("nan", "none") or s in ("-", "--", "N/A") else s


def _ts_key(value: str) -> str:
    """用于首/末次出现的排序键：尽量补零规范化，失败则原样。"""
    s = _norm(value)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return s


# --------------------------------------------------------------------- 读导出
@dataclass
class ExportMeta:
    path: str
    time_range: str = ""
    log_range: str = ""
    query_string: str = ""
    direction: str = ""
    total_rows: int = 0


def load_export(path: str | Path) -> tuple[ExportMeta, list[dict[str, str]]]:
    """读取 SIP 导出 xlsx：返回 (meta, rows)；rows 为 dict 列表（列名来自表头）。"""
    from python_calamine import CalamineWorkbook  # 项目 venv 已装

    wb = CalamineWorkbook.from_path(str(path))
    sheet = wb.get_sheet_by_index(0)
    raw = sheet.to_python(skip_empty_area=False)
    if len(raw) < META_ROWS + 2:
        raise ValueError(f"导出文件行数不足，疑似非 SIP 导出格式: {path}")

    meta = ExportMeta(path=str(path))
    # 元信息行：前 7 行，按首列标签取值；搜索条件可能跨行/跨列，做合并
    for idx in range(META_ROWS):
        row = raw[idx]
        label = _norm(row[0]) if row else ""
        value = " ".join(_norm(c) for c in row[1:] if _norm(c))
        if label.startswith("时间范围"):
            meta.time_range = value
        elif label.startswith("日志范围"):
            meta.log_range = value
        elif label.startswith("搜索条件"):
            meta.query_string = value
        elif label.startswith("访问方向"):
            meta.direction = value

    header_row = None
    for idx in range(min(len(raw), META_ROWS + 3)):
        if _norm(raw[idx][0]) == "序号" and "源IP" in [_norm(c) for c in raw[idx]]:
            header_row = idx
            break
    if header_row is None:
        header_row = META_ROWS
    header = [_norm(c) for c in raw[header_row]]
    ncols = len(header)

    rows: list[dict[str, str]] = []
    for row in raw[header_row + 1:]:
        if not any(_norm(c) for c in row[:ncols]):
            continue
        item = {header[i]: _norm(row[i]) if i < len(row) else "" for i in range(ncols)}
        if not item.get("源IP") and not item.get("目的IP"):
            continue
        rows.append(item)
    meta.total_rows = len(rows)

    # 合并导出（*99.xlsx，由本地合并工具生成）没有元信息行：回落到同目录的分段文件取搜索条件/时间范围
    if not (meta.query_string or meta.time_range):
        p = Path(path)
        siblings = sorted(
            q for q in p.parent.glob("sangfor-sip-report-KsearchLog-*.xlsx")
            if q.name != p.name and not q.name.endswith("99.xlsx")
        )
        if siblings:
            try:
                seg_meta, _ = load_export(siblings[0])
                meta.query_string = meta.query_string or seg_meta.query_string
                meta.log_range = meta.log_range or seg_meta.log_range
                meta.direction = meta.direction or seg_meta.direction
                # 注意：不从分段继承 time_range —— 那只是某个分段的时间窗，会误导整体窗口
            except Exception:
                pass
    return meta, rows


# --------------------------------------------------------------------- 聚合分析
@dataclass
class Peer:
    ip: str
    side: str            # internal / external
    events: int = 0
    ports: Counter = field(default_factory=Counter)
    descriptions: Counter = field(default_factory=Counter)

    def to_dict(self, top_desc: int = 2) -> dict:
        return {
            "ip": self.ip,
            "side": self.side,
            "events": self.events,
            "ports": [p for p, _ in self.ports.most_common(6) if p],
            "top_descriptions": [d for d, _ in self.descriptions.most_common(top_desc) if d],
        }


@dataclass
class Server:
    ip: str
    events: int = 0
    outbound_events: int = 0     # 内网 → 外网
    inbound_events: int = 0      # 外网 → 内网
    internal_peer_events: int = 0
    first_seen: str = ""
    last_seen: str = ""
    log_types: Counter = field(default_factory=Counter)
    attack_types: Counter = field(default_factory=Counter)
    severities: Counter = field(default_factory=Counter)
    descriptions: Counter = field(default_factory=Counter)
    peers: dict[str, Peer] = field(default_factory=dict)

    def peer(self, ip: str, side: str) -> Peer:
        if ip not in self.peers:
            self.peers[ip] = Peer(ip=ip, side=side)
        return self.peers[ip]

    @property
    def direction_label(self) -> str:
        out, inb, inner = self.outbound_events, self.inbound_events, self.internal_peer_events
        if out and (inb or inner):
            tag = "双向（含外联）"
        elif out:
            tag = "主动外联"
        elif inb:
            tag = "被动（外部对内）"
        elif inner:
            tag = "仅内网互访"
        else:
            tag = "未知"
        return tag

    def to_dict(self, top_desc: int = 3, top_peers: int | None = None) -> dict:
        peers = [p for p in self.peers.values() if p.ip]
        peers.sort(key=lambda p: -p.events)
        if top_peers:
            peers = peers[:top_peers]
        return {
            "ip": self.ip,
            "events": self.events,
            "direction": self.direction_label,
            "outbound_events": self.outbound_events,
            "inbound_events": self.inbound_events,
            "internal_peer_events": self.internal_peer_events,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "log_types": [k for k, _ in self.log_types.most_common(4) if k],
            "attack_types": [k for k, _ in self.attack_types.most_common(5) if k],
            "severities": dict(self.severities.most_common(4)),
            "top_descriptions": [k for k, _ in self.descriptions.most_common(top_desc) if k],
            "external_peers": [p.to_dict() for p in peers if p.side == "external"],
            "internal_peers": [p.to_dict() for p in peers if p.side == "internal"],
        }


def analyze(rows: Iterable[dict[str, str]], *, top: int = 10, top_peers: int | None = None) -> dict:
    """把导出明细聚合成「内网服务器 TOP N + 各自外联 IP」。"""
    servers: dict[str, Server] = {}
    skipped_no_internal = 0
    counted_rows = 0

    for r in rows:
        src_ip, src_type = _norm(r.get("源IP")), _norm(r.get("源所属类型"))
        dst_ip, dst_type = _norm(r.get("目的IP")), _norm(r.get("目的所属类型"))
        if not src_ip and not dst_ip:
            continue
        src_side = classify_side(src_ip, src_type) if src_ip else "external"
        dst_side = classify_side(dst_ip, dst_type) if dst_ip else "external"
        if src_side != "internal" and dst_side != "internal":
            skipped_no_internal += 1
            continue
        counted_rows += 1
        t = _ts_key(r.get("时间"))
        sev = _norm(r.get("严重等级"))
        desc = _norm(r.get("描述"))
        ltype = _norm(r.get("日志类型"))
        atype = _norm(r.get("攻击类型"))
        ports = (_norm(r.get("源端口")), _norm(r.get("目的端口")))

        # 一个日志行里可能两侧都是内网（内网互访），两侧都记一次但方向各自计数
        for host_ip, host_side, peer_ip, peer_side, host_is_src in (
            (src_ip, src_side, dst_ip, dst_side, True),
            (dst_ip, dst_side, src_ip, src_side, False),
        ):
            if host_side != "internal" or not host_ip:
                continue
            srv = servers.setdefault(host_ip, Server(ip=host_ip))
            srv.events += 1
            if not srv.first_seen or (t and t < srv.first_seen):
                srv.first_seen = t
            if not srv.last_seen or (t and t > srv.last_seen):
                srv.last_seen = t
            for counter, value in ((srv.log_types, ltype), (srv.attack_types, atype),
                                   (srv.severities, sev), (srv.descriptions, desc)):
                if value:
                    counter[value] += 1
            # 方向：谁发起 —— 内网主机是源 = 主动外联；内网主机是目的 = 被动（外部对内）
            if peer_side == "internal":
                srv.internal_peer_events += 1
            elif host_is_src:
                srv.outbound_events += 1
            else:
                srv.inbound_events += 1
            if peer_ip:
                peer = srv.peer(peer_ip, peer_side)
                peer.events += 1
                for p in ports:
                    if p:
                        peer.ports[p] += 1
                if desc:
                    peer.descriptions[desc] += 1

    ranked = sorted(servers.values(), key=lambda s: (-s.events, s.ip))[:top]
    return {
        "servers_total": len(servers),
        "rows_total": len(list(rows)) if isinstance(rows, list) else counted_rows + skipped_no_internal,
        "rows_with_internal": counted_rows,
        "rows_skipped_no_internal": skipped_no_internal,
        "top": top,
        "servers": [
            {**s.to_dict(top_peers=top_peers), "rank": i + 1} for i, s in enumerate(ranked)
        ],
    }


# --------------------------------------------------------------------- 输出
def write_outputs(out_dir: str | Path, meta: ExportMeta, report: dict) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    payload = {"meta": meta.__dict__, "report": report}
    (out / "virus_report.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")

    with (out / "virus_internal_servers.csv").open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["排名", "内网服务器", "事件数", "方向", "主动外联数", "被动数",
                    "首次出现", "末次出现", "外联IP数", "外联IP", "主要描述"])
        for s in report["servers"]:
            ext = s["external_peers"]
            w.writerow([s["rank"], s["ip"], s["events"], s["direction"], s["outbound_events"],
                        s["inbound_events"], s["first_seen"], s["last_seen"], len(ext),
                        " ".join(p["ip"] for p in ext), " / ".join(s["top_descriptions"])])

    with (out / "virus_outbound_peers.csv").open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["内网服务器", "外联IP", "事件数", "端口", "主要描述"])
        for s in report["servers"]:
            for p in s["external_peers"]:
                w.writerow([s["ip"], p["ip"], p["events"], " ".join(p["ports"]),
                            " / ".join(p["top_descriptions"])])

    (out / "virus_report.md").write_text(render_markdown(meta, report), encoding="utf-8")
    return {
        "json": str(out / "virus_report.json"),
        "servers_csv": str(out / "virus_internal_servers.csv"),
        "peers_csv": str(out / "virus_outbound_peers.csv"),
        "markdown": str(out / "virus_report.md"),
    }


def render_markdown(meta: ExportMeta, report: dict, *, max_peers: int = 15) -> str:
    lines = ["# 病毒日志分析：内网服务器 TOP %d 与外联 IP" % report["top"], ""]
    lines += [
        f"- 导出文件：`{meta.path}`",
        f"- 时间范围：{meta.time_range or '（未标注）'}",
        f"- 日志范围：{meta.log_range or '（未标注）'}　访问方向：{meta.direction or '（未标注）'}",
        f"- 搜索条件：`{meta.query_string or '（未标注）'}`",
        f"- 明细行数：{report['rows_total']}（含内网参与 {report['rows_with_internal']}，"
        f"无内网参与 {report['rows_skipped_no_internal']}）",
        f"- 涉及内网主机：{report['servers_total']} 台",
        "",
    ]
    for s in report["servers"]:
        lines.append(f"## {s['rank']}. {s['ip']}　（{s['events']} 条，{s['direction']}）")
        lines.append(f"- 首次/末次：{s['first_seen']} → {s['last_seen']}")
        if s["log_types"]:
            lines.append(f"- 日志类型：{'、'.join(s['log_types'])}")
        if s["attack_types"]:
            lines.append(f"- 攻击类型：{'、'.join(s['attack_types'])}")
        if s["top_descriptions"]:
            lines.append(f"- 典型描述：{'；'.join(s['top_descriptions'])}")
        ext = s["external_peers"][:max_peers]
        if ext:
            lines.append(f"- 外联服务器 IP（{len(s['external_peers'])} 个）：")
            for p in ext:
                port = f"，端口 {'/'.join(p['ports'][:3])}" if p["ports"] else ""
                desc = f"，{p['top_descriptions'][0]}" if p["top_descriptions"] else ""
                lines.append(f"    - `{p['ip']}`　{p['events']} 条{port}{desc}")
            if len(s["external_peers"]) > len(ext):
                lines.append(f"    - …（其余 {len(s['external_peers']) - len(ext)} 个见 CSV）")
        else:
            lines.append("- 外联服务器 IP：无（该主机在本窗口内无对外连接记录）")
        lines.append("")
    return "\n".join(lines)
