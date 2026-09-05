from __future__ import annotations

import json
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd

from .excelio import read_export_excel

# 导出 xlsx 的表头固定在第 8 行（前 7 行为填充空行），与 commands.prepare_analysis_input 一致。
HEADER_SKIPROWS = 7

# 合并产物保留的列（去掉每段导出自带的序号/标记/探针端口，以及体积巨大的数据包内容）。
KEEP_COLUMNS = [
    "时间",
    "描述",
    "日志类型",
    "攻击类型",
    "源IP",
    "源所属类型",
    "源端口",
    "目的IP",
    "目的所属类型",
    "目的端口",
    "严重等级",
    "动作",
    "状态码",
    "数据来源",
    "攻击结果",
    "命中白名单",
    "X-Forwarded-For",
]

# 跨 run 合并时按这些字段去重（同一攻击事件可能在重叠窗口的多次导出里重复出现）。
DEDUP_COLUMNS = ["时间", "源IP", "源端口", "目的IP", "目的端口", "攻击类型", "描述"]

TIME_COLUMN = "时间"
SRC_IP_COLUMN = "源IP"


@dataclass(frozen=True)
class RunExport:
    """一次 run 的日志导出及其覆盖窗口。"""

    run_id: str
    window_start: str
    window_end: str
    exports_dir: Path
    row_count: int | None = None
    possibly_truncated: bool = False
    error: str = ""


def _parse_time(value: str | datetime | Any) -> datetime | None:
    """把导出里的时间单元格统一解析为 naive datetime。"""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return pd.to_datetime(text, errors="coerce").to_pydatetime()
    except (TypeError, ValueError):
        return None


def _window_intersects(start: str, end: str, cutoff: datetime, now: datetime) -> bool:
    """导出窗口 [start, end) 与 [cutoff, now] 是否有交集。"""
    window_start = _parse_time(start)
    window_end = _parse_time(end)
    if window_start is None or window_end is None:
        return False
    return window_start < now and window_end > cutoff


def collect_run_exports(runs_dir: str | Path, cutoff: datetime, now: datetime) -> tuple[list[RunExport], list[dict[str, Any]]]:
    """扫描 runs/ 下所有 run，挑出导出日志窗口与 [cutoff, now] 相交的导出。

    返回 (入选的导出, 被跳过的 run 摘要)。窗口以 exports/manifest-*.json 的
    requested_start/requested_end 为准（缺失时回退到 run manifest 的 args.start/end）。
    """
    runs_path = Path(runs_dir)
    selected: list[RunExport] = []
    skipped: list[dict[str, Any]] = []

    for run_dir in sorted(runs_path.glob("*")):
        if not run_dir.is_dir():
            continue
        run_manifest_path = run_dir / "manifest.json"
        if not run_manifest_path.is_file():
            continue
        try:
            run_manifest = json.loads(run_manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            skipped.append({"run_id": run_dir.name, "reason": "unreadable manifest"})
            continue
        run_id = run_dir.name

        export_stage = (run_manifest.get("stages") or {}).get("export-logs") or {}
        if export_stage.get("status") != "completed":
            skipped.append({"run_id": run_id, "reason": "export-logs stage not completed"})
            continue

        exports_dir = run_dir / "exports"
        export_manifests = sorted(exports_dir.glob("manifest-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        window_start: str | None = None
        window_end: str | None = None
        export_manifest: dict[str, Any] = {}
        if export_manifests:
            try:
                export_manifest = json.loads(export_manifests[0].read_text(encoding="utf-8"))
            except (OSError, ValueError):
                export_manifest = {}
            window_start = export_manifest.get("requested_start")
            window_end = export_manifest.get("requested_end")
        if not window_start or not window_end:
            args = run_manifest.get("args") or {}
            window_start = args.get("start")
            window_end = args.get("end")
        if not window_start or not window_end:
            skipped.append({"run_id": run_id, "reason": "no export window recorded"})
            continue
        if not _window_intersects(window_start, window_end, cutoff, now):
            skipped.append({"run_id": run_id, "reason": "window outside range", "window": f"{window_start} -> {window_end}"})
            continue

        segments = export_manifest.get("segments") or []
        export_limit = int(export_manifest.get("limit", 0) or 0)
        split_limit = int(export_manifest.get("split_limit", 0) or 0)
        threshold = split_limit or export_limit or 10000
        last_count = int(segments[-1].get("actual_count", segments[-1].get("count", 0))) if segments else 0
        possibly_truncated = bool(segments) and last_count >= threshold
        selected.append(
            RunExport(
                run_id=run_id,
                window_start=window_start,
                window_end=window_end,
                exports_dir=exports_dir,
                possibly_truncated=possibly_truncated,
            )
        )

    return selected, skipped


def read_run_frame(exports_dir: str | Path) -> pd.DataFrame:
    """读取一次 run 的全部日志导出段，拼接为一个 DataFrame。

    以 exports/manifest-*.json 的 segments 为准（比 99 合并文件可靠：分析阶段
    失败时 99 文件可能不存在）。段文件统一跳过前 7 行填充空行。
    """
    exports_path = Path(exports_dir)
    manifests = sorted(exports_path.glob("manifest-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    frames: list[pd.DataFrame] = []
    if manifests:
        try:
            export_manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
        except (OSError, ValueError):
            export_manifest = {}
        for segment in export_manifest.get("segments") or []:
            source = exports_path / str(segment.get("file_name", ""))
            if not source.is_file():
                continue
            frame = read_export_excel(source)
            if TIME_COLUMN in frame.columns:
                frames.append(frame)
    if not frames:
        # 兜底：没有导出清单时直接找最晚的 xlsx 段文件。
        candidates = sorted(exports_path.glob("*.xlsx"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not candidates:
            raise FileNotFoundError(f"no exported log segments under {exports_path}")
        frame = read_export_excel(candidates[0])
        frames.append(frame)
    combined = pd.concat(frames, ignore_index=True)
    return combined


def merge_recent_logs(
    runs_dir: str | Path,
    output_dir: str | Path | None = None,
    *,
    days: int = 30,
    now: datetime | None = None,
) -> dict[str, Any]:
    """合并近 N 天所有 run 导出的攻击日志。

    步骤：按窗口选 run → 读各 run 导出段 → 纵向拼接 → 按时间列过滤近 N 天 →
    按攻击事件字段去重 → 写合并 CSV、攻击者最后活跃汇总 CSV、覆盖报告。
    纯本地只读操作，不访问任何设备。
    """
    runs_path = Path(runs_dir)
    current = now or datetime.now()
    cutoff = current - timedelta(days=days)

    selected, skipped = collect_run_exports(runs_path, cutoff, current)
    if not selected:
        raise ValueError(f"近 {days} 天内没有可用的日志导出（请先运行 full / export-logs）")

    def _load(run_export: RunExport) -> tuple[RunExport, pd.DataFrame | None, dict[str, Any]]:
        try:
            frame = read_run_frame(run_export.exports_dir)
        except FileNotFoundError as exc:
            return run_export, None, {"run_id": run_export.run_id, "window": f"{run_export.window_start} -> {run_export.window_end}", "rows": 0, "error": str(exc)}
        loaded = RunExport(
            run_id=run_export.run_id,
            window_start=run_export.window_start,
            window_end=run_export.window_end,
            exports_dir=run_export.exports_dir,
            row_count=len(frame),
            possibly_truncated=run_export.possibly_truncated,
        )
        summary = {
            "run_id": loaded.run_id,
            "window": f"{loaded.window_start} -> {loaded.window_end}",
            "rows": loaded.row_count,
            "possibly_truncated": loaded.possibly_truncated,
        }
        return loaded, frame, summary

    import concurrent.futures

    frames: list[pd.DataFrame] = []
    run_summaries: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(selected))) as pool:
        for run_export, frame, summary in pool.map(_load, selected):
            run_summaries.append(summary)
            if frame is not None:
                frames.append(frame)

    if not frames:
        raise ValueError("入选 run 的日志段全部读取失败，无法合并")

    merged = pd.concat(frames, ignore_index=True)
    if TIME_COLUMN in merged.columns:
        merged[TIME_COLUMN] = pd.to_datetime(merged[TIME_COLUMN], errors="coerce")
        merged = merged[merged[TIME_COLUMN].notna()]
        merged = merged[(merged[TIME_COLUMN] >= cutoff) & (merged[TIME_COLUMN] <= current)]

    merged = merged.drop_duplicates(subset=[c for c in DEDUP_COLUMNS if c in merged.columns], keep="first")

    keep = [c for c in KEEP_COLUMNS if c in merged.columns]
    merged = merged[keep].sort_values(TIME_COLUMN).reset_index(drop=True)

    # 攻击者最后活跃汇总：后续黑名单复查的直接输入。
    if SRC_IP_COLUMN in merged.columns and len(merged):
        attacker_summary = (
            merged.groupby(SRC_IP_COLUMN, dropna=False)[TIME_COLUMN]
            .agg(最后攻击时间="max", 攻击次数="count")
            .reset_index()
            .sort_values("最后攻击时间", ascending=False)
        )
    else:
        attacker_summary = pd.DataFrame(columns=[SRC_IP_COLUMN, "最后攻击时间", "攻击次数"])

    output_path = Path(output_dir) if output_dir else runs_path.parent / "outputs" / "merged_logs"
    output_path.mkdir(parents=True, exist_ok=True)
    merged_csv = output_path / f"merged_attack_logs_{days}d.csv"
    attacker_csv = output_path / f"attackers_last_seen_{days}d.csv"
    coverage_json = output_path / f"coverage_{days}d.json"
    coverage_md = output_path / f"coverage_{days}d.md"

    merged.to_csv(merged_csv, index=False, encoding="utf-8-sig")
    attacker_summary.to_csv(attacker_csv, index=False, encoding="utf-8-sig")

    covered_start = merged[TIME_COLUMN].min() if len(merged) else None
    covered_end = merged[TIME_COLUMN].max() if len(merged) else None
    stale_days = (current - covered_end).total_seconds() / 86400 if covered_end is not None else None
    notes: list[str] = []
    if stale_days is not None and stale_days > 2:
        notes.append(f"最新日志覆盖到 {covered_end:%Y-%m-%d %H:%M}，距今 {stale_days:.1f} 天，数据偏旧")
    if covered_start is not None and covered_start > cutoff:
        notes.append(f"最早日志从 {covered_start:%Y-%m-%d %H:%M} 开始，近 {days} 天窗口前段未被覆盖")
    truncated = [s["run_id"] for s in run_summaries if s.get("possibly_truncated")]
    if truncated:
        notes.append(f"以下 run 的导出可能被截断（末段达到分段阈值），覆盖不完整：{', '.join(truncated)}")
    if not notes:
        notes.append("覆盖正常")

    coverage = {
        "generated_at": current.strftime("%Y-%m-%d %H:%M:%S"),
        "days_requested": days,
        "cutoff": cutoff.strftime("%Y-%m-%d %H:%M:%S"),
        "now": current.strftime("%Y-%m-%d %H:%M:%S"),
        "runs_used": run_summaries,
        "runs_skipped": skipped,
        "total_rows": int(len(merged)),
        "unique_source_ips": int(attacker_summary[SRC_IP_COLUMN].nunique()) if len(attacker_summary) else 0,
        "covered_start": covered_start.strftime("%Y-%m-%d %H:%M:%S") if covered_start is not None else None,
        "covered_end": covered_end.strftime("%Y-%m-%d %H:%M:%S") if covered_end is not None else None,
        "stale_days": round(stale_days, 2) if stale_days is not None else None,
        "notes": notes,
        "outputs": {
            "merged_csv": str(merged_csv),
            "attackers_last_seen_csv": str(attacker_csv),
            "coverage_json": str(coverage_json),
            "coverage_md": str(coverage_md),
        },
    }
    coverage_json.write_text(json.dumps(coverage, ensure_ascii=False, indent=2), encoding="utf-8")
    coverage_md.write_text(_render_coverage_md(coverage), encoding="utf-8")
    return coverage


def _render_coverage_md(coverage: dict[str, Any]) -> str:
    lines = [
        f"# 近 {coverage['days_requested']} 天日志合并报告",
        "",
        f"- 生成时间：{coverage['generated_at']}",
        f"- 统计窗口：{coverage['cutoff']} ~ {coverage['now']}",
        f"- 合并行数：{coverage['total_rows']}",
        f"- 攻击源 IP 数：{coverage['unique_source_ips']}",
        f"- 实际覆盖：{coverage['covered_start']} ~ {coverage['covered_end']}" if coverage.get("covered_start") else "- 实际覆盖：无",
        "",
        "## 使用的 run",
        "",
        "| run_id | 窗口 | 行数 | 可能截断 |",
        "|---|---|---|---|",
    ]
    for run in coverage["runs_used"]:
        lines.append(f"| {run['run_id']} | {run['window']} | {run['rows']} | {'是' if run.get('possibly_truncated') else '否'} |")
    lines.append("")
    lines.append("## 提示")
    lines.append("")
    for note in coverage["notes"]:
        lines.append(f"- {note}")
    lines.append("")
    if coverage.get("runs_skipped"):
        lines.append("## 跳过的 run（窗口外或导出不完整）")
        lines.append("")
        for skipped in coverage["runs_skipped"]:
            lines.append(f"- {skipped.get('run_id')}: {skipped.get('reason')}")
        lines.append("")
    return "\n".join(lines)