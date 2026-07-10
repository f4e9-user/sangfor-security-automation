from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any, TextIO

from .commands import NORMALIZED_RECOMMENDATION_FIELDS
from .redaction import redact_data, redact_secrets


def write_daily_report(
    run_dir: str | Path,
    manifest: dict[str, Any],
    normalized_csv: str | Path,
    *,
    log_window: tuple[str, str] | None = None,
) -> tuple[Path, Path]:
    run_path = Path(run_dir)
    reports_dir = run_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    rows = _read_rows(normalized_csv)
    blocked = [row for row in rows if _truthy(row.get("blocked_this_run", ""))]
    skipped = [row for row in rows if row.get("skip_reason")]
    payload = redact_data(
        {
            "run_id": manifest.get("run_id", run_path.name),
            "started_at": manifest.get("started_at"),
            "ended_at": manifest.get("ended_at"),
            "log_window": {"start": log_window[0], "end": log_window[1]} if log_window else None,
            "session_checks": _session_checks(manifest),
            "exported_logs": manifest.get("outputs", {}).get("exported_xlsx", ""),
            "firewall_blacklist": manifest.get("outputs", {}).get("firewall_blacklist", ""),
            "analyzed_log_count": _analyzed_log_count(manifest, run_path),
            "candidate_ip_count": len(rows),
            "blocked_count": len(blocked),
            "skipped_count": len(skipped),
            "blocked_ips": [_evidence(row) for row in blocked],
            "skipped_ips": [_skip(row) for row in skipped],
        }
    )

    json_path = reports_dir / "daily_report.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    md_path = reports_dir / "daily_report.md"
    md_path.write_text(_markdown(payload), encoding="utf-8")
    return md_path, json_path


def _read_rows(path: str | Path) -> list[dict[str, str]]:
    with Path(path).open(newline="", encoding="utf-8-sig") as handle:
        return [
            {field: redact_secrets(row.get(field, "")) for field in NORMALIZED_RECOMMENDATION_FIELDS}
            for row in csv.DictReader(handle)
        ]


def _session_checks(manifest: dict[str, Any]) -> dict[str, str]:
    stages = manifest.get("stages", {}) if isinstance(manifest.get("stages", {}), dict) else {}
    check = stages.get("check-sessions", {}) if isinstance(stages.get("check-sessions", {}), dict) else {}
    return {"check-sessions": str(check.get("status", "unknown"))}


def _evidence(row: dict[str, str]) -> dict[str, str]:
    return {
        "ip": row.get("ip", ""),
        "recommendation": row.get("recommendation", ""),
        "final_score": row.get("final_score", ""),
        "attack_count": row.get("attack_count", ""),
        "threat_types": row.get("threat_types", ""),
        "severity": row.get("severity", ""),
        "attack_chain": row.get("attack_chain", ""),
        "sample_urls": row.get("sample_urls", ""),
        "evidence_summary": row.get("evidence_summary", ""),
        "historical_occurrences": row.get("historical_occurrences", ""),
        "recommendation_reasons": row.get("recommendation_reasons", ""),
        "source_report": row.get("source_report", ""),
    }


def _skip(row: dict[str, str]) -> dict[str, str]:
    skipped = _evidence(row)
    skipped["skip_reason"] = row.get("skip_reason", "")
    return skipped


def _markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Sangfor Daily Security Report",
        "",
        f"- Run ID: {payload.get('run_id', '')}",
        f"- Started: {payload.get('started_at', '')}",
        f"- Ended: {payload.get('ended_at', '')}",
    ]
    window = payload.get("log_window") or {}
    if window:
        lines.append(f"- Log window: {window.get('start', '')} to {window.get('end', '')}")
    lines.extend(
        [
            f"- Session checks: {(payload.get('session_checks') or {}).get('check-sessions', 'unknown')}",
            f"- Exported logs: {payload.get('exported_logs', '')}",
            f"- Firewall blacklist: {payload.get('firewall_blacklist', '')}",
            f"- Analyzed logs: {_fmt_count(payload.get('analyzed_log_count'))}",
            f"- Candidate malicious IPs: {payload.get('candidate_ip_count', 0)}",
            f"- Actually blocked IPs: {payload.get('blocked_count', 0)}",
            "",
            "## Blocked IPs",
        ]
    )
    for row in payload.get("blocked_ips", []):
        lines.extend(_evidence_lines(row))
    if not payload.get("blocked_ips"):
        lines.append("- None")
    lines.extend(["", "## Skipped IPs"])
    for row in payload.get("skipped_ips", []):
        lines.extend(_evidence_lines(row, prefix=f"skip_reason={row.get('skip_reason', '')}"))
    if not payload.get("skipped_ips"):
        lines.append("- None")
    return redact_secrets("\n".join(lines) + "\n")


def _evidence_lines(row: dict[str, str], *, prefix: str = "") -> list[str]:
    head = f"- {row.get('ip', '')}"
    if prefix:
        head += f" ({prefix})"
    return [
        head,
        f"  recommendation: {row.get('recommendation', '')}, final_score: {row.get('final_score', '')}, attack_count: {row.get('attack_count', '')}",
        f"  threat_types: {row.get('threat_types', '')}, severity: {row.get('severity', '')}, attack_chain: {row.get('attack_chain', '')}",
        f"  sample_urls: {row.get('sample_urls', '')}",
        f"  evidence_summary: {row.get('evidence_summary', '')}",
        f"  historical_occurrences: {row.get('historical_occurrences', '')}, reasons: {row.get('recommendation_reasons', '')}",
    ]


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y", "是"}


def _fmt_count(value: Any) -> str:
    return "N/A" if value is None else str(value)


def _analyzed_log_count(manifest: dict[str, Any], run_path: Path) -> int | None:
    """Number of SIP log entries analyzed in this run.

    Prefer the value captured into the run manifest during export; fall back to
    the export manifest JSON written alongside the xlsx (so historical runs that
    predate that capture still report a count).
    """
    outputs = manifest.get("outputs", {}) if isinstance(manifest, dict) else {}
    stored = outputs.get("exported_log_count")
    if isinstance(stored, int):
        return stored
    try:
        stored_int = int(stored)
    except (TypeError, ValueError):
        stored_int = None
    if stored_int is not None:
        return stored_int
    return read_exported_log_count(run_path / "exports")


def read_exported_log_count(exports_dir: str | Path) -> int | None:
    """Read total_count from the latest exports/manifest-*.json, or None."""
    exports_path = Path(exports_dir)
    if not exports_path.is_dir():
        return None
    candidates = sorted(exports_path.glob("manifest-*.json"))
    if not candidates:
        return None
    try:
        data = json.loads(candidates[-1].read_text(encoding="utf-8"))
        total = data.get("total_count")
        return int(total) if total is not None else None
    except (OSError, ValueError, TypeError):
        return None


def print_console_report(run_dir: str | Path, *, stream: TextIO = sys.stdout) -> int:
    """Print a concise terminal summary for a run: analyzed logs, blocked IP
    count, and the evidence chain for each actually-blocked IP.

    Read-only. Returns the number of blocked IPs printed.
    """
    run_path = Path(run_dir)
    payload = _load_report_payload(run_path)
    blocked_ips = payload.get("blocked_ips", []) or []
    window = payload.get("log_window") or {}
    window_text = f"  ({window.get('start', '?')} → {window.get('end', '?')})" if window else ""

    lines: list[str] = []
    lines.append(f"Run {payload.get('run_id', run_path.name)}{window_text}")
    lines.append(f"分析日志: {_fmt_count(payload.get('analyzed_log_count'))} 条")
    lines.append(
        f"候选恶意 IP: {payload.get('candidate_ip_count', 0)} | "
        f"实际封禁: {payload.get('blocked_count', 0)} | "
        f"跳过: {payload.get('skipped_count', 0)}"
    )
    lines.append("")
    lines.append("已封禁 IP 证据链:")
    if not blocked_ips:
        lines.append("  无")
    for index, row in enumerate(blocked_ips, start=1):
        lines.append(
            f"[{index}] {row.get('ip', '')}   评分 {row.get('final_score', '')}  "
            f"攻击 {row.get('attack_count', '')}  {row.get('recommendation', '')}"
        )
        if row.get("threat_types"):
            lines.append(f"    威胁: {row.get('threat_types', '')}")
        if row.get("attack_chain"):
            lines.append(f"    攻击链: {row.get('attack_chain', '')}")
        if row.get("evidence_summary"):
            lines.append(f"    证据: {row.get('evidence_summary', '')}")
        if row.get("recommendation_reasons"):
            lines.append(f"    理由: {row.get('recommendation_reasons', '')}")
    stream.write(redact_secrets("\n".join(lines) + "\n"))
    return len(blocked_ips)


def _load_manifest(run_path: Path) -> dict[str, Any]:
    manifest_file = run_path / "manifest.json"
    if not manifest_file.is_file():
        return {}
    try:
        return json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _load_report_payload(run_path: Path) -> dict[str, Any]:
    """Load the daily report payload, preferring reports/daily_report.json and
    falling back to a minimal payload computed from the normalized CSV +
    run manifest (so runs without a written report still summarize).
    """
    json_path = run_path / "reports" / "daily_report.json"
    if json_path.is_file():
        try:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = None
        if payload is not None:
            # Backfill analyzed_log_count for runs whose report predates that field.
            if payload.get("analyzed_log_count") is None:
                manifest = _load_manifest(run_path)
                payload["analyzed_log_count"] = _analyzed_log_count(manifest, run_path)
            return payload

    manifest = _load_manifest(run_path)

    rows: list[dict[str, str]] = []
    normalized = run_path / "analysis" / "blocklist_recommendations.normalized.csv"
    if normalized.is_file():
        try:
            rows = _read_rows(normalized)
        except OSError:
            rows = []
    blocked = [row for row in rows if _truthy(row.get("blocked_this_run", ""))]
    skipped = [row for row in rows if row.get("skip_reason")]
    return {
        "run_id": manifest.get("run_id", run_path.name),
        "log_window": None,
        "analyzed_log_count": _analyzed_log_count(manifest, run_path),
        "candidate_ip_count": len(rows),
        "blocked_count": len(blocked),
        "skipped_count": len(skipped),
        "blocked_ips": [_evidence(row) for row in blocked],
    }
