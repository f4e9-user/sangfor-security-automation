from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

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
