from __future__ import annotations

import csv
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .redaction import redact_secrets

NORMALIZED_RECOMMENDATION_FIELDS = [
    "ip",
    "recommendation",
    "final_score",
    "base_score",
    "history_score",
    "attack_count",
    "threat_types",
    "severity",
    "attack_chain",
    "evidence_summary",
    "sample_urls",
    "historical_occurrences",
    "recommendation_reasons",
    "source_report",
    "already_blacklisted",
    "blocked_this_run",
    "skip_reason",
]

BLOCK_RECOMMENDATIONS = {"立即封禁", "建议封禁"}


class ApplyGuardError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class BlockSelection:
    targets: list[str]
    rows: list[dict[str, str]]
    apply: bool
    apply_refusal: str = ""


def run_subprocess(args: list[str], *, cwd: str | Path | None = None, stdout_path: Path | None = None, stderr_path: Path | None = None) -> CommandResult:
    completed = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)
    stdout = redact_secrets(completed.stdout)
    stderr = redact_secrets(completed.stderr)
    if stdout_path:
        stdout_path.write_text(stdout, encoding="utf-8")
    if stderr_path:
        stderr_path.write_text(stderr, encoding="utf-8")
    return CommandResult(args=args, returncode=completed.returncode, stdout=stdout, stderr=stderr)


def export_logs_command(root: Path, session_file: Path, start: str, end: str, favorite_name: str, output_dir: Path, export_date: str | None = None) -> list[str]:
    command = [
        sys.executable,
        str(root / "situation-awareness" / "sangfor_log_export.py"),
        "--session-file",
        str(session_file),
        "--start",
        start,
        "--end",
        end,
        "--favorite-name",
        favorite_name,
        "--output-dir",
        str(output_dir),
    ]
    if export_date:
        command.extend(["--export-date", export_date])
    return command


def export_firewall_blacklist_command(root: Path, session_file: Path, output_dir: Path) -> list[str]:
    return [
        sys.executable,
        str(root / "firewall" / "sangfor_firewall_blocklist.py"),
        "--session-file",
        str(session_file),
        "--export",
        "--output-dir",
        str(output_dir),
    ]


def analyze_command(root: Path, xlsx: Path, blacklist: Path, db_path: Path, whitelist_file: Path, output_dir: Path, *, persist_history: bool = False) -> tuple[list[str], Path]:
    analyzer_dir = root / "analyzer" / "SXF_extract_attacker"
    command = [
        sys.executable,
        "extract_attacker.py",
        str(xlsx),
        "--blacklist",
        str(blacklist),
        "--exclude-from-csv",
        "--local-analyze",
        "--blocklist",
    ]
    if not persist_history:
        command.append("--no-db")
    command.extend([
        "--db-path",
        str(db_path),
    ])
    return command, analyzer_dir


def block_command(root: Path, session_file: Path, targets_file: Path, description: str, *, apply: bool) -> list[str]:
    command = [
        sys.executable,
        str(root / "firewall" / "sangfor_firewall_blocklist.py"),
        "--session-file",
        str(session_file),
        "--file",
        str(targets_file),
        "--desc",
        description,
    ]
    if apply:
        command.append("--execute")
    return command


def normalize_recommendations(raw_csv: str | Path, output_csv: str | Path, *, source_report: str | Path = "") -> Path:
    raw_path = Path(raw_csv)
    out_path = Path(output_csv)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, str]] = []
    with raw_path.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            rows.append(_normalize_row(row, str(source_report)))
    _write_normalized(out_path, rows)
    return out_path


def select_block_targets(
    normalized_csv: str | Path,
    *,
    whitelist_file: str | Path | None = None,
    max_targets: int = 200,
    min_final_score: int | None = None,
    apply: bool = False,
    recommendation_levels: Iterable[str] = BLOCK_RECOMMENDATIONS,
    run_dir: str | Path | None = None,
    explicit_recommendations: bool = False,
    manual_override_reason: str | None = None,
) -> BlockSelection:
    normalized_path = Path(normalized_csv).resolve()
    if apply and run_dir is not None:
        run_path = Path(run_dir).resolve()
        if explicit_recommendations:
            if run_path not in normalized_path.parents and not (manual_override_reason or "").strip():
                raise ApplyGuardError("apply with an external recommendations file requires a manual override reason")
        elif run_path not in normalized_path.parents:
            raise ApplyGuardError("apply requires recommendations from the current run or an explicit recommendations path")
    whitelist = _load_whitelist(whitelist_file)
    allowed = set(recommendation_levels)
    selected: list[str] = []
    rows: list[dict[str, str]] = []
    with normalized_path.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            row = {field: row.get(field, "") for field in NORMALIZED_RECOMMENDATION_FIELDS}
            ip = row["ip"].strip()
            reason = ""
            if row["recommendation"] not in allowed:
                reason = "recommendation_not_blocked"
            elif min_final_score is not None and _score(row["final_score"]) < min_final_score:
                reason = "below_min_final_score"
            elif _truthy(row["already_blacklisted"]):
                reason = "already_blacklisted"
            elif ip in whitelist:
                reason = "whitelisted"
            elif len(selected) >= max_targets:
                reason = "max_targets_exceeded"
            elif ip:
                selected.append(ip)
                row["blocked_this_run"] = "true" if apply else "false"
            else:
                reason = "missing_ip"
            row["skip_reason"] = reason
            rows.append(row)
    apply_refusal = "no_targets" if apply and not selected else ""
    return BlockSelection(targets=selected, rows=rows, apply=apply, apply_refusal=apply_refusal)


def write_block_artifacts(selection: BlockSelection, block_dir: str | Path) -> tuple[Path, Path]:
    block_path = Path(block_dir)
    block_path.mkdir(parents=True, exist_ok=True)
    targets_path = block_path / "targets.txt"
    dry_run_path = block_path / "dry_run.json"
    targets_path.write_text("\n".join(selection.targets) + ("\n" if selection.targets else ""), encoding="utf-8")
    dry_run_path.write_text(
        _json_dumps({"apply": selection.apply, "target_count": len(selection.targets), "targets": selection.targets, "rows": selection.rows}),
        encoding="utf-8",
    )
    return targets_path, dry_run_path


def write_apply_result(selection: BlockSelection, block_dir: str | Path, *, executed: bool, command_result: CommandResult | None = None) -> Path:
    block_path = Path(block_dir)
    block_path.mkdir(parents=True, exist_ok=True)
    path = block_path / "apply_result.json"
    status = "executed" if executed else "refused" if selection.apply_refusal else "not_requested"
    payload = {
        "apply": selection.apply,
        "status": status,
        "reason": selection.apply_refusal,
        "target_count": len(selection.targets),
        "targets": selection.targets,
    }
    if command_result is not None:
        payload["command"] = [redact_secrets(part) for part in command_result.args]
        payload["returncode"] = command_result.returncode
        payload["stdout"] = command_result.stdout
        payload["stderr"] = command_result.stderr
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def rewrite_normalized_with_selection(selection: BlockSelection, output_csv: str | Path) -> Path:
    out_path = Path(output_csv)
    _write_normalized(out_path, selection.rows)
    return out_path


def find_latest_file(directory: str | Path, pattern: str) -> Path:
    matches = sorted(Path(directory).glob(pattern), key=lambda path: path.stat().st_mtime, reverse=True)
    if not matches:
        raise FileNotFoundError(f"no files matching {pattern} in {directory}")
    return matches[0]


def copy_analyzer_output(root: Path, analysis_dir: Path, source_report: Path) -> Path:
    expected = root / "analyzer" / "SXF_extract_attacker" / "outputs" / f"{source_report.stem}_blocklist_recommendations.csv"
    if not expected.exists():
        expected = find_latest_file(root / "analyzer" / "SXF_extract_attacker" / "outputs", "*_blocklist_recommendations.csv")
    dest = analysis_dir / expected.name
    shutil.copy2(expected, dest)
    return dest


def _normalize_row(row: dict[str, str], source_report: str) -> dict[str, str]:
    final_score = _first(row, "final_score", "评分", "最终评分")
    evidence_summary = _join_nonempty(
        _first(row, "evidence_summary", "证据摘要", "evidence", default=""),
        _first(row, "样本描述", "sample_description", default=""),
        _first(row, "Payload风险", "payload_risk", default=""),
    )
    return {
        "ip": _first(row, "ip", "IP", "源IP", "src_ip"),
        "recommendation": _first(row, "recommendation", "建议", "推荐动作"),
        "final_score": final_score,
        "base_score": _first(row, "base_score", "基础评分", "行为分", default=final_score),
        "history_score": _first(row, "history_score", "历史评分", default=""),
        "attack_count": _first(row, "attack_count", "攻击次数", "count", default=""),
        "threat_types": _first(row, "threat_types", "主要威胁", "威胁类型", "主要威胁类型", default=""),
        "severity": _first(row, "severity", "最高严重等级", "严重等级", default=""),
        "attack_chain": _first(row, "attack_chain", "攻击链", "攻击链阶段", default=""),
        "evidence_summary": _truncate(evidence_summary),
        "sample_urls": _truncate(_first(row, "sample_urls", "样本URL", "样本 URL", "url", default="")),
        "historical_occurrences": _first(row, "historical_occurrences", "历史出现次数", default=""),
        "recommendation_reasons": _first(row, "recommendation_reasons", "推荐理由", "原因", default=""),
        "source_report": _first(row, "source_report", default=source_report),
        "already_blacklisted": str(_first(row, "already_blacklisted", "已在黑名单", default="false")).lower(),
        "blocked_this_run": str(_first(row, "blocked_this_run", default="false")).lower(),
        "skip_reason": _first(row, "skip_reason", default=""),
    }


def _join_nonempty(*values: str) -> str:
    return " | ".join(value.strip() for value in values if value and value.strip())


def _first(row: dict[str, str], *keys: str, default: str = "") -> str:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip() != "":
            return str(value).strip()
    return default


def _truncate(value: str, limit: int = 500) -> str:
    return value if len(value) <= limit else value[:limit] + "..."


def _load_whitelist(path: str | Path | None) -> set[str]:
    if not path or not Path(path).exists():
        return set()
    entries = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.add(line)
    return entries


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y", "是", "已封禁"}


def _score(value: str) -> int:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return 0


def _write_normalized(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=NORMALIZED_RECOMMENDATION_FIELDS)
        writer.writeheader()
        writer.writerows({field: row.get(field, "") for field in NORMALIZED_RECOMMENDATION_FIELDS} for row in rows)


def _json_dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)
