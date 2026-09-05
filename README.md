# Sangfor Security Automation

This project combines Sangfor situation-awareness log export, Sangfor firewall blacklist export, attacker analysis, and firewall blocking into a staged automation pipeline.

The detailed design and validation plan live in `docs/sangfor-automation-pipeline-plan.md`. Treat that document as the source of truth for workflow semantics and artifact contracts.

## Directory Layout

```text
pipeline/                         # unified stage runner, config, state, reports
situation-awareness/              # SIP login/session, keepalive, and log export helpers
firewall/                         # Sangfor AF session, blacklist export, and blocking helpers
analyzer/SXF_extract_attacker/     # upstream analysis engine used by the pipeline
docs/                             # design and operational documentation
config/pipeline.yaml              # tracked placeholder defaults
secrets/pipeline.local.yaml       # optional ignored local runtime config
```

## Environment Setup

Install test/runtime dependencies for the unified pipeline:

```bash
python -m pip install -r requirements.txt
python -m playwright install --with-deps chromium
```

The broad verification command is:

```bash
python -m pytest situation-awareness firewall tests analyzer/SXF_extract_attacker/tests -q
```

## Session Files

Situation-awareness platform:

```text
/home/user/.config/sangfor/session.json
```

Required fields:

```json
{
  "base_url": "https://sip.local",
  "cookie": "...",
  "xid": "..."
}
```

Firewall:

```text
/home/user/.config/sangfor-firewall/session.json
```

Required fields:

```json
{
  "base_url": "https://firewall.local",
  "product": "sangfor-firewall",
  "cookie": "...",
  "csrf": {
    "_cftoken": "md5(md5(md5(SESSID)))",
    "gcs_csrf": "md5(x-anti-csrf-gcs)"
  }
}
```

## Unified Pipeline

By default the CLI loads `secrets/pipeline.local.yaml` when it exists, then falls back to `config/pipeline.yaml`. Keep real internal base URLs in the ignored local config, not in tracked files.

Run stages through the pipeline module:

```bash
python -m pipeline.run_pipeline check-sessions
python -m pipeline.run_pipeline export-logs --start "2026-07-06 00:00:00" --end "2026-07-06 23:59:59"
python -m pipeline.run_pipeline export-firewall-blacklist
python -m pipeline.run_pipeline merge-logs --days 30
python -m pipeline.run_pipeline review --mode cached --days 30 --min-block-age 30
python -m pipeline.run_pipeline analyze
python -m pipeline.run_pipeline block
python -m pipeline.run_pipeline full --start "2026-07-06 00:00:00" --end "2026-07-06 23:59:59"

`merge-logs` 是纯本地只读命令：按各 run 的导出窗口（`exports/manifest-*.json` 的
`requested_start/end`）挑出与近 N 天相交的日志导出，合并去重后输出到
`outputs/merged_logs/`（合并明细 CSV + 攻击者最后活跃 CSV + 覆盖报告），不访问设备。
覆盖不足或数据偏旧会在报告中提示。

`review --mode cached` 复查月度自动封禁黑名单 IP：候选解除 = 黑名单里描述匹配
`N月(自动)封禁`（兼容新旧两种模板：pipeline 的 `N月自动封禁` 与旧版脚本的 `N月封禁`）
的 IP，且近期（默认 30 天）无攻击流量、封禁超过 `--min-block-age` 天、且不在白名单。
纯本地只读，只输出候选列表（`outputs/blacklist_review/`），**不执行解除**——
解除需防火墙删除接口，`--mode fresh` 尚未实现。
```

`block` is dry-run by default. Real firewall changes require `--apply`; `full --apply` first writes dry-run artifacts and then runs the apply stage with same-run prerequisite checks.

## Artifacts

Each run writes under `runs/<run_id>/`:

```text
exports/      # exported SIP log workbooks
blacklist/    # exported firewall blacklist CSV
analysis/     # raw and normalized analyzer recommendations
block/        # targets.txt, dry_run.json, apply_result.json
logs/         # pipeline.log, events.jsonl, stage stdout/stderr logs
manifest.json # run status, stage status, inputs, outputs
```

The mutable pointer `state/latest.json` records the latest run directory. Session health snapshots are written under `state/`.

## Safety Notes

- Passwords stay in local login helpers and are not sent through chat.
- Keepalive exits when SIP returns HTTP 302 or `need_login=true` so stale sessions are not silently reused.
- Blocking uses recommendation level, existing blacklist state, allowlist, `analysis.min_final_score`, and run target limits before selecting IPs.
- `--apply` requires healthy live sessions and same-run export/analyze prerequisites unless an explicit external recommendations file is accompanied by a manual override reason.
