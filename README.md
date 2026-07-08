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
config/pipeline.yaml              # pipeline defaults
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
  "base_url": "https://172.16.1.118",
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
  "base_url": "https://172.16.1.116",
  "product": "sangfor-firewall",
  "cookie": "...",
  "csrf": {
    "_cftoken": "md5(md5(md5(SESSID)))",
    "gcs_csrf": "md5(x-anti-csrf-gcs)"
  }
}
```

## Unified Pipeline

Run stages through the pipeline module:

```bash
python -m pipeline.run_pipeline --config config/pipeline.yaml check-sessions
python -m pipeline.run_pipeline --config config/pipeline.yaml export-logs --start "2026-07-06 00:00:00" --end "2026-07-06 23:59:59"
python -m pipeline.run_pipeline --config config/pipeline.yaml export-firewall-blacklist
python -m pipeline.run_pipeline --config config/pipeline.yaml analyze
python -m pipeline.run_pipeline --config config/pipeline.yaml block
python -m pipeline.run_pipeline --config config/pipeline.yaml full --start "2026-07-06 00:00:00" --end "2026-07-06 23:59:59"
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
