import csv
import json
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from pipeline.artifacts import ArtifactStore
from pipeline.config import PipelineConfig, schedule_window
from pipeline.redaction import redact_secrets
from pipeline.run_pipeline import PipelineRunner, run_command
from pipeline.sessions import MissingSessionError, validate_firewall_session, validate_sip_session
from pipeline.state import EventLogger, RunManifest
from pipeline.commands import (
    NORMALIZED_RECOMMENDATION_FIELDS,
    ApplyGuardError,
    normalize_recommendations,
    select_block_targets,
    write_apply_result,
)
from pipeline.reports import write_daily_report


SECRET_TEXT = "Cookie: SESSID=abc; Authorization: Bearer hidden; xid=secret-xid; _cftoken=csrf-secret"


def read_csv(path: Path):
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_redaction_removes_headers_json_fields_and_cli_values():
    payload = (
        "Cookie: SESSID=abc; Set-Cookie: token=def\n"
        "Authorization: Bearer bearer-secret\n"
        '{"cookie": "secret-cookie", "xid": "secret-xid", "csrf": {"_cftoken": "csrf-secret"}, "api_key": "key"}\n'
        "cmd --cookie raw-cookie --xid raw-xid --csrf-token raw-csrf --password pass123 token=kv-token"
    )

    redacted = redact_secrets(payload)

    assert "secret-cookie" not in redacted
    assert "secret-xid" not in redacted
    assert "csrf-secret" not in redacted
    assert "raw-cookie" not in redacted
    assert "raw-xid" not in redacted
    assert "raw-csrf" not in redacted
    assert "pass123" not in redacted
    assert "kv-token" not in redacted
    assert redacted.count("[REDACTED]") >= 7


def test_artifact_store_creates_run_layout_and_latest_state(tmp_path):
    store = ArtifactStore(tmp_path / "runs", tmp_path / "state")

    artifacts = store.create_run("20260707_130000")

    assert artifacts.run_dir == tmp_path / "runs" / "20260707_130000"
    for dirname in ["exports", "blacklist", "analysis", "block", "logs"]:
        assert (artifacts.run_dir / dirname).is_dir()
    latest = json.loads((tmp_path / "state" / "latest.json").read_text(encoding="utf-8"))
    assert latest["run_id"] == "20260707_130000"
    assert latest["run_dir"] == str(artifacts.run_dir)


def test_normalize_recommendations_writes_standard_schema(tmp_path):
    source_report = tmp_path / "sangfor-sip-report-KsearchLog-2026070701.xlsx"
    raw_csv = tmp_path / "raw.csv"
    raw_csv.write_text(
        "IP,建议,评分,final_score,base_score,history_score,攻击次数,威胁类型,最高严重等级,攻击链,证据摘要,样本URL,历史出现次数,推荐理由,already_blacklisted\n"
        "1.1.1.1,立即封禁,88,91,70,21,42,SQL注入|扫描,高,侦察>利用,证据,https://example.test/a,3,高频攻击|历史复现,false\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "blocklist_recommendations.normalized.csv"

    normalize_recommendations(raw_csv, normalized, source_report=source_report)

    rows = read_csv(normalized)
    assert rows[0].keys() == set(NORMALIZED_RECOMMENDATION_FIELDS)
    assert rows[0]["ip"] == "1.1.1.1"
    assert rows[0]["recommendation"] == "立即封禁"
    assert rows[0]["final_score"] == "91"
    assert rows[0]["source_report"] == str(source_report)
    assert rows[0]["blocked_this_run"] == "false"
    assert rows[0]["skip_reason"] == ""


def test_select_block_targets_defaults_to_dry_run_and_skips_monitoring_whitelist_and_blacklist(tmp_path):
    normalized = tmp_path / "blocklist_recommendations.normalized.csv"
    normalized.write_text(
        "ip,recommendation,final_score,base_score,history_score,attack_count,threat_types,severity,attack_chain,evidence_summary,sample_urls,historical_occurrences,recommendation_reasons,source_report,already_blacklisted,blocked_this_run,skip_reason\n"
        "1.1.1.1,立即封禁,90,70,20,10,扫描,高,侦察,证据,url,1,高频,report.xlsx,false,false,\n"
        "2.2.2.2,建议封禁,60,45,15,6,注入,中,利用,证据,url,0,命中,report.xlsx,false,false,\n"
        "3.3.3.3,持续监控,80,60,20,8,扫描,中,侦察,证据,url,0,观察,report.xlsx,false,false,\n"
        "4.4.4.4,立即封禁,95,75,20,9,扫描,高,侦察,证据,url,0,白名单,report.xlsx,false,false,\n"
        "5.5.5.5,立即封禁,95,75,20,9,扫描,高,侦察,证据,url,0,已封禁,report.xlsx,true,false,\n",
        encoding="utf-8",
    )
    whitelist = tmp_path / "ip_whitelist.txt"
    whitelist.write_text("4.4.4.4\n", encoding="utf-8")

    selection = select_block_targets(normalized, whitelist_file=whitelist, max_targets=200, apply=False)

    assert selection.targets == ["1.1.1.1", "2.2.2.2"]
    assert selection.apply is False
    assert selection.rows[2]["skip_reason"] == "recommendation_not_blocked"
    assert selection.rows[3]["skip_reason"] == "whitelisted"
    assert selection.rows[4]["skip_reason"] == "already_blacklisted"


def test_select_block_targets_skips_scores_below_min_final_score(tmp_path):
    normalized = tmp_path / "blocklist_recommendations.normalized.csv"
    normalized.write_text(
        "ip,recommendation,final_score,base_score,history_score,attack_count,threat_types,severity,attack_chain,evidence_summary,sample_urls,historical_occurrences,recommendation_reasons,source_report,already_blacklisted,blocked_this_run,skip_reason\n"
        "1.1.1.1,立即封禁,44,30,14,10,扫描,中,侦察,证据,url,1,低分,report.xlsx,false,false,\n"
        "2.2.2.2,建议封禁,45,30,15,6,注入,中,利用,证据,url,0,达标,report.xlsx,false,false,\n",
        encoding="utf-8",
    )

    selection = select_block_targets(normalized, whitelist_file=None, max_targets=200, apply=False, min_final_score=45)

    assert selection.targets == ["2.2.2.2"]
    assert selection.rows[0]["skip_reason"] == "below_min_final_score"
    assert selection.rows[1]["skip_reason"] == ""


def test_session_validation_fails_when_required_files_or_fields_are_missing(tmp_path):
    missing = tmp_path / "missing.json"
    with pytest.raises(MissingSessionError):
        validate_sip_session(missing)

    sip = tmp_path / "sip.json"
    sip.write_text(json.dumps({"base_url": "https://sip.local", "cookie": "cookie-only"}), encoding="utf-8")
    with pytest.raises(MissingSessionError, match="xid"):
        validate_sip_session(sip)

    firewall = tmp_path / "firewall.json"
    firewall.write_text(json.dumps({"base_url": "https://fw.local"}), encoding="utf-8")
    with pytest.raises(MissingSessionError, match="cookie"):
        validate_firewall_session(firewall)


def test_check_sessions_runs_live_health_checks_and_writes_status_evidence(tmp_path, monkeypatch):
    sip = tmp_path / "sip.json"
    firewall = tmp_path / "firewall.json"
    sip.write_text(json.dumps({"base_url": "https://sip.local", "cookie": "sip-cookie", "xid": "xid"}), encoding="utf-8")
    firewall.write_text(json.dumps({"base_url": "https://fw.local", "cookie": "fw-cookie"}), encoding="utf-8")
    config = PipelineConfig.from_dict(
        {
            "paths": {
                "sip_session_file": str(sip),
                "firewall_session_file": str(firewall),
                "runs_dir": str(tmp_path / "runs"),
                "state_dir": str(tmp_path / "state"),
            }
        },
        root_dir=tmp_path,
    )
    artifacts = ArtifactStore(tmp_path / "runs", tmp_path / "state").create_run("20260707_083000")
    runner = PipelineRunner(config, artifacts, RunManifest(artifacts.run_dir, artifacts.run_id, {}), EventLogger(artifacts.run_dir, artifacts.run_id))

    monkeypatch.setattr("pipeline.run_pipeline.check_sip_session_health", lambda path: {"healthy": True, "need_login": False, "session_file": str(path)})
    monkeypatch.setattr("pipeline.run_pipeline.check_firewall_session_health", lambda path: {"healthy": True, "login_page": False, "session_file": str(path)})

    runner.check_sessions()

    sip_status = json.loads((tmp_path / "state" / "sip_session.status.json").read_text(encoding="utf-8"))
    firewall_status = json.loads((tmp_path / "state" / "firewall_session.status.json").read_text(encoding="utf-8"))
    assert sip_status["healthy"] is True
    assert sip_status["need_login"] is False
    assert "timestamp" in sip_status
    assert firewall_status["healthy"] is True
    assert firewall_status["login_page"] is False


def test_check_sessions_rejects_need_login_health_result(tmp_path, monkeypatch):
    sip = tmp_path / "sip.json"
    firewall = tmp_path / "firewall.json"
    sip.write_text(json.dumps({"base_url": "https://sip.local", "cookie": "sip-cookie", "xid": "xid"}), encoding="utf-8")
    firewall.write_text(json.dumps({"base_url": "https://fw.local", "cookie": "fw-cookie"}), encoding="utf-8")
    config = PipelineConfig.from_dict({"paths": {"sip_session_file": str(sip), "firewall_session_file": str(firewall)}}, root_dir=tmp_path)
    artifacts = ArtifactStore(tmp_path / "runs", tmp_path / "state").create_run("20260707_083000")
    runner = PipelineRunner(config, artifacts, RunManifest(artifacts.run_dir, artifacts.run_id, {}), EventLogger(artifacts.run_dir, artifacts.run_id))

    monkeypatch.setattr("pipeline.run_pipeline.check_sip_session_health", lambda path: {"healthy": False, "need_login": True, "session_file": str(path)})
    monkeypatch.setattr("pipeline.run_pipeline.check_firewall_session_health", lambda path: {"healthy": True, "login_page": False, "session_file": str(path)})

    with pytest.raises(MissingSessionError, match="SIP session health check failed"):
        runner.check_sessions()


def test_manifest_and_events_redact_secret_values(tmp_path):
    run_dir = tmp_path / "runs" / "20260707_130000"
    (run_dir / "logs").mkdir(parents=True)
    manifest = RunManifest(run_dir, "20260707_130000", {"session": SECRET_TEXT})
    manifest.start_stage("check-sessions", {"message": SECRET_TEXT})
    manifest.finish_stage("check-sessions", "failed", error=SECRET_TEXT)
    manifest.finish("failed", error=SECRET_TEXT)

    event_logger = EventLogger(run_dir, "20260707_130000")
    event_logger.emit("check-sessions", "ERROR", "session_failed", SECRET_TEXT, {"secret": SECRET_TEXT})

    manifest_text = (run_dir / "manifest.json").read_text(encoding="utf-8")
    events_text = (run_dir / "logs" / "events.jsonl").read_text(encoding="utf-8")
    combined = manifest_text + events_text
    assert "SESSID=abc" not in combined
    assert "secret-xid" not in combined
    assert "csrf-secret" not in combined
    assert "[REDACTED]" in combined


def test_event_logger_writes_human_readable_pipeline_log(tmp_path):
    run_dir = tmp_path / "runs" / "20260707_130000"
    event_logger = EventLogger(run_dir, "20260707_130000")

    event_logger.emit("check-sessions", "INFO", "stage_started", "Cookie: SESSID=abc")

    pipeline_log = run_dir / "logs" / "pipeline.log"
    assert pipeline_log.exists()
    text = pipeline_log.read_text(encoding="utf-8")
    assert "check-sessions" in text
    assert "stage_started" in text
    assert "SESSID=abc" not in text
    assert "[REDACTED]" in text


def test_check_sessions_command_returns_failure_for_missing_sessions(tmp_path):
    config_path = tmp_path / "pipeline.yaml"
    config_path.write_text(
        "paths:\n"
        f"  sip_session_file: {tmp_path / 'missing-sip.json'}\n"
        f"  firewall_session_file: {tmp_path / 'missing-firewall.json'}\n"
        f"  runs_dir: {tmp_path / 'runs'}\n"
        f"  state_dir: {tmp_path / 'state'}\n"
        f"  data_dir: {tmp_path / 'data'}\n"
        "analysis:\n"
        f"  whitelist_file: {tmp_path / 'ip_whitelist.txt'}\n"
        "blocking:\n"
        "  max_targets_per_run: 200\n",
        encoding="utf-8",
    )

    exit_code = run_command(["--config", str(config_path), "check-sessions"])

    assert exit_code == 1
    latest = json.loads((tmp_path / "state" / "latest.json").read_text(encoding="utf-8"))
    manifest = json.loads((Path(latest["run_dir"]) / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert manifest["stages"]["check-sessions"]["status"] == "failed"


def test_schedule_window_calculates_previous_day_in_configured_timezone(tmp_path):
    config = PipelineConfig.from_dict(
        {
            "schedules": {
                "daily-default": {
                    "enabled": True,
                    "cron": "30 8 * * *",
                    "timezone": "Asia/Shanghai",
                    "favorite_name": "3",
                    "window": {
                        "type": "previous_day",
                        "timezone": "Asia/Shanghai",
                        "start_time": "00:00:00",
                        "end_time": "23:59:59",
                    },
                }
            }
        },
        root_dir=tmp_path,
    )

    start, end = schedule_window(
        config.schedules["daily-default"],
        now=datetime(2026, 7, 7, 8, 30, tzinfo=ZoneInfo("Asia/Shanghai")),
    )

    assert start == "2026-07-06 00:00:00"
    assert end == "2026-07-06 23:59:59"


def test_scheduled_apply_requires_config_allow_apply(tmp_path, monkeypatch):
    config = PipelineConfig.from_dict(
        {
            "schedules": {
                "dry-run-job": {
                    "enabled": True,
                    "cron": "30 8 * * *",
                    "timezone": "Asia/Shanghai",
                    "allow_apply": False,
                    "favorite_name": "3",
                    "window": {"type": "previous_day", "start_time": "00:00:00", "end_time": "23:59:59"},
                },
                "apply-job": {
                    "enabled": True,
                    "cron": "30 8 * * *",
                    "timezone": "Asia/Shanghai",
                    "allow_apply": True,
                    "favorite_name": "3",
                    "window": {"type": "previous_day", "start_time": "00:00:00", "end_time": "23:59:59"},
                },
            }
        },
        root_dir=tmp_path,
    )
    artifacts = ArtifactStore(tmp_path / "runs", tmp_path / "state").create_run("20260707_083000")
    manifest = RunManifest(artifacts.run_dir, artifacts.run_id, {})
    events = EventLogger(artifacts.run_dir, artifacts.run_id)
    runner = PipelineRunner(config, artifacts, manifest, events)
    calls = []

    def fake_full(start, end, favorite_name, export_date, *, apply=False):
        calls.append({"start": start, "end": end, "favorite_name": favorite_name, "apply": apply})

    monkeypatch.setattr(runner, "full", fake_full)
    monkeypatch.setattr("pipeline.run_pipeline.schedule_window", lambda schedule: ("2026-07-06 00:00:00", "2026-07-06 23:59:59"))

    runner.scheduled("dry-run-job", apply=True)
    runner.scheduled("apply-job", apply=True)

    assert calls[0]["apply"] is False
    assert calls[1]["apply"] is True


def test_full_apply_runs_dry_run_before_apply(tmp_path, monkeypatch):
    config = PipelineConfig.from_dict({}, root_dir=tmp_path)
    artifacts = ArtifactStore(tmp_path / "runs", tmp_path / "state").create_run("20260707_083000")
    runner = PipelineRunner(config, artifacts, RunManifest(artifacts.run_dir, artifacts.run_id, {}), EventLogger(artifacts.run_dir, artifacts.run_id))
    recommendations = artifacts.analysis_dir / "blocklist_recommendations.normalized.csv"
    calls = []

    monkeypatch.setattr(runner, "check_sessions", lambda: calls.append(("check_sessions", None)))
    monkeypatch.setattr(runner, "export_logs", lambda start, end, favorite_name, export_date: calls.append(("export_logs", None)) or tmp_path / "logs.xlsx")
    monkeypatch.setattr(runner, "export_firewall_blacklist", lambda: calls.append(("export_firewall_blacklist", None)) or tmp_path / "blacklist.csv")
    monkeypatch.setattr(runner, "analyze", lambda xlsx, blacklist: calls.append(("analyze", None)) or recommendations)
    monkeypatch.setattr(runner, "block", lambda recs, *, apply=False, manual_override_reason=None: calls.append(("block", apply)) or ["1.1.1.1"])
    monkeypatch.setattr("pipeline.run_pipeline.write_daily_report", lambda *args, **kwargs: (tmp_path / "report.md", tmp_path / "report.json"))

    runner.full("2026-07-06 00:00:00", "2026-07-06 23:59:59", None, None, apply=True)

    assert calls == [
        ("check_sessions", None),
        ("export_logs", None),
        ("export_firewall_blacklist", None),
        ("analyze", None),
        ("block", False),
        ("block", True),
    ]


def test_apply_refuses_when_targets_are_empty_and_writes_apply_result(tmp_path):
    normalized = tmp_path / "runs" / "20260707_083000" / "analysis" / "blocklist_recommendations.normalized.csv"
    normalized.parent.mkdir(parents=True)
    normalized.write_text(
        "ip,recommendation,final_score,base_score,history_score,attack_count,threat_types,severity,attack_chain,evidence_summary,sample_urls,historical_occurrences,recommendation_reasons,source_report,already_blacklisted,blocked_this_run,skip_reason\n"
        "3.3.3.3,持续监控,80,60,20,8,扫描,中,侦察,证据,url,0,观察,report.xlsx,false,false,\n",
        encoding="utf-8",
    )

    selection = select_block_targets(normalized, whitelist_file=None, max_targets=200, apply=True)

    assert selection.targets == []
    assert selection.apply_refusal == "no_targets"
    apply_result = write_apply_result(selection, tmp_path / "runs" / "20260707_083000" / "block", executed=False)
    payload = json.loads(apply_result.read_text(encoding="utf-8"))
    assert payload["status"] == "refused"
    assert payload["reason"] == "no_targets"


def test_apply_refuses_when_recommendations_are_outside_current_run(tmp_path):
    run_dir = tmp_path / "runs" / "20260707_083000"
    normalized = tmp_path / "manual" / "blocklist_recommendations.normalized.csv"
    normalized.parent.mkdir(parents=True)
    normalized.write_text(
        "ip,recommendation,final_score,base_score,history_score,attack_count,threat_types,severity,attack_chain,evidence_summary,sample_urls,historical_occurrences,recommendation_reasons,source_report,already_blacklisted,blocked_this_run,skip_reason\n"
        "1.1.1.1,立即封禁,90,70,20,10,扫描,高,侦察,证据,url,1,高频,report.xlsx,false,false,\n",
        encoding="utf-8",
    )

    with pytest.raises(ApplyGuardError, match="current run"):
        select_block_targets(normalized, whitelist_file=None, max_targets=200, apply=True, run_dir=run_dir, explicit_recommendations=False)


def test_apply_external_recommendations_require_manual_override_reason(tmp_path):
    run_dir = tmp_path / "runs" / "20260707_083000"
    normalized = tmp_path / "manual" / "blocklist_recommendations.normalized.csv"
    normalized.parent.mkdir(parents=True)
    normalized.write_text(
        "ip,recommendation,final_score,base_score,history_score,attack_count,threat_types,severity,attack_chain,evidence_summary,sample_urls,historical_occurrences,recommendation_reasons,source_report,already_blacklisted,blocked_this_run,skip_reason\n"
        "1.1.1.1,立即封禁,90,70,20,10,扫描,高,侦察,证据,url,1,高频,report.xlsx,false,false,\n",
        encoding="utf-8",
    )

    with pytest.raises(ApplyGuardError, match="manual override"):
        select_block_targets(
            normalized,
            whitelist_file=None,
            max_targets=200,
            apply=True,
            run_dir=run_dir,
            explicit_recommendations=True,
        )


def test_apply_external_recommendations_accept_manual_override_reason(tmp_path):
    run_dir = tmp_path / "runs" / "20260707_083000"
    normalized = tmp_path / "manual" / "blocklist_recommendations.normalized.csv"
    normalized.parent.mkdir(parents=True)
    normalized.write_text(
        "ip,recommendation,final_score,base_score,history_score,attack_count,threat_types,severity,attack_chain,evidence_summary,sample_urls,historical_occurrences,recommendation_reasons,source_report,already_blacklisted,blocked_this_run,skip_reason\n"
        "1.1.1.1,立即封禁,90,70,20,10,扫描,高,侦察,证据,url,1,高频,report.xlsx,false,false,\n",
        encoding="utf-8",
    )

    selection = select_block_targets(
        normalized,
        whitelist_file=None,
        max_targets=200,
        apply=True,
        run_dir=run_dir,
        explicit_recommendations=True,
        manual_override_reason="incident INC-20260707 operator approved external CSV",
    )

    assert selection.targets == ["1.1.1.1"]


def test_block_apply_requires_completed_same_run_prerequisites_and_live_health(tmp_path, monkeypatch):
    sip = tmp_path / "sip.json"
    firewall = tmp_path / "firewall.json"
    sip.write_text(json.dumps({"base_url": "https://sip.local", "cookie": "sip-cookie", "xid": "xid"}), encoding="utf-8")
    firewall.write_text(json.dumps({"base_url": "https://fw.local", "cookie": "fw-cookie"}), encoding="utf-8")
    config = PipelineConfig.from_dict(
        {"paths": {"sip_session_file": str(sip), "firewall_session_file": str(firewall)}, "blocking": {"max_targets_per_run": 200}},
        root_dir=tmp_path,
    )
    artifacts = ArtifactStore(tmp_path / "runs", tmp_path / "state").create_run("20260707_083000")
    normalized = artifacts.analysis_dir / "blocklist_recommendations.normalized.csv"
    normalized.write_text(
        "ip,recommendation,final_score,base_score,history_score,attack_count,threat_types,severity,attack_chain,evidence_summary,sample_urls,historical_occurrences,recommendation_reasons,source_report,already_blacklisted,blocked_this_run,skip_reason\n"
        "1.1.1.1,立即封禁,90,70,20,10,扫描,高,侦察,证据,url,1,高频,report.xlsx,false,false,\n",
        encoding="utf-8",
    )
    manifest = RunManifest(artifacts.run_dir, artifacts.run_id, {})
    runner = PipelineRunner(config, artifacts, manifest, EventLogger(artifacts.run_dir, artifacts.run_id))
    monkeypatch.setattr("pipeline.run_pipeline.check_sip_session_health", lambda path: {"healthy": True, "need_login": False})
    monkeypatch.setattr("pipeline.run_pipeline.check_firewall_session_health", lambda path: {"healthy": True, "login_page": False})

    with pytest.raises(ApplyGuardError, match="export-logs"):
        runner.block(normalized, apply=True)

    manifest.finish_stage("export-logs", "completed", details={"xlsx": str(artifacts.exports_dir / "logs.xlsx")})
    manifest.finish_stage("export-firewall-blacklist", "completed", details={"blacklist": str(artifacts.blacklist_dir / "sangfor_firewall_blacklists.csv")})
    manifest.finish_stage("analyze", "completed", details={"normalized": str(normalized)})
    calls = []
    monkeypatch.setattr("pipeline.run_pipeline.run_subprocess", lambda command, **kwargs: calls.append(command) or type("R", (), {"returncode": 0, "stdout": "", "stderr": "", "args": command})())

    runner.block(normalized, apply=True)

    assert calls


def test_daily_report_contains_blocked_skipped_evidence_and_no_secrets(tmp_path):
    run_dir = tmp_path / "runs" / "20260707_083000"
    normalized = run_dir / "analysis" / "blocklist_recommendations.normalized.csv"
    normalized.parent.mkdir(parents=True)
    normalized.write_text(
        "ip,recommendation,final_score,base_score,history_score,attack_count,threat_types,severity,attack_chain,evidence_summary,sample_urls,historical_occurrences,recommendation_reasons,source_report,already_blacklisted,blocked_this_run,skip_reason\n"
        "1.1.1.1,立即封禁,90,70,20,10,SQL注入,高,侦察>利用,Cookie: SESSID=secret-cookie,https://example.test/path?token=secret-token,3,高频攻击,report.xlsx,false,true,\n"
        "2.2.2.2,建议封禁,60,45,15,6,扫描,中,侦察,证据,url,0,命中规则,report.xlsx,false,false,whitelisted\n",
        encoding="utf-8",
    )
    manifest = {
        "run_id": "20260707_083000",
        "started_at": "2026-07-07T00:30:00+00:00",
        "ended_at": "2026-07-07T00:31:00+00:00",
        "stages": {"check-sessions": {"status": "completed"}},
        "outputs": {"exported_xlsx": "report.xlsx", "firewall_blacklist": "blacklist.csv"},
        "target_count": 1,
        "apply": True,
    }

    md_path, json_path = write_daily_report(run_dir, manifest, normalized, log_window=("2026-07-06 00:00:00", "2026-07-06 23:59:59"))

    markdown = md_path.read_text(encoding="utf-8")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert "1.1.1.1" in markdown
    assert "2.2.2.2" in markdown
    assert "whitelisted" in markdown
    assert payload["blocked_ips"][0]["ip"] == "1.1.1.1"
    assert payload["skipped_ips"][0]["skip_reason"] == "whitelisted"
    combined = markdown + json.dumps(payload, ensure_ascii=False)
    assert "secret-cookie" not in combined
    assert "secret-token" not in combined
    assert "[REDACTED]" in combined
