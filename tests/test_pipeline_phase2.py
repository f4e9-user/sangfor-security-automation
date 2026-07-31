import csv
import json
import sys
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
    analyze_command,
    normalize_recommendations,
    select_block_targets,
    write_apply_result,
)
from pipeline.reports import write_daily_report


SECRET_TEXT = "Cookie: SESSID=abc; Authorization: Bearer hidden; xid=secret-xid; _cftoken=csrf-secret"


def read_csv(path: Path):
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


class _DummyPaths:
    def __init__(self, root: Path):
        self.runs_dir = root / "runs"
        self.state_dir = root / "state"


class _DummyConfig:
    def __init__(self, root: Path):
        self.paths = _DummyPaths(root)


def test_redaction_removes_headers_json_fields_and_cli_values():
    payload = (
        "Cookie: SESSID=abc; Set-Cookie: token=def\n"
        "Authorization: Bearer bearer-secret\n"
        '{"cookie": "secret-cookie", "xid": "secret-xid", "csrf": {"_cftoken": "csrf-secret"}, "api_key": "key", "base_url": "https://sip.local"}\n'
        "cmd --cookie raw-cookie --xid raw-xid --csrf-token raw-csrf --password pass123 --base-url https://10.0.0.9 --host 192.0.2.117 token=kv-token "
        "https://firewall.local/framework.php http://10.0.0.8:8080"
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
    assert "bearer-secret" not in redacted
    assert "sip.local" not in redacted
    assert "10.0.0.9" not in redacted
    assert "192.0.2.117" not in redacted
    assert "firewall.local" not in redacted
    assert "10.0.0.8" not in redacted
    assert redacted.count("[REDACTED]") >= 10


def test_redact_secrets_keep_urls_shows_device_url_but_hides_credentials():
    payload = (
        "Page.goto: net::ERR_EMPTY_RESPONSE at https://192.0.2.118/ui/\n"
        'Cookie: SESSID=secret-cookie\n'
        '{"base_url": "https://192.0.2.118", "cookie": "raw-cookie"}\n'
        "--base-url https://192.0.2.118 --password pass123 token=kv-token\n"
    )
    redacted = redact_secrets(payload, keep_urls=True)
    # device URL/IP/base_url stay visible so the error is diagnosable
    assert "https://192.0.2.118" in redacted
    assert "192.0.2.118" in redacted
    assert "/ui/" in redacted
    assert "--base-url https://192.0.2.118" in redacted
    # credentials are still hidden
    assert "secret-cookie" not in redacted
    assert "raw-cookie" not in redacted
    assert "pass123" not in redacted
    assert "kv-token" not in redacted
    assert "[REDACTED]" in redacted
    # strict mode (default) still hides the device URL
    assert "192.0.2.118" not in redact_secrets(payload)


def test_run_subprocess_keeps_urls_in_stderr_log(tmp_path):
    from pipeline.commands import run_subprocess

    stderr_path = tmp_path / "login-sip.stderr.log"
    result = run_subprocess(
        [
            sys.executable,
            "-c",
            "import sys; sys.stderr.write('net::ERR_EMPTY_RESPONSE at https://192.0.2.118/ui/\\nCookie: SESSID=secret\\n'); sys.exit(1)",
        ],
        stderr_path=stderr_path,
    )

    text = stderr_path.read_text(encoding="utf-8")
    assert "https://192.0.2.118/ui/" in text
    assert "SESSID=secret" not in text
    # the returned value also keeps the URL (callers re-redact strictly when storing)
    assert "192.0.2.118" in result.stderr
    assert result.returncode == 1


def test_pipeline_config_loads_target_base_urls(tmp_path):
    config_path = tmp_path / "pipeline.yaml"
    config_path.write_text(
        "sip:\n"
        "  base_url: https://sip.local\n"
        "firewall:\n"
        "  base_url: https://fw.local\n",
        encoding="utf-8",
    )

    config = PipelineConfig.load(config_path, root_dir=tmp_path)

    assert config.sip_base_url == "https://sip.local"
    assert config.firewall_base_url == "https://fw.local"


def test_pipeline_config_prefers_ignored_local_config_by_default(tmp_path):
    config_dir = tmp_path / "config"
    secrets_dir = tmp_path / "secrets"
    config_dir.mkdir()
    secrets_dir.mkdir()
    (config_dir / "pipeline.yaml").write_text(
        "sip:\n"
        "  base_url: https://sip.local\n"
        "firewall:\n"
        "  base_url: https://firewall.local\n",
        encoding="utf-8",
    )
    (secrets_dir / "pipeline.local.yaml").write_text(
        "sip:\n"
        "  base_url: https://private-sip.local\n"
        "firewall:\n"
        "  base_url: https://private-fw.local\n",
        encoding="utf-8",
    )

    config = PipelineConfig.load(root_dir=tmp_path)

    assert config.sip_base_url == "https://private-sip.local"
    assert config.firewall_base_url == "https://private-fw.local"


def test_login_commands_pass_configured_base_urls(tmp_path, monkeypatch):
    config = PipelineConfig.from_dict(
        {
            "sip": {"base_url": "https://sip.local"},
            "firewall": {"base_url": "https://fw.local"},
        },
        root_dir=tmp_path,
    )
    store = ArtifactStore(tmp_path / "runs", tmp_path / "state")
    artifacts = store.create_run("20260707_130000")
    manifest = RunManifest(artifacts.run_dir, "20260707_130000", {})
    events = EventLogger(artifacts.run_dir, "20260707_130000")
    commands = []

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run_subprocess(command, **kwargs):
        commands.append(command)
        return Result()

    monkeypatch.setattr("pipeline.run_pipeline.run_subprocess", fake_run_subprocess)

    PipelineRunner(config, artifacts, manifest, events).login(target="all", headless=True)

    assert commands[0][commands[0].index("--base-url") + 1] == "https://sip.local"
    assert commands[1][commands[1].index("--base-url") + 1] == "https://fw.local"


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
        "IP,建议,评分,final_score,base_score,history_score,攻击次数,威胁类型,主要威胁,最高严重等级,攻击链,Payload风险,证据摘要,样本描述,样本URL,历史出现次数,推荐理由,already_blacklisted\n"
        "1.1.1.1,立即封禁,88,91,70,21,42,SQL注入|扫描,信息泄露|网站扫描,高,侦察>利用,源码/备份文件探测,证据,检测到网站攻击！攻击类型：信息泄漏攻击,https://example.test/a,3,高频攻击|历史复现,false\n",
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
    assert rows[0]["threat_types"] == "信息泄露|网站扫描"
    assert "检测到网站攻击" in rows[0]["evidence_summary"]
    assert "源码/备份文件探测" in rows[0]["evidence_summary"]
    assert rows[0]["sample_urls"] == "https://example.test/a"
    assert rows[0]["blocked_this_run"] == "false"
    assert rows[0]["skip_reason"] == ""


def test_prepare_analysis_input_merges_all_manifest_segments(tmp_path):
    import pandas as pd

    from pipeline.commands import prepare_analysis_input

    exports = tmp_path / "exports"
    exports.mkdir()
    columns = ["序号", "时间", "攻击类型", "源IP"]
    first = exports / "sangfor-sip-report-KsearchLog-2026071701.xlsx"
    second = exports / "sangfor-sip-report-KsearchLog-2026071702.xlsx"
    pd.DataFrame([[1, "2026-07-16 10:00:00", "扫描", "1.1.1.1"], [2, "2026-07-16 10:01:00", "注入", "2.2.2.2"]], columns=columns).to_excel(first, index=False, startrow=7)
    pd.DataFrame([[3, "2026-07-17 10:00:00", "扫描", "3.3.3.3"]], columns=columns).to_excel(second, index=False, startrow=7)
    (exports / "manifest-20260717.json").write_text(
        json.dumps({
            "total_count": 3,
            "segments": [
                {"file_name": first.name, "count": 2},
                {"file_name": second.name, "count": 1},
            ],
        }),
        encoding="utf-8",
    )

    merged = prepare_analysis_input(exports)

    assert merged.name == "sangfor-sip-report-KsearchLog-2026071799.xlsx"
    rows = pd.read_excel(merged, engine="openpyxl", skiprows=7)
    assert len(rows) == 3
    assert rows["源IP"].tolist() == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    assert list(rows.columns) == columns


def test_prepare_analysis_input_accepts_count_drift_below_export_limit(tmp_path):
    import pandas as pd

    from pipeline.commands import prepare_analysis_input

    exports = tmp_path / "exports"
    exports.mkdir()
    columns = ["序号", "源IP"]
    first = exports / "sangfor-sip-report-KsearchLog-2026071701.xlsx"
    second = exports / "sangfor-sip-report-KsearchLog-2026071702.xlsx"
    pd.DataFrame([[index, f"192.0.2.{index}"] for index in range(1, 10)], columns=columns).to_excel(first, index=False, startrow=7)
    pd.DataFrame([[10, "192.0.2.10"], [11, "192.0.2.11"]], columns=columns).to_excel(second, index=False, startrow=7)
    (exports / "manifest-20260717.json").write_text(
        json.dumps({
            "limit": 10,
            "split_limit": 8,
            "total_count": 10,
            "segment_total_count": 10,
            "segments": [
                {"file_name": first.name, "count": 8},
                {"file_name": second.name, "count": 2},
            ],
        }),
        encoding="utf-8",
    )

    merged = prepare_analysis_input(exports)

    rows = pd.read_excel(merged, engine="openpyxl", skiprows=7)
    assert len(rows) == 11


def test_prepare_analysis_input_rejects_segment_at_export_limit(tmp_path):
    import pandas as pd
    import pytest

    from pipeline.commands import prepare_analysis_input

    exports = tmp_path / "exports"
    exports.mkdir()
    columns = ["序号", "源IP"]
    first = exports / "sangfor-sip-report-KsearchLog-2026071701.xlsx"
    second = exports / "sangfor-sip-report-KsearchLog-2026071702.xlsx"
    pd.DataFrame([[index, f"192.0.2.{index}"] for index in range(1, 11)], columns=columns).to_excel(first, index=False, startrow=7)
    pd.DataFrame([[11, "192.0.2.11"]], columns=columns).to_excel(second, index=False, startrow=7)
    (exports / "manifest-20260717.json").write_text(
        json.dumps({
            "limit": 10,
            "split_limit": 8,
            "total_count": 9,
            "segment_total_count": 9,
            "segments": [
                {"file_name": first.name, "count": 8},
                {"file_name": second.name, "count": 1},
            ],
        }),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="reached export limit"):
        prepare_analysis_input(exports)


def test_prepare_analysis_input_reuses_single_manifest_segment(tmp_path):
    from pipeline.commands import prepare_analysis_input

    exports = tmp_path / "exports"
    exports.mkdir()
    source = exports / "sangfor-sip-report-KsearchLog-2026071701.xlsx"
    source.write_bytes(b"xlsx-placeholder")
    (exports / "manifest-20260717.json").write_text(
        json.dumps({"total_count": 1, "segments": [{"file_name": source.name, "count": 1}]}),
        encoding="utf-8",
    )

    assert prepare_analysis_input(exports) == source


def test_analyze_command_can_disable_or_enable_history_persistence(tmp_path):
    whitelist = tmp_path / "ip_whitelist.txt"
    command, cwd = analyze_command(
        tmp_path,
        tmp_path / "logs.xlsx",
        tmp_path / "blacklist.csv",
        tmp_path / "attackers.db",
        whitelist,
        tmp_path / "analysis",
        persist_history=False,
    )

    assert cwd == tmp_path / "analyzer" / "SXF_extract_attacker"
    assert "--blocklist" in command
    assert "--no-db" in command
    # whitelist_file is now actually forwarded to the analyzer
    assert "--whitelist-file" in command
    assert command[command.index("--whitelist-file") + 1] == str(whitelist)
    # stats_out omitted when not requested
    assert "--stats-out" not in command

    stats_path = tmp_path / "analysis" / "stats.json"
    apply_command, _ = analyze_command(
        tmp_path,
        tmp_path / "logs.xlsx",
        tmp_path / "blacklist.csv",
        tmp_path / "attackers.db",
        whitelist,
        tmp_path / "analysis",
        persist_history=True,
        stats_out=stats_path,
    )
    assert "--no-db" not in apply_command
    assert apply_command[apply_command.index("--stats-out") + 1] == str(stats_path)


def test_load_whitelist_parses_ip_reason_format(tmp_path):
    from pipeline.commands import _load_whitelist

    wl = tmp_path / "ip_whitelist.txt"
    wl.write_text(
        "# comment line\n"
        "58.248.69.44,出口IP\n"
        "183.129.153.150,百度爬虫，良性流量\n"
        "1.2.3.4\n",
        encoding="utf-8",
    )
    entries = _load_whitelist(wl)
    assert entries == {"58.248.69.44", "183.129.153.150", "1.2.3.4"}
    # reasons must not leak into the IP set
    assert all("," not in ip for ip in entries)


def test_write_daily_report_includes_stats_dimensions(tmp_path):
    run_dir = tmp_path / "runs" / "20260710_172704"
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "analysis" / "blocklist_recommendations.normalized.csv").write_text(
        "ip,recommendation,final_score,base_score,history_score,attack_count,threat_types,severity,attack_chain,evidence_summary,sample_urls,historical_occurrences,recommendation_reasons,source_report,already_blacklisted,blocked_this_run,skip_reason\n"
        "9.9.9.9,建议封禁,64,50,14,70,信息泄露,高危,信息窃取,证据,url,0,理由,report.xlsx,false,true,\n",
        encoding="utf-8",
    )
    (run_dir / "analysis" / "stats.json").write_text(
        json.dumps({
            "total_records": 6300,
            "excluded_count": 1306,
            "threat_type_top10": [{"type": "爬虫工具", "count": 1892}, {"type": "信息泄露", "count": 702}],
            "source_ip_top10": [{"ip": "159.75.172.163", "count": 233}, {"ip": "34.96.63.75", "count": 208}],
            "attack_results": {"success_rate": 0.0, "blocked_rate": 0.0, "distribution": {"攻击失败": 6300}},
            "defense_posture": {"waf_block_rate": 0.0, "whitelist_hit_rate": 0.0, "critical_high_ratio": 0.302},
            "temporal_patterns": {"span_hours": 54.9, "peak_hour": 13, "peak_count": 846, "attacks_per_hour": 114.8},
            "attack_chains": [{"ip": "31.132.90.3", "total_attacks": 314, "unique_threat_types": 7, "attack_stages": ["漏洞利用", "WebShell投递"]}],
        }),
        encoding="utf-8",
    )
    manifest = {
        "run_id": "20260710_172704",
        "stages": {"check-sessions": {"status": "completed"}},
        "outputs": {"exported_xlsx": "report.xlsx", "firewall_blacklist": "blacklist.csv"},
    }

    md_path, json_path = write_daily_report(run_dir, manifest, run_dir / "analysis" / "blocklist_recommendations.normalized.csv", log_window=("2026-07-08 10:30:00", "2026-07-10 17:30:00"))
    markdown = md_path.read_text(encoding="utf-8")
    payload = json.loads(json_path.read_text(encoding="utf-8"))

    assert "Analyzed logs: 6300" in markdown
    assert "Excluded logs (whitelist/blacklist): 1306" in markdown
    assert payload["analyzed_log_count"] == 6300
    assert payload["excluded_log_count"] == 1306
    assert "## Top threat types" in markdown and "爬虫工具: 1892" in markdown
    assert "## Top source IPs" in markdown and "159.75.172.163: 233" in markdown
    assert "## Defense posture" in markdown and "Attack success rate: 0.0%" in markdown
    assert "## Attack chains" in markdown and "31.132.90.3" in markdown and "漏洞利用 → WebShell投递" in markdown


def test_print_console_report_includes_stats_dimensions(tmp_path):
    import io

    from pipeline.reports import print_console_report

    run_dir = tmp_path / "runs" / "20260710_172704"
    (run_dir / "reports").mkdir(parents=True)
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "analysis" / "blocklist_recommendations.normalized.csv").write_text(
        "ip,recommendation,final_score,base_score,history_score,attack_count,threat_types,severity,attack_chain,evidence_summary,sample_urls,historical_occurrences,recommendation_reasons,source_report,already_blacklisted,blocked_this_run,skip_reason\n"
        "9.9.9.9,建议封禁,64,50,14,70,信息泄露,高危,信息窃取,证据,url,0,理由,report.xlsx,false,true,\n",
        encoding="utf-8",
    )
    (run_dir / "analysis" / "stats.json").write_text(
        json.dumps({
            "total_records": 6300,
            "excluded_count": 1306,
            "threat_type_top10": [{"type": "爬虫工具", "count": 1892}],
            "source_ip_top10": [{"ip": "159.75.172.163", "count": 233}],
            "attack_results": {"success_rate": 0.0, "blocked_rate": 0.0},
            "defense_posture": {"waf_block_rate": 0.0, "critical_high_ratio": 0.302},
            "temporal_patterns": {"peak_hour": 13, "peak_count": 846, "attacks_per_hour": 114.8},
            "attack_chains": [{"ip": "31.132.90.3", "total_attacks": 314, "attack_stages": ["漏洞利用", "WebShell投递"]}],
        }),
        encoding="utf-8",
    )
    buf = io.StringIO()
    print_console_report(run_dir, stream=buf)
    out = buf.getvalue()

    assert "分析日志: 6300 条（排除白/黑名单 1306 条）" in out
    assert "威胁 Top: 爬虫工具 1892" in out
    assert "源IP Top: 159.75.172.163 233" in out
    assert "防御态势:" in out and "高危占比 30.2%" in out
    assert "攻击链: 31.132.90.3 (314次): 漏洞利用→WebShell投递" in out


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
    manifest = RunManifest(run_dir, "20260707_130000", {"session": SECRET_TEXT, "base_url": "https://sip.local"})
    manifest.start_stage("check-sessions", {"message": SECRET_TEXT, "base_url": "https://firewall.local"})
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
    assert "sip.local" not in combined
    assert "firewall.local" not in combined
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


def test_login_command_uses_configured_project_session_paths(tmp_path, monkeypatch):
    config_path = tmp_path / "pipeline.yaml"
    credentials_file = tmp_path / "login.json.gpg"
    sip_session = tmp_path / "secrets" / "sip_session.json"
    firewall_session = tmp_path / "secrets" / "firewall_session.json"
    config_path.write_text(
        "paths:\n"
        f"  sip_session_file: {sip_session}\n"
        f"  firewall_session_file: {firewall_session}\n"
        f"  runs_dir: {tmp_path / 'runs'}\n"
        f"  state_dir: {tmp_path / 'state'}\n",
        encoding="utf-8",
    )
    calls = []

    def fake_run_subprocess(args, **kwargs):
        calls.append(args)
        from pipeline.commands import CommandResult

        return CommandResult(args=args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("pipeline.run_pipeline.run_subprocess", fake_run_subprocess)

    exit_code = run_command([
        "--config",
        str(config_path),
        "login",
        "--credentials-file",
        str(credentials_file),
        "--captcha-provider",
        "chaojiying",
        "--chaojiying-codetype",
        "1902",
        "--browser-executable",
        "/tmp/chrome",
    ])

    assert exit_code == 0
    assert len(calls) == 2
    sip_index = calls[0].index("--session-file")
    firewall_index = calls[1].index("--session-file")
    assert calls[0][sip_index + 1] == str(sip_session)
    assert calls[1][firewall_index + 1] == str(firewall_session)
    for call in calls:
        credentials_index = call.index("--credentials-file")
        provider_index = call.index("--captcha-provider")
        codetype_index = call.index("--chaojiying-codetype")
        browser_index = call.index("--browser-executable")
        assert call[credentials_index + 1] == str(credentials_file)
        assert call[provider_index + 1] == "chaojiying"
        assert call[codetype_index + 1] == "1902"
        assert call[browser_index + 1] == "/tmp/chrome"
    assert "--no-keepalive" in calls[1]


def test_run_command_prints_console_progress_summary_and_log_paths(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "pipeline.yaml"
    config_path.write_text(
        "paths:\n"
        f"  runs_dir: {tmp_path / 'runs'}\n"
        f"  state_dir: {tmp_path / 'state'}\n",
        encoding="utf-8",
    )

    def fake_check_sessions(self):
        self.manifest.start_stage("check-sessions")
        self.events.emit("check-sessions", "INFO", "stage_started", "checking session files")
        self.events.emit("check-sessions", "DEBUG", "health_payload", "debug health payload", {"sip": "ok"})
        self.manifest.finish_stage("check-sessions", "completed")
        self.events.emit("check-sessions", "INFO", "stage_completed", "session health checks passed")

    monkeypatch.setattr(PipelineRunner, "check_sessions", fake_check_sessions)

    exit_code = run_command(["--config", str(config_path), "--run-id", "20260707_083000", "check-sessions"])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Run ID: 20260707_083000" in out
    assert f"Run dir: {tmp_path / 'runs' / '20260707_083000'}" in out
    assert "[INFO] check-sessions stage_started: checking session files" in out
    assert "debug health payload" not in out
    assert "Status: completed" in out
    assert "Events: " in out
    assert "events.jsonl" in out
    assert "Pipeline log: " in out
    assert "pipeline.log" in out


def test_run_command_debug_prints_debug_events(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "pipeline.yaml"
    config_path.write_text(
        "paths:\n"
        f"  runs_dir: {tmp_path / 'runs'}\n"
        f"  state_dir: {tmp_path / 'state'}\n",
        encoding="utf-8",
    )

    def fake_check_sessions(self):
        self.events.emit("check-sessions", "DEBUG", "health_payload", "debug health payload", {"sip": "ok"})

    monkeypatch.setattr(PipelineRunner, "check_sessions", fake_check_sessions)

    exit_code = run_command(["--config", str(config_path), "--run-id", "20260707_083000", "--debug", "check-sessions"])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "[DEBUG] check-sessions health_payload: debug health payload" in out
    assert '{"sip": "ok"}' in out


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

    def fake_full(start, end, favorite_name, export_date, *, apply=False, report=False):
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
    monkeypatch.setattr(runner, "analyze", lambda xlsx, blacklist, *, persist_history=False: calls.append(("analyze", persist_history)) or recommendations)
    monkeypatch.setattr(runner, "block", lambda recs, *, apply=False, manual_override_reason=None: calls.append(("block", apply)) or ["1.1.1.1"])
    monkeypatch.setattr("pipeline.run_pipeline.write_daily_report", lambda *args, **kwargs: (tmp_path / "report.md", tmp_path / "report.json"))

    runner.full("2026-07-06 00:00:00", "2026-07-06 23:59:59", None, None, apply=True)

    assert calls == [
        ("check_sessions", None),
        ("export_logs", None),
        ("export_firewall_blacklist", None),
        ("analyze", True),
        ("block", False),
        ("block", True),
    ]


def test_full_dry_run_does_not_persist_analysis_history(tmp_path, monkeypatch):
    config = PipelineConfig.from_dict({}, root_dir=tmp_path)
    artifacts = ArtifactStore(tmp_path / "runs", tmp_path / "state").create_run("20260707_083000")
    runner = PipelineRunner(config, artifacts, RunManifest(artifacts.run_dir, artifacts.run_id, {}), EventLogger(artifacts.run_dir, artifacts.run_id))
    recommendations = artifacts.analysis_dir / "blocklist_recommendations.normalized.csv"
    calls = []

    monkeypatch.setattr(runner, "check_sessions", lambda: None)
    monkeypatch.setattr(runner, "export_logs", lambda start, end, favorite_name, export_date: tmp_path / "logs.xlsx")
    monkeypatch.setattr(runner, "export_firewall_blacklist", lambda: tmp_path / "blacklist.csv")
    monkeypatch.setattr(runner, "analyze", lambda xlsx, blacklist, *, persist_history=False: calls.append(("analyze", persist_history)) or recommendations)
    monkeypatch.setattr(runner, "block", lambda recs, *, apply=False, manual_override_reason=None: calls.append(("block", apply)) or ["1.1.1.1"])
    monkeypatch.setattr("pipeline.run_pipeline.write_daily_report", lambda *args, **kwargs: (tmp_path / "report.md", tmp_path / "report.json"))

    runner.full("2026-07-06 00:00:00", "2026-07-06 23:59:59", None, None, apply=False)

    assert calls == [("analyze", False), ("block", False)]


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
        "outputs": {
            "exported_xlsx": "report.xlsx",
            "firewall_blacklist": "blacklist.csv",
            "exported_log_count": 6300,
        },
        "target_count": 1,
        "apply": True,
    }

    md_path, json_path = write_daily_report(run_dir, manifest, normalized, log_window=("2026-07-06 00:00:00", "2026-07-06 23:59:59"))

    markdown = md_path.read_text(encoding="utf-8")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert "1.1.1.1" in markdown
    assert "2.2.2.2" in markdown
    assert "whitelisted" in markdown
    assert "Analyzed logs: 6300" in markdown
    assert payload["analyzed_log_count"] == 6300
    assert payload["blocked_ips"][0]["ip"] == "1.1.1.1"
    assert payload["skipped_ips"][0]["skip_reason"] == "whitelisted"
    combined = markdown + json.dumps(payload, ensure_ascii=False)
    assert "secret-cookie" not in combined
    assert "secret-token" not in combined
    assert "[REDACTED]" in combined


def test_print_console_report_lists_recommendations_and_actual_blocks(tmp_path):
    import io

    from pipeline.reports import print_console_report

    run_dir = tmp_path / "runs" / "20260710_172704"
    (run_dir / "reports").mkdir(parents=True)
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "exports").mkdir(parents=True)
    normalized = run_dir / "analysis" / "blocklist_recommendations.normalized.csv"
    normalized.write_text(
        "ip,recommendation,final_score,base_score,history_score,attack_count,threat_types,severity,attack_chain,evidence_summary,sample_urls,historical_occurrences,recommendation_reasons,source_report,already_blacklisted,blocked_this_run,skip_reason\n"
        "9.9.9.9,建议封禁,64.3,50,14,70,WebShell上传|代码注入,高危,WebShell投递 → 漏洞利用,通用XSS攻击,url,0,累计 70 次攻击,report.xlsx,false,true,\n"
        "8.8.8.8,持续监控,40,30,10,4,扫描,高危,侦察,证据,url,0,观察中,report.xlsx,false,false,低分\n",
        encoding="utf-8",
    )
    (run_dir / "manifest.json").write_text(
        json.dumps({"run_id": "20260710_172704", "outputs": {"exported_log_count": 6300}}),
        encoding="utf-8",
    )
    (run_dir / "reports" / "daily_report.json").write_text(
        json.dumps(
            {
                "run_id": "20260710_172704",
                "log_window": {"start": "2026-07-08 10:30:00", "end": "2026-07-10 17:30:00"},
                "analyzed_log_count": 6300,
                "candidate_ip_count": 2,
                "recommended_count": 1,
                "blocked_count": 1,
                "skipped_count": 1,
                "blocked_ips": [
                    {
                        "ip": "9.9.9.9",
                        "recommendation": "建议封禁",
                        "final_score": "64.3",
                        "attack_count": "70",
                        "threat_types": "WebShell上传|代码注入",
                        "attack_chain": "WebShell投递 → 漏洞利用",
                        "evidence_summary": "通用XSS攻击",
                        "recommendation_reasons": "累计 70 次攻击",
                    }
                ],
                "recommended_ips": [
                    {
                        "ip": "9.9.9.9",
                        "recommendation": "建议封禁",
                        "final_score": "64.3",
                        "attack_count": "70",
                        "threat_types": "WebShell上传|代码注入",
                        "attack_chain": "WebShell投递 → 漏洞利用",
                        "evidence_summary": "通用XSS攻击",
                        "recommendation_reasons": "累计 70 次攻击",
                        "blocked_this_run": "true",
                    }
                ],
                "skipped_ips": [{"ip": "8.8.8.8", "skip_reason": "低分"}],
            }
        ),
        encoding="utf-8",
    )

    buf = io.StringIO()
    count = print_console_report(run_dir, stream=buf)
    out = buf.getvalue()

    assert count == 1
    assert "分析日志: 6300 条" in out
    assert "建议封禁: 1" in out
    assert "实际封禁: 1" in out
    assert "建议封禁 IP 证据链:" in out
    assert "执行状态: 本次已封禁" in out
    assert "9.9.9.9" in out
    assert "WebShell投递 → 漏洞利用" in out
    # skipped IP is intentionally not shown in the console evidence chain
    assert "8.8.8.8" not in out


def test_full_prints_console_report_by_default(tmp_path, monkeypatch):
    config = PipelineConfig.from_dict({}, root_dir=tmp_path)
    artifacts = ArtifactStore(tmp_path / "runs", tmp_path / "state").create_run("20260717_173927")
    runner = PipelineRunner(config, artifacts, RunManifest(artifacts.run_dir, artifacts.run_id, {}), EventLogger(artifacts.run_dir, artifacts.run_id))
    recommendations = artifacts.analysis_dir / "blocklist_recommendations.normalized.csv"
    printed = []

    monkeypatch.setattr(runner, "check_sessions", lambda: None)
    monkeypatch.setattr(runner, "export_logs", lambda *args: tmp_path / "logs.xlsx")
    monkeypatch.setattr(runner, "export_firewall_blacklist", lambda: tmp_path / "blacklist.csv")
    monkeypatch.setattr(runner, "analyze", lambda *args, **kwargs: recommendations)
    monkeypatch.setattr(runner, "block", lambda *args, **kwargs: ["9.9.9.9"])
    monkeypatch.setattr("pipeline.run_pipeline.write_daily_report", lambda *args, **kwargs: (tmp_path / "report.md", tmp_path / "report.json"))
    monkeypatch.setattr("pipeline.run_pipeline.print_console_report", lambda run_dir: printed.append(run_dir))

    runner.full("2026-07-10 17:30:00", "2026-07-17 17:30:00", None, None)

    assert printed == [artifacts.run_dir]


def test_print_console_report_backfills_count_from_export_manifest(tmp_path):
    import io

    from pipeline.reports import print_console_report

    run_dir = tmp_path / "runs" / "20260710_172704"
    (run_dir / "reports").mkdir(parents=True)
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "exports").mkdir(parents=True)
    # normalized CSV with one blocked row
    (run_dir / "analysis" / "blocklist_recommendations.normalized.csv").write_text(
        "ip,recommendation,final_score,base_score,history_score,attack_count,threat_types,severity,attack_chain,evidence_summary,sample_urls,historical_occurrences,recommendation_reasons,source_report,already_blacklisted,blocked_this_run,skip_reason\n"
        "9.9.9.9,建议封禁,64.3,50,14,70,WebShell上传,高危,漏洞利用,证据,url,0,理由,report.xlsx,false,true,\n",
        encoding="utf-8",
    )
    # stale daily_report.json predating analyzed_log_count
    (run_dir / "reports" / "daily_report.json").write_text(
        json.dumps({"run_id": "20260710_172704", "blocked_count": 1, "candidate_ip_count": 1, "blocked_ips": [{"ip": "9.9.9.9"}]}),
        encoding="utf-8",
    )
    # export manifest supplies the count
    (run_dir / "exports" / "manifest-20260708_103000-20260710_173000.json").write_text(
        json.dumps({"total_count": 6300}),
        encoding="utf-8",
    )

    buf = io.StringIO()
    print_console_report(run_dir, stream=buf)
    assert "分析日志: 6300 条" in buf.getvalue()


def test_report_subcommand_does_not_create_run_and_uses_latest(tmp_path, monkeypatch):
    from pipeline import run_pipeline as rp

    calls = {}
    monkeypatch.setattr(rp.PipelineConfig, "load", classmethod(lambda cls, *a, **k: _DummyConfig(tmp_path)))
    monkeypatch.setattr(rp, "print_console_report", lambda run_dir, *a, **k: calls.setdefault("run_dir", run_dir))

    (tmp_path / "runs" / "20260707_083000").mkdir(parents=True)

    rc = rp.run_command(["report"])

    assert rc == 0
    assert calls["run_dir"] == tmp_path / "runs" / "20260707_083000"
    # no new run directory should have been created by the read-only report command
    assert not (tmp_path / "state" / "latest.json").exists()
