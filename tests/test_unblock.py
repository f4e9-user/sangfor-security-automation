import json
import sys
from pathlib import Path

import pytest

from pipeline.commands import (
    unblock_command,
    write_unblock_apply_result,
    write_unblock_artifacts,
)


def test_unblock_command_builds_firewall_cli_with_apply_flag(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    session = tmp_path / "firewall_session.json"
    targets = tmp_path / "targets.txt"
    command = unblock_command(root, session, targets, apply=False)
    assert command[:2] == [sys.executable, str(root / "firewall" / "sangfor_firewall_blocklist.py")]
    assert "--session-file" in command and str(session) in command
    assert "--file" in command and str(targets) in command
    assert "--unblock" in command
    assert "--execute" not in command

    command_apply = unblock_command(root, session, targets, apply=True)
    assert "--execute" in command_apply


def test_write_unblock_artifacts_and_apply_result(tmp_path):
    unblock_dir = tmp_path / "unblock"
    targets = ["87.236.176.112", "1.2.3.4"]

    targets_path, dry_run_path = write_unblock_artifacts(targets, unblock_dir, apply=False)
    assert targets_path.read_text(encoding="utf-8").splitlines() == targets
    dry_run = json.loads(dry_run_path.read_text(encoding="utf-8"))
    assert dry_run["target_count"] == 2
    assert dry_run["targets"] == targets
    assert dry_run["apply"] is False

    result_path = write_unblock_apply_result(targets, unblock_dir, executed=True)
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    assert payload["status"] == "executed"
    assert payload["target_count"] == 2
    assert payload["targets"] == targets


def test_write_unblock_artifacts_empty_targets(tmp_path):
    targets_path, dry_run_path = write_unblock_artifacts([], tmp_path / "u", apply=True)
    assert targets_path.read_text(encoding="utf-8") == ""
    assert json.loads(dry_run_path.read_text(encoding="utf-8"))["target_count"] == 0