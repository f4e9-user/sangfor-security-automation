"""`--run-id` 续跑必须保留既有阶段记录（否则 apply 守卫必然失败）。

2026-09-11 实测：run 的 export-logs / export-firewall-blacklist / analyze 都 completed，
用 `--run-id <id> block --apply` 补 apply 时，RunManifest 重建了空 manifest，
stages 全丢 → 守卫报 "apply requires completed same-run export-logs"。
"""
from __future__ import annotations

from pathlib import Path

from pipeline.state import RunManifest


def test_new_run_starts_with_empty_stages(tmp_path: Path) -> None:
    manifest = RunManifest(tmp_path / "runs" / "20260101_000000", "20260101_000000", {"command": "full"})
    assert manifest.data["stages"] == {}
    assert manifest.data["status"] == "running"


def test_reusing_existing_run_keeps_completed_stages(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs" / "20260101_000000"
    first = RunManifest(run_dir, "20260101_000000", {"command": "full"})
    for stage in ("check-sessions", "export-firewall-blacklist", "export-logs", "analyze"):
        first.start_stage(stage)
        first.finish_stage(stage, "completed")
    first.data["apply"] = True
    first.data["target_count"] = 65
    first.write()

    resumed = RunManifest(run_dir, "20260101_000000", {"command": "block", "apply": True})

    assert set(resumed.data["stages"]) >= {"export-logs", "export-firewall-blacklist", "analyze"}
    for stage in ("export-logs", "export-firewall-blacklist", "analyze"):
        assert resumed.data["stages"][stage]["status"] == "completed"
    assert resumed.data["target_count"] == 65
    assert resumed.data["apply"] is True
    # 新一次调用自身的状态是干净的
    assert resumed.data["status"] == "running"
    assert resumed.data["ended_at"] is None
    assert resumed.data["error"] is None


def test_manifest_of_another_run_id_is_not_reused(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs" / "20260101_000000"
    first = RunManifest(run_dir, "20260101_000000", {"command": "full"})
    first.start_stage("export-logs")
    first.finish_stage("export-logs", "completed")
    first.write()

    other = RunManifest(run_dir, "20260101_000001", {"command": "full"})
    assert other.data["stages"] == {}


def test_corrupt_manifest_falls_back_to_empty(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs" / "20260101_000000"
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text("{not json", encoding="utf-8")
    manifest = RunManifest(run_dir, "20260101_000000", {"command": "full"})
    assert manifest.data["stages"] == {}
