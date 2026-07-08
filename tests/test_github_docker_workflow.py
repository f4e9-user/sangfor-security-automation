import yaml
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "docker-images.yml"
COMPOSE = ROOT / "docker-compose.yml"
DOCKERIGNORE = ROOT / ".dockerignore"


def test_docker_images_workflow_publishes_runtime_and_playwright_images():
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    workflow_jobs = data["jobs"]
    assert "build-and-push" in workflow_jobs
    strategy = workflow_jobs["build-and-push"]["strategy"]["matrix"]["image"]
    names = {entry["name"] for entry in strategy}
    dockerfiles = {entry["dockerfile"] for entry in strategy}
    suffixes = {entry["suffix"] for entry in strategy}
    assert names == {"runtime", "playwright"}
    assert dockerfiles == {"docker/Dockerfile", "docker/Dockerfile.playwright"}
    assert suffixes == {"", "-playwright"}
    permissions = data["permissions"]
    assert permissions["contents"] == "read"
    assert permissions["packages"] == "write"
    checkout = workflow_jobs["build-and-push"]["steps"][0]
    assert checkout["uses"] == "actions/checkout@v4"
    populate = workflow_jobs["build-and-push"]["steps"][1]
    assert populate["name"] == "Populate analyzer source"
    assert "https://github.com/atsud0/SXF_extract_attacker.git" in populate["run"]
    assert "--branch main" in populate["run"]
    assert "c5ae8879ac34c3b13e8a0c49d1ef5f7d3c95b0fc" in populate["run"]


def test_compose_uses_prebuilt_ghcr_images_for_all_services():
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = compose["services"]
    assert services["pipeline"]["image"] == "ghcr.io/f4e9-user/sangfor-security-automation:latest"
    assert services["scheduler"]["image"] == "ghcr.io/f4e9-user/sangfor-security-automation:latest"
    assert services["sip-keepalive"]["image"] == "ghcr.io/f4e9-user/sangfor-security-automation:playwright-latest"
    assert services["firewall-keepalive"]["image"] == "ghcr.io/f4e9-user/sangfor-security-automation:playwright-latest"


def test_dockerignore_excludes_sensitive_and_runtime_artifacts():
    entries = set(DOCKERIGNORE.read_text(encoding="utf-8").splitlines())
    assert "secrets/" in entries
    assert "runs/" in entries
    assert "state/" in entries
    assert ".venv/" in entries
