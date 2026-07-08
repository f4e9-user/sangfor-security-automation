from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_docker_deployment_files_exist_and_use_cli_entrypoint():
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    requirements = (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8")

    assert "python:3.11-slim" in dockerfile
    assert 'ENTRYPOINT ["python", "extract_attacker.py"]' in dockerfile
    assert "./data:/app/data" in compose
    assert "./outputs:/app/outputs" in compose
    assert "pandas" in requirements
    assert "openpyxl" in requirements


def test_github_workflow_builds_docker_image():
    workflow = (REPO_ROOT / ".github" / "workflows" / "docker-build.yml").read_text(encoding="utf-8")

    assert "docker/build-push-action" in workflow
    assert "docker/setup-qemu-action" in workflow
    assert "docker/login-action" in workflow
    assert "ghcr.io" in workflow
    assert "packages: write" in workflow
    assert "linux/amd64,linux/arm64" in workflow
    assert "push: ${{ github.event_name != 'pull_request' }}" in workflow
    assert "Dockerfile" in workflow


if __name__ == "__main__":
    test_docker_deployment_files_exist_and_use_cli_entrypoint()
    test_github_workflow_builds_docker_image()
    print("plain python deployment file tests passed")
