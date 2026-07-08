from pathlib import Path


def test_root_keeps_only_entrypoint_and_readme_as_regular_files():
    repo_root = Path(__file__).resolve().parents[1]
    visible_files = {
        path.name
        for path in repo_root.iterdir()
        if path.is_file() and not path.name.startswith(".")
    }

    assert visible_files == {
        "Dockerfile",
        "README.md",
        "docker-compose.yml",
        "extract_attacker.py",
        "requirements.txt",
    }


if __name__ == "__main__":
    test_root_keeps_only_entrypoint_and_readme_as_regular_files()
    print("plain python project layout test passed")
