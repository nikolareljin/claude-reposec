import subprocess
from pathlib import Path
from claude_reposec.git_history import scan_git_history


def _make_git_repo(path: Path) -> None:
    subprocess.run(["git", "init"], cwd=path, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, capture_output=True)


def test_detects_env_file_in_history(tmp_path):
    _make_git_repo(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("SECRET=abc123\n")
    subprocess.run(["git", "add", ".env"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "commit", "-m", "add env"], cwd=tmp_path, capture_output=True)
    env_file.unlink()
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "commit", "-m", "remove env"], cwd=tmp_path, capture_output=True)

    findings = scan_git_history(tmp_path)
    assert any(f.pattern == "env_file_committed" for f in findings)


def test_no_findings_on_clean_history(tmp_path):
    _make_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("# Hello\n")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, capture_output=True)

    findings = scan_git_history(tmp_path)
    assert all(f.pattern != "env_file_committed" for f in findings)
