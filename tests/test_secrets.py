from claude_reposec.secrets import scan_secrets


def test_detects_aws_access_key(tmp_path):
    (tmp_path / "config.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = scan_secrets(tmp_path)
    patterns = [f.pattern for f in findings]
    assert "aws_access_key" in patterns


def test_detects_github_token(tmp_path):
    (tmp_path / ".env.example").write_text("TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZabcde1234\n")
    findings = scan_secrets(tmp_path)
    assert any(f.pattern == "github_token_classic" for f in findings)


def test_detects_private_key_header(tmp_path):
    (tmp_path / "key.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK\n")
    findings = scan_secrets(tmp_path)
    assert any(f.pattern == "private_key_header" for f in findings)


def test_skips_git_dir(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = scan_secrets(tmp_path)
    assert all(not f.file.startswith(".git") for f in findings)


def test_match_preview_is_redacted(tmp_path):
    (tmp_path / "app.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = scan_secrets(tmp_path)
    for f in findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in f.match_preview


def test_detects_connection_string(tmp_path):
    (tmp_path / "db.py").write_text('DB = "postgres://admin:supersecret@localhost/mydb"\n')
    findings = scan_secrets(tmp_path)
    assert any(f.pattern == "connection_string" for f in findings)
