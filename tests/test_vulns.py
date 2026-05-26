from claude_reposec.vulns import scan_vulns


def test_detects_flask_default_secret(tmp_path):
    (tmp_path / "app.py").write_text('app.secret_key = "change-me"\n')
    findings = scan_vulns(tmp_path)
    assert any(f.pattern == "flask_default_secret" for f in findings)


def test_detects_debug_true(tmp_path):
    (tmp_path / "app.py").write_text('app.run(host="0.0.0.0", debug=True)\n')
    findings = scan_vulns(tmp_path)
    assert any(f.pattern == "hardcoded_debug_true" for f in findings)


def test_detects_subprocess_shell_true(tmp_path):
    (tmp_path / "runner.py").write_text(
        'import subprocess\nsubprocess.run(cmd, shell=True)\n'
    )
    findings = scan_vulns(tmp_path)
    assert any(f.pattern == "subprocess_shell_true" for f in findings)


def test_clean_file_no_findings(tmp_path):
    (tmp_path / "clean.py").write_text(
        'import os\n\ndef add(a, b):\n    return a + b\n'
    )
    findings = scan_vulns(tmp_path)
    assert findings == []


def test_skips_non_python_file(tmp_path):
    (tmp_path / "readme.md").write_text('app.secret_key = "change-me"\n')
    findings = scan_vulns(tmp_path)
    assert findings == []
