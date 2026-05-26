from claude_reposec.models import Finding, ScanResult


def test_finding_to_dict_round_trips():
    f = Finding(
        category="secret",
        file="app.py",
        line=42,
        pattern="aws_access_key",
        match_preview="AKIA***",
        commit=None,
        severity_hint="critical",
    )
    d = f.to_dict()
    assert d["category"] == "secret"
    assert d["file"] == "app.py"
    assert d["line"] == 42
    assert d["pattern"] == "aws_access_key"
    assert d["match_preview"] == "AKIA***"
    assert d["commit"] is None
    assert d["severity_hint"] == "critical"
    assert d["context"] == {}


def test_scan_result_findings_by_category():
    findings = [
        Finding("secret", "a.py", 1, "p", "x", None, "critical"),
        Finding("pii", "b.py", 2, "q", "y", None, "info"),
        Finding("secret", "c.py", 3, "r", "z", None, "high"),
    ]
    result = ScanResult(
        repo_path="/tmp/repo",
        repo_name="repo",
        commit_count=10,
        languages=["Python"],
        findings=findings,
        scan_duration_ms=100,
        scanner_version="0.1.0",
    )
    by_cat = result.findings_by_category()
    assert len(by_cat["secret"]) == 2
    assert len(by_cat["pii"]) == 1
    assert len(by_cat["git_history"]) == 0
