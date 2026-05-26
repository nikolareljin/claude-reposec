import json
from pathlib import Path
from unittest.mock import patch
from claude_reposec.deps import scan_deps, _parse_requirements_txt, _parse_package_json


def test_parse_requirements_txt(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.28.0\nflask==2.3.0\n# comment\n-r other.txt\n"
    )
    packages = _parse_requirements_txt(tmp_path / "requirements.txt")
    assert ("PyPI", "requests", "2.28.0") in packages
    assert ("PyPI", "flask", "2.3.0") in packages
    assert len(packages) == 2


def test_parse_package_json(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"express": "^4.18.0"},
        "devDependencies": {"jest": "~29.0.0"},
    }))
    packages = _parse_package_json(tmp_path / "package.json")
    names = [(e, p) for e, p, v in packages]
    assert ("npm", "express") in names
    assert ("npm", "jest") in names


def test_scan_deps_no_manifest(tmp_path):
    findings = scan_deps(tmp_path)
    assert findings == []


def test_scan_deps_with_vuln(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.4.0\n")
    mock_result = [{
        "vulns": [{
            "id": "GHSA-test-1234-abcd",
            "summary": "Test vulnerability",
            "severity": [{"type": "CVSS_V3", "score": "8.1"}],
            "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.28.0"}]}]}],
        }]
    }]
    with patch("claude_reposec.deps._query_osv_batch", return_value=mock_result):
        findings = scan_deps(tmp_path)
    assert len(findings) == 1
    assert findings[0].pattern == "known_vulnerability"
    assert findings[0].context["vuln_id"] == "GHSA-test-1234-abcd"
    assert findings[0].severity_hint == "high"
    assert "2.28.0" in findings[0].context["fix_versions"]


def test_scan_deps_clean(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    with patch("claude_reposec.deps._query_osv_batch", return_value=[{"vulns": []}]):
        findings = scan_deps(tmp_path)
    assert findings == []
