from pathlib import Path
from claude_reposec.pii import scan_pii


def test_detects_email(tmp_path):
    (tmp_path / "config.py").write_text('ADMIN = "john.doe@example.com"\n')
    findings = scan_pii(tmp_path)
    assert any(f.pattern == "email_address" for f in findings)


def test_email_preview_is_redacted(tmp_path):
    (tmp_path / "config.py").write_text('ADMIN = "john.doe@example.com"\n')
    findings = scan_pii(tmp_path)
    email_findings = [f for f in findings if f.pattern == "email_address"]
    assert all("john.doe@example.com" not in f.match_preview for f in email_findings)


def test_detects_ssn(tmp_path):
    (tmp_path / "data.txt").write_text("SSN: 123-45-6789\n")
    findings = scan_pii(tmp_path)
    assert any(f.pattern == "us_ssn" for f in findings)


def test_detects_valid_credit_card(tmp_path):
    (tmp_path / "test.txt").write_text("card: 4532015112830366\n")
    findings = scan_pii(tmp_path)
    assert any(f.pattern == "credit_card" for f in findings)


def test_rejects_invalid_credit_card(tmp_path):
    (tmp_path / "test.txt").write_text("number: 4532015112830000\n")
    findings = scan_pii(tmp_path)
    assert not any(f.pattern == "credit_card" for f in findings)
