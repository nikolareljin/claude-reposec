from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .models import Finding
from .secrets import SKIP_DIRS, _is_text_file

PII_PATTERNS: list[tuple[str, str, str]] = [
    ("email_address", r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "info"),
    ("us_phone",      r"\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "medium"),
    ("us_ssn",        r"\b\d{3}-\d{2}-\d{4}\b", "critical"),
    ("credit_card",   r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", "critical"),
]


def _luhn_valid(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    odd = digits[-1::-2]
    even_doubled = [d * 2 - 9 if d * 2 > 9 else d * 2 for d in digits[-2::-2]]
    return (sum(odd) + sum(even_doubled)) % 10 == 0


def _redact_pii(value: str, name: str) -> str:
    if name == "email_address" and "@" in value:
        local, domain = value.split("@", 1)
        return (local[:2] + "***@" + domain) if len(local) > 2 else "***@" + domain
    return value[:3] + "***"


def scan_pii(repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    compiled = [(name, re.compile(pat), sev) for name, pat, sev in PII_PATTERNS]

    for file_path in repo_root.rglob("*"):
        if not file_path.is_file():
            continue
        if any(part in SKIP_DIRS for part in file_path.relative_to(repo_root).parts):
            continue
        if not _is_text_file(file_path):
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel = str(file_path.relative_to(repo_root))
        for lineno, line in enumerate(content.splitlines(), 1):
            for name, pattern, severity in compiled:
                for m in pattern.finditer(line):
                    val = m.group(0)
                    if name == "credit_card" and not _luhn_valid(val):
                        continue
                    findings.append(Finding(
                        category="pii",
                        file=rel,
                        line=lineno,
                        pattern=name,
                        match_preview=_redact_pii(val, name),
                        commit=None,
                        severity_hint=severity,
                    ))

    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "log", "--all", "--format=%ae"],
            capture_output=True, text=True, timeout=30,
        )
        for email in set(result.stdout.strip().splitlines()):
            if email:
                findings.append(Finding(
                    category="pii",
                    file="git-history",
                    line=None,
                    pattern="git_author_email",
                    match_preview=_redact_pii(email, "email_address"),
                    commit=None,
                    severity_hint="info",
                    context={"note": "Email in public git history"},
                ))
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    return findings
