from __future__ import annotations

import re
from pathlib import Path

from .models import Finding

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".tox", ".eggs"}
SKIP_EXTENSIONS = {".min.js", ".map", ".lock", ".png", ".jpg", ".jpeg", ".gif", ".ico",
                   ".pdf", ".zip", ".tar", ".gz", ".whl", ".pyc", ".pyo"}
MAX_FILE_SIZE = 1024 * 1024  # 1 MB

SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("aws_access_key",       r"AKIA[0-9A-Z]{16}",                                                                       "critical"),
    ("aws_secret_key",       r"(?i)aws_secret[_\-]?(?:access[_\-]?)?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})",          "critical"),
    ("github_token_classic", r"ghp_[a-zA-Z0-9]{35,}",                                                                    "critical"),
    ("github_token_server",  r"ghs_[a-zA-Z0-9]{35,}",                                                                    "critical"),
    ("github_token_oauth",   r"gho_[a-zA-Z0-9]{35,}",                                                                    "critical"),
    ("github_token_user",    r"ghu_[a-zA-Z0-9]{35,}",                                                                    "critical"),
    ("github_token_refresh", r"ghr_[a-zA-Z0-9]{35,}",                                                                    "high"),
    ("stripe_live_key",      r"sk_live_[a-zA-Z0-9]{24,}",                                                               "critical"),
    ("stripe_restricted",    r"rk_live_[a-zA-Z0-9]{24,}",                                                               "high"),
    ("private_key_header",   r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",                                 "critical"),
    ("slack_token",          r"xox[baprs]-[0-9A-Za-z\-]+",                                                              "high"),
    ("connection_string",    r"(?:mysql|postgres(?:ql)?|mongodb|redis|mssql)://[^:@\s]+:[^@\s]+@",                      "high"),
    ("basic_auth_url",       r"https?://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-!@#$%^&*]{4,}@[a-zA-Z0-9]",                     "high"),
    ("generic_password",     r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]",                             "medium"),
    ("generic_api_key",      r"(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]",                   "medium"),
    ("generic_secret",       r"(?i)(?:secret(?:[_\-]?key)?|secretkey)\s*[=:]\s*['\"][a-zA-Z0-9_\-!@#$%^&*]{8,}['\"]", "medium"),
]


def _redact(match: str) -> str:
    return match[:4] + "***" if len(match) > 4 else "***"


def _is_text_file(path: Path) -> bool:
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return False
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return False
        path.read_bytes()[:512].decode("utf-8")
        return True
    except (UnicodeDecodeError, OSError):
        return False


def scan_secrets(repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    compiled = [(name, re.compile(pat), sev) for name, pat, sev in SECRET_PATTERNS]

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
                m = pattern.search(line)
                if m:
                    findings.append(Finding(
                        category="secret",
                        file=rel,
                        line=lineno,
                        pattern=name,
                        match_preview=_redact(m.group(0)),
                        commit=None,
                        severity_hint=severity,
                    ))
    return findings
