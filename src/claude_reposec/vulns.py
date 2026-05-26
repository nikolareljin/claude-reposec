from __future__ import annotations

import re
from pathlib import Path

from .models import Finding
from .secrets import SKIP_DIRS

VULN_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        "flask_default_secret",
        r"""(?i)secret[_\-]?key\s*[=:]\s*["'](change[\-_]?me|default|secret|dev(?:elopment)?|test(?:ing)?|password|changethis|your[\-_]?secret)["']""",
        "critical",
        "Flask secret_key uses a known default — session cookies can be forged",
    ),
    (
        "hardcoded_debug_true",
        r"""(?i)app\.run\s*\([^)]*\bdebug\s*=\s*True""",
        "high",
        "Flask debug=True enables interactive debugger without authentication",
    ),
    (
        "blind_xff_trust",
        r"""X[\-_]Forwarded[\-_]For.*\.split|getallmatchingheaders.*[Xx]-[Ff]orwarded|headers\.get\(['"]\s*[Xx]-[Ff]orwarded""",
        "high",
        "X-Forwarded-For header trusted without proxy allowlist — rate limit bypass",
    ),
    (
        "subprocess_shell_true",
        r"""subprocess\s*\.\s*(?:run|Popen|call|check_output)\s*\([^)]*\bshell\s*=\s*True""",
        "medium",
        "subprocess with shell=True may allow shell injection if args include user input",
    ),
    (
        "sql_string_concat",
        r"""(?i)(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'\n]{0,80}["']\s*[+%]\s*\w|f["'](?:SELECT|INSERT|UPDATE|DELETE)""",
        "high",
        "SQL query built via string concatenation — potential SQL injection",
    ),
    (
        "unencrypted_cred_write",
        r"""(?i)(?:password|secret|token|api_key)\b[^=\n]{0,30}=.*(?:json\.dump|write_json|open.*['"]\s*w)""",
        "medium",
        "Credential may be written to file without encryption",
    ),
]

_ROUTE_RE = re.compile(r"""@app\.route\([^)]+\)\s*\n(?:@[^\n]+\n)*def\s+\w+\(""", re.MULTILINE)
_AUTH_RE = re.compile(r"@login_required|@require_auth|@jwt_required|@requires_auth")


def scan_vulns(repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    compiled = [
        (name, re.compile(pat, re.MULTILINE | re.DOTALL), sev, desc)
        for name, pat, sev, desc in VULN_PATTERNS
    ]

    for file_path in repo_root.rglob("*.py"):
        if not file_path.is_file():
            continue
        if any(part in SKIP_DIRS for part in file_path.relative_to(repo_root).parts):
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel = str(file_path.relative_to(repo_root))

        for name, pattern, severity, desc in compiled:
            for m in pattern.finditer(content):
                lineno = content[: m.start()].count("\n") + 1
                preview = m.group(0)[:80].replace("\n", " ").strip()
                findings.append(Finding(
                    category="vuln",
                    file=rel,
                    line=lineno,
                    pattern=name,
                    match_preview=preview,
                    commit=None,
                    severity_hint=severity,
                    context={"description": desc},
                ))

        for m in _ROUTE_RE.finditer(content):
            block = m.group(0)
            if not _AUTH_RE.search(block):
                lineno = content[: m.start()].count("\n") + 1
                findings.append(Finding(
                    category="vuln",
                    file=rel,
                    line=lineno,
                    pattern="unauthenticated_route",
                    match_preview=block.split("\n")[0][:60],
                    commit=None,
                    severity_hint="info",
                    context={"description": "Route handler without visible auth decorator"},
                ))

    return findings
