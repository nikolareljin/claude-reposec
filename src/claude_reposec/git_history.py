from __future__ import annotations

import subprocess
from pathlib import Path

from .models import Finding
from .secrets import SECRET_PATTERNS, _redact

_SENSITIVE_FILENAMES = [".env", "credentials", "secrets", "id_rsa", "id_ed25519", ".netrc", "*.pem", "*.key"]


def _git(args: list[str], cwd: Path, timeout: int = 60) -> str:
    try:
        r = subprocess.run(
            ["git", "-C", str(cwd)] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        return r.stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return ""


def scan_git_history(repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []

    env_log = _git(
        ["log", "--all", "--diff-filter=A", "--name-only",
         "--format=COMMIT:%H", "--", "*.env", ".env"],
        repo_root,
    )
    current = None
    for line in env_log.splitlines():
        if line.startswith("COMMIT:"):
            current = line[7:]
        elif line.strip():
            findings.append(Finding(
                category="git_history",
                file=line.strip(),
                line=None,
                pattern="env_file_committed",
                match_preview=line.strip(),
                commit=current,
                severity_hint="critical",
                context={"note": ".env file was committed to history"},
            ))

    for pattern_name, pattern_regex, severity in SECRET_PATTERNS:
        output = _git(
            ["log", "--all", "-S", pattern_regex, "--oneline", "--no-decorate"],
            repo_root, timeout=30,
        )
        for line in output.strip().splitlines():
            if not line:
                continue
            parts = line.split(" ", 1)
            commit_hash = parts[0]
            msg = parts[1] if len(parts) > 1 else ""
            findings.append(Finding(
                category="git_history",
                file="git-history",
                line=None,
                pattern=f"history_{pattern_name}",
                match_preview=f"commit {commit_hash[:8]}",
                commit=commit_hash,
                severity_hint=severity,
                context={"pattern": pattern_name, "message": msg},
            ))

    for fname in _SENSITIVE_FILENAMES:
        deleted = _git(
            ["log", "--all", "--diff-filter=D", "--name-only",
             "--format=COMMIT:%H", "--", f"*{fname}"],
            repo_root,
        )
        current = None
        for line in deleted.splitlines():
            if line.startswith("COMMIT:"):
                current = line[7:]
            elif line.strip():
                findings.append(Finding(
                    category="git_history",
                    file=line.strip(),
                    line=None,
                    pattern="deleted_secret_file",
                    match_preview=line.strip(),
                    commit=current,
                    severity_hint="high",
                    context={"note": "Sensitive file deleted from working tree but remains in git history"},
                ))

    return findings
