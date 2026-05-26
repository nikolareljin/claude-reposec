from __future__ import annotations

import subprocess
import time
from pathlib import Path

from .deps import scan_deps
from .git_history import scan_git_history
from .models import ScanResult
from .pii import scan_pii
from .secrets import scan_secrets, SKIP_DIRS
from .vulns import scan_vulns
from . import __version__

_EXT_LANG = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".rs": "Rust", ".go": "Go", ".java": "Java", ".rb": "Ruby",
    ".php": "PHP", ".cs": "C#", ".cpp": "C++", ".c": "C",
}


def _detect_languages(repo_root: Path) -> list[str]:
    found: set[str] = set()
    for f in repo_root.rglob("*"):
        if any(part in SKIP_DIRS for part in f.parts):
            continue
        lang = _EXT_LANG.get(f.suffix.lower())
        if lang:
            found.add(lang)
    return sorted(found)


def _count_commits(repo_root: Path) -> int:
    try:
        r = subprocess.run(
            ["git", "-C", str(repo_root), "rev-list", "--all", "--count"],
            capture_output=True, text=True, timeout=15,
        )
        return int(r.stdout.strip())
    except (subprocess.SubprocessError, ValueError, FileNotFoundError):
        return 0


def scan_repository(repo_root: Path, skip_history: bool = False) -> ScanResult:
    root = repo_root.resolve()
    start = time.monotonic()

    findings = []
    findings.extend(scan_secrets(root))
    findings.extend(scan_pii(root))
    findings.extend(scan_vulns(root))
    findings.extend(scan_deps(root))
    if not skip_history:
        findings.extend(scan_git_history(root))

    return ScanResult(
        repo_path=str(root),
        repo_name=root.name,
        commit_count=_count_commits(root),
        languages=_detect_languages(root),
        findings=findings,
        scan_duration_ms=int((time.monotonic() - start) * 1000),
        scanner_version=__version__,
    )
