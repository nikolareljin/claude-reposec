from __future__ import annotations
from dataclasses import dataclass, field


@dataclass(slots=True)
class Finding:
    category: str
    file: str
    line: int | None
    pattern: str
    match_preview: str
    commit: str | None
    severity_hint: str
    context: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "pattern": self.pattern,
            "match_preview": self.match_preview,
            "commit": self.commit,
            "severity_hint": self.severity_hint,
            "context": self.context,
        }


@dataclass(slots=True)
class ScanResult:
    repo_path: str
    repo_name: str
    commit_count: int
    languages: list[str]
    findings: list[Finding]
    scan_duration_ms: int
    scanner_version: str

    def to_dict(self) -> dict:
        return {
            "repo_path": self.repo_path,
            "repo_name": self.repo_name,
            "commit_count": self.commit_count,
            "languages": self.languages,
            "findings": [f.to_dict() for f in self.findings],
            "scan_duration_ms": self.scan_duration_ms,
            "scanner_version": self.scanner_version,
        }

    def findings_by_category(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {
            "secret": [], "pii": [], "git_history": [], "vuln": [], "dep": [],
        }
        for f in self.findings:
            result.setdefault(f.category, []).append(f)
        return result
