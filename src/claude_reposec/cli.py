from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from .scanner import scan_repository
from . import __version__

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}
_SEV_EMOJI = {"critical": "🔴 CRITICAL", "high": "🟠 HIGH", "medium": "🟡 MEDIUM", "info": "🟢 INFO"}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="reposec", description="Deep security scanner for git repos.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="Scan a repository for security issues")
    scan.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    scan.add_argument("--json", action="store_true", help="Output raw JSON")
    scan.add_argument("--save", action="store_true", help="Write report to security-report-YYYY-MM-DD.md")
    scan.add_argument("--output", metavar="FILE", help="Write report to FILE")
    scan.add_argument("--ci", action="store_true", help="Exit 1 if HIGH/CRITICAL found")
    scan.add_argument("--quick", action="store_true", help="Skip git history scan")
    return p


def _render_report(result) -> str:
    counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    for f in result.findings:
        counts[f.severity_hint] = counts.get(f.severity_hint, 0) + 1

    by_cat = result.findings_by_category()
    clean = [c for c, fs in by_cat.items() if not fs]

    lines = [
        f"# Security Scan — {result.repo_name} — {date.today().isoformat()}",
        "",
        f"Scanned {result.commit_count} commits · {result.scan_duration_ms}ms"
        + (f" · {', '.join(result.languages)}" if result.languages else ""),
        "",
        "## Summary",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 CRITICAL | {counts['critical']} |",
        f"| 🟠 HIGH | {counts['high']} |",
        f"| 🟡 MEDIUM | {counts['medium']} |",
        f"| 🟢 INFO | {counts['info']} |",
        f"| ✅ Clean categories | {len(clean)}/5 |",
        "",
        "## Findings",
    ]

    sorted_findings = sorted(result.findings, key=lambda f: _SEV_ORDER.get(f.severity_hint, 9))

    if not sorted_findings:
        lines.append("\nNo findings. Repository looks clean. ✅")
    else:
        current_sev = None
        for f in sorted_findings:
            if f.severity_hint != current_sev:
                current_sev = f.severity_hint
                lines.append(f"\n### {_SEV_EMOJI.get(f.severity_hint, f.severity_hint.upper())}")
            loc = f"{f.file}:{f.line}" if f.line else f.file
            desc = f.context.get("description") or f.context.get("note") or ""
            extra = f" — {desc}" if desc else ""
            lines.append(f"- `{loc}` — **{f.pattern}** — `{f.match_preview}`{extra}")

    if clean:
        lines += ["", "## ✅ Clean — Confirmed Not Present", ""]
        lines += [f"- {c}" for c in sorted(clean)]

    return "\n".join(lines)


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "scan":
        repo = Path(args.path).resolve()
        if not repo.exists():
            print(f"error: path does not exist: {repo}", file=sys.stderr)
            return 2

        result = scan_repository(repo, skip_history=args.quick)

        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            report = _render_report(result)
            print(report)

            if args.save or args.output:
                out = Path(args.output) if args.output else repo / f"security-report-{date.today().isoformat()}.md"
                out.write_text(report, encoding="utf-8")
                print(f"\nReport saved → {out}", file=sys.stderr)

        if args.ci:
            if any(f.severity_hint in ("critical", "high") for f in result.findings):
                print("CI: HIGH/CRITICAL findings present — exit 1", file=sys.stderr)
                return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
