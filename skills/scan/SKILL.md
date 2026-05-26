# /scan — Repository Security Scan

Perform a deep security scan of a git repository. Detects secrets, PII, code vulnerabilities,
git history leaks, and dependency CVEs.

## Pre-flight

Before scanning, verify the Python CLI is installed:

```bash
reposec --version
```

If this fails, show the user:

```
reposec is not installed. Install it with:
  pip install git+https://github.com/nikolareljin/claude-reposec
Then re-run /scan.
```

Do not proceed if `reposec` is not available.

## Running the scan

Run the scanner and capture JSON output:

```bash
reposec scan <TARGET_PATH> --json [--quick]
```

- Default: scan current working directory
- Use `--quick` only if the user explicitly passed it (skips git history)
- Parse the JSON output into a `ScanResult` object

## Adaptive dispatch

Count total findings in the JSON result:

- **Fewer than 20 findings**: Analyze all findings inline. Produce the full report yourself without
  spawning agents. Use the same section format as agents output (see Report Format below).
- **20 or more findings**: Spawn 5 parallel agents, one per category bucket. Pass each agent its
  category's `list[Finding]` JSON plus the repo name and path. Collect all agent outputs.

Agent names: `secrets-agent`, `pii-agent`, `git-history-agent`, `vulns-agent`, `deps-agent`

## Merge and report

After analysis (inline or agent-based):

1. Sort findings: CRITICAL → HIGH → MEDIUM → INFO
2. Produce unified markdown report (see Report Format)
3. If `--save` was passed: write `security-report-YYYY-MM-DD.md` to repo root. Warn the user to
   add `security-report-*.md` to `.gitignore` before committing.
4. If `--ci` was passed: exit with code 1 if any CRITICAL or HIGH findings exist.

## Report Format

```markdown
# Security Scan — <repo-name> — YYYY-MM-DD

## Summary
| Severity | Count |
|----------|-------|
| CRITICAL | N |
| HIGH     | N |
| MEDIUM   | N |
| INFO     | N |
| Clean categories | N/5 |

## Findings

[Sorted by severity, grouped by category]
Each finding: `file:line — pattern — description — exploit scenario — fix recommendation`

## Clean — Confirmed Not Present
[List categories with zero findings]
```
