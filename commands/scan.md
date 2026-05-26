---
description: Deep security scan of a git repo — secrets, PII, vulnerabilities, git history, and dependency CVEs
argument-hint: "[path] [--quick] [--save] [--ci]"
---

# /scan

Perform a deep security scan of a git repository.

## Usage

```
/scan [path] [--quick] [--save] [--ci]
```

## Arguments

- `path` — path to the repository to scan (default: current directory)
- `--quick` — skip git history scan (faster for large repos)
- `--save` — write the report to `security-report-YYYY-MM-DD.md` in the repo root
- `--ci` — exit with code 1 if any CRITICAL or HIGH findings are present

## Examples

```
/scan                              # scan current directory
/scan path/to/repo                 # scan a specific repo
/scan --quick                      # skip git history
/scan --save                       # save report to file
/scan --ci                         # CI mode: fail on HIGH/CRITICAL
/scan path/to/repo --save --ci     # full scan, save, fail on findings
```

## What it detects

- **Secrets**: AWS keys, GitHub tokens, Stripe keys, private keys, Slack tokens, connection strings
- **PII**: email addresses, phone numbers, SSNs, credit card numbers
- **Git history**: secrets or sensitive files ever committed (even if later deleted)
- **Vulnerabilities**: Flask misconfigs, subprocess injection, SQL string concat, missing auth
- **Dependencies**: CVEs in requirements.txt and package.json via OSV API

## Requirements

The `reposec` Python CLI must be installed:

```bash
pip install git+https://github.com/nikolareljin/claude-reposec
```
