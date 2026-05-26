# claude-reposec

Deep security scanning for git repositories. Detects secrets, PII, code vulnerabilities,
git history leaks, and dependency CVEs.

## What it detects

| Category | Examples |
|----------|---------|
| Secrets | AWS keys, GitHub tokens, Stripe keys, private keys, Slack tokens, connection strings |
| PII | Email addresses, phone numbers, SSNs, credit card numbers |
| Git history | Secrets or sensitive files ever committed, even if later deleted |
| Vulnerabilities | Flask misconfigs, subprocess injection, SQL string concat, missing auth decorators |
| Dependencies | CVEs in `requirements.txt` and `package.json` via OSV API |

## Installation

### As a Claude Code plugin

```bash
claude plugin install nikolareljin/claude-reposec
```

Then install the Python CLI (required):

```bash
pip install git+https://github.com/nikolareljin/claude-reposec
```

### Standalone CLI (no Claude required)

```bash
pip install git+https://github.com/nikolareljin/claude-reposec
reposec --version
```

## Usage

### In Claude Code

```
/scan                          # scan current directory
/scan path/to/repo             # scan a specific repo
/scan --quick                  # skip git history (faster)
/scan --save                   # save report to security-report-YYYY-MM-DD.md
/scan --ci                     # exit 1 if HIGH/CRITICAL findings exist
```

### Standalone CLI

```bash
reposec scan                       # scan current directory
reposec scan path/to/repo          # scan a specific repo
reposec scan --json                # output structured JSON
reposec scan --quick               # skip git history
reposec scan --save                # write report to file
reposec scan --ci                  # CI mode: exit 1 on HIGH/CRITICAL
reposec scan --output report.md    # write report to specific file
```

## CI Integration

### GitHub Actions

```yaml
- name: Security scan
  run: |
    pip install git+https://github.com/nikolareljin/claude-reposec
    reposec scan --ci
```

Or use the reusable workflow from [ci-helpers](https://github.com/nikolareljin/ci-helpers)
if your organization uses that library.

## How it works

1. **Secrets scanner**: Applies regex patterns to all text files (skips `.git/`, `node_modules/`,
   binaries, files > 1 MB). Secret values are redacted in all output — only previews are shown.

2. **PII scanner**: Detects email, phone, SSN, and credit card patterns. Credit cards are
   validated with the Luhn algorithm to reduce false positives.

3. **Git history scanner**: Runs `git log --all -S <pattern>` for each secret pattern,
   finds `.env` files ever committed, and detects deleted sensitive filenames.

4. **Vulnerability scanner**: Pattern-matches Python files for common misconfigurations
   (Flask debug mode, hardcoded secret keys, blind XFF trust, SQL string concatenation).

5. **Dependency scanner**: Parses `requirements.txt` and `package.json`, queries the
   [OSV API](https://osv.dev) for known CVEs, and caches results for 24 hours.

## Privacy

- Secret values are **never** stored or logged. Only redacted previews appear in reports.
- OSV API queries send only package name and version — no source code, no file paths.
- Reports written with `--save` should be added to `.gitignore`.

## Requirements

- Python 3.10+
- Git (for history scanning)
- Internet access (for OSV dependency CVE lookups)

## License

MIT — see [LICENSE](LICENSE). See [TERMS.md](TERMS.md) for liability information.
