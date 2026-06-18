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

---

## Installation

### 1. Install the Python CLI

The `reposec` CLI is required for both Claude Code plugin and standalone use.

**Linux / WSL (Ubuntu/Debian)**

```bash
# Option A: pipx (recommended — isolated, no system conflicts)
pipx install git+https://github.com/nikolareljin/claude-reposec

# Option B: user install
pip install --user git+https://github.com/nikolareljin/claude-reposec
```

> **pipx not installed?** Run: `sudo apt install pipx` (Ubuntu 23.04+) or `pip install --user pipx`

**macOS**

```bash
# Option A: pipx (recommended)
brew install pipx
pipx install git+https://github.com/nikolareljin/claude-reposec

# Option B: user install
pip3 install --user git+https://github.com/nikolareljin/claude-reposec
```

**Windows (WSL)**

Same as Linux above. Run inside your WSL terminal.

Verify the install:

```bash
reposec --version
```

---

### 2. Install the Claude Code plugin

**Step 1 — Add the marketplace** (one time, any Claude Code session):

```
/plugin marketplace add nikolareljin/claude-plugins
```

**Step 2 — Install the plugin:**

```
/plugin install claude-reposec@nikolareljin-plugins
```

**Step 3 — Restart Claude Code**, then run:

```
/nr-scan
```

> **No marketplace needed** — the CLI works fully without Claude Code (see Standalone CLI below).

---

## Usage

### In Claude Code

```
/nr-scan                          # scan current directory
/nr-scan path/to/repo             # scan a specific repo
/nr-scan --quick                  # skip git history (faster)
/nr-scan --save                   # save report to security-report-YYYY-MM-DD.md
/nr-scan --ci                     # exit 1 if HIGH/CRITICAL findings exist
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

---

## CI Integration

### GitHub Actions

```yaml
- name: Security scan
  run: |
    pip install --user git+https://github.com/nikolareljin/claude-reposec
    reposec scan --ci
```

Or use the reusable workflow from [ci-helpers](https://github.com/nikolareljin/ci-helpers)
if your organization uses that library.

---

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

---

## Privacy

- Secret values are **never** stored or logged. Only redacted previews appear in reports.
- OSV API queries send only package name and version — no source code, no file paths.
- Reports written with `--save` should be added to `.gitignore`.

---

## Requirements

- Python 3.10+
- Git (for history scanning)
- Internet access (for OSV dependency CVE lookups)

---

## License

MIT — see [LICENSE](LICENSE). See [TERMS.md](TERMS.md) for liability information.

---

## Clone traffic

![Clone traffic](https://raw.githubusercontent.com/nikolareljin/stats/main/charts/claude-reposec.svg)

_Updated daily. Total and unique cloners over the last 14 days._
