# Privacy Policy

## What data this tool accesses

When you run `reposec scan`, the tool:

- Reads files in the target repository (local disk only)
- Runs `git log` commands on the target repository (local only)
- Queries the OSV API (`https://api.osv.dev`) with package names and versions only

## What data leaves your machine

Only OSV API queries: package name + pinned version string. No source code, no file
paths, no secrets, no repository metadata is sent to any external service.

## What data is stored locally

OSV API responses are cached in `~/.cache/reposec/osv/` for 24 hours to reduce
network requests. This cache contains only package names, versions, and CVE data —
no source code.

Reports written with `--save` are stored in the repository root. These files should
be added to `.gitignore` to prevent accidental commits.

## Secret handling

Secret values found during scanning are **never** stored, logged, or included in
reports. Only redacted previews (first 4 characters + `***`) appear in output.
