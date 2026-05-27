# Changelog

## [0.2.1] - 2026-05-26

### Fixed

- README: correct `marketplace add` syntax — command takes one `<source>` arg, not `<name> <source>`

[0.2.1]: https://github.com/nikolareljin/claude-reposec/releases/tag/0.2.1

---

## [0.2.0] - 2026-05-26

### Added

- Claude Code command `/nr-scan` — deep security scan via `reposec` CLI
- Adaptive dispatch: inline analysis for <20 findings, 5 parallel agents for ≥20
- Report format: severity table, per-finding fix recommendations
- `--quick`, `--save`, `--ci` flags supported

### Changed

- Claude Code command namespaced: `/scan` → `/nr-scan`
- `plugin.json` path fields removed — auto-discovery from repo root
- Marketplace registry moved to `nikolareljin/claude-plugins`
- Installation docs updated: `pipx`/`pip --user` (replaces bare `pip`)

### Notes

- First working release of the plugin command
- Standalone CLI (`reposec scan`) unchanged

[0.2.0]: https://github.com/nikolareljin/claude-reposec/releases/tag/0.2.0
