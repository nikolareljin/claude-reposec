from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

from .models import Finding

CACHE_DIR = Path.home() / ".cache" / "reposec" / "osv"
CACHE_TTL = 86400
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def _cache_key(ecosystem: str, package: str, version: str) -> Path:
    safe = f"{ecosystem}_{package}_{version}".replace("/", "_").replace(":", "_")
    return CACHE_DIR / f"{safe}.json"


def _read_cache(key: Path) -> dict | None:
    if not key.exists():
        return None
    try:
        data = json.loads(key.read_text())
        if time.time() - data.get("_cached_at", 0) < CACHE_TTL:
            return data
    except (json.JSONDecodeError, OSError):
        pass
    return None


def _write_cache(key: Path, data: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        out = dict(data)
        out["_cached_at"] = time.time()
        key.write_text(json.dumps(out))
    except OSError:
        pass


def _parse_requirements_txt(path: Path) -> list[tuple[str, str, str]]:
    packages = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_\-\.]+)==([^\s;]+)", line)
        if m:
            packages.append(("PyPI", m.group(1), m.group(2)))
    return packages


def _parse_package_json(path: Path) -> list[tuple[str, str, str]]:
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    packages = []
    for section in ("dependencies", "devDependencies"):
        for pkg, ver in data.get(section, {}).items():
            clean = ver.lstrip("^~>=< ")
            if re.match(r"^\d+\.\d+", clean):
                packages.append(("npm", pkg, clean))
    return packages


def _query_osv_batch(packages: list[tuple[str, str, str]]) -> list[dict]:
    queries = [
        {"version": ver, "package": {"name": pkg, "ecosystem": eco}}
        for eco, pkg, ver in packages
    ]
    payload = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        OSV_BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read()).get("results", [])
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return []


def scan_deps(repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    all_packages: list[tuple[str, str, str]] = []

    for req in repo_root.rglob("requirements*.txt"):
        if any(p in {".git", "node_modules", "__pycache__"} for p in req.parts):
            continue
        all_packages.extend(_parse_requirements_txt(req))

    pkg_json = repo_root / "package.json"
    if pkg_json.exists():
        all_packages.extend(_parse_package_json(pkg_json))

    if not all_packages:
        return findings

    uncached: list[tuple[int, tuple[str, str, str]]] = []
    results_map: dict[int, dict] = {}

    for i, pkg in enumerate(all_packages):
        cached = _read_cache(_cache_key(*pkg))
        if cached is not None:
            results_map[i] = cached
        else:
            uncached.append((i, pkg))

    for start in range(0, len(uncached), 100):
        batch = uncached[start : start + 100]
        api_results = _query_osv_batch([p for _, p in batch])
        for (idx, pkg), result in zip(batch, api_results):
            _write_cache(_cache_key(*pkg), result)
            results_map[idx] = result

    for i, (eco, pkg_name, version) in enumerate(all_packages):
        for vuln in results_map.get(i, {}).get("vulns", []):
            vuln_id = vuln.get("id", "unknown")
            severity = "high"
            cvss = ""
            for s in vuln.get("severity", []):
                if s.get("type") == "CVSS_V3":
                    try:
                        score = float(s["score"])
                        cvss = f"CVSS {score}"
                        if score >= 9.0:
                            severity = "critical"
                        elif score >= 7.0:
                            severity = "high"
                        elif score >= 4.0:
                            severity = "medium"
                        else:
                            severity = "info"
                    except (ValueError, KeyError):
                        pass

            fix_versions = [
                e["fixed"]
                for aff in vuln.get("affected", [])
                for r in aff.get("ranges", [])
                for e in r.get("events", [])
                if "fixed" in e
            ]

            findings.append(Finding(
                category="dep",
                file=f"dependency:{pkg_name}@{version}",
                line=None,
                pattern="known_vulnerability",
                match_preview=f"{vuln_id} in {pkg_name}=={version}",
                commit=None,
                severity_hint=severity,
                context={
                    "vuln_id": vuln_id,
                    "package": pkg_name,
                    "version": version,
                    "ecosystem": eco,
                    "cvss": cvss,
                    "fix_versions": fix_versions,
                    "summary": vuln.get("summary", ""),
                },
            ))

    return findings
