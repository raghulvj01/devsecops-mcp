from __future__ import annotations

import json
import os
import re
from typing import Any

import requests


def _parse_requirements_txt(file_path: str) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    with open(file_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:[=<>!~]+\s*(.+))?", line)
            if match:
                name = match.group(1)
                version = match.group(2).strip() if match.group(2) else ""
                packages.append({"name": name, "version": version})
    return packages


def _parse_package_json(file_path: str) -> list[dict[str, str]]:
    with open(file_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    packages: list[dict[str, str]] = []
    for dep_key in ("dependencies", "devDependencies"):
        for name, version in data.get(dep_key, {}).items():
            clean_version = re.sub(r"^[\^~>=<]", "", version)
            packages.append({"name": name, "version": clean_version})
    return packages


def _query_osv(ecosystem: str, package_name: str, version: str) -> list[dict[str, Any]]:
    """Query the OSV.dev API for known vulnerabilities."""
    payload: dict[str, Any] = {
        "package": {"name": package_name, "ecosystem": ecosystem},
    }
    if version:
        payload["version"] = version

    try:
        resp = requests.post(
            "https://api.osv.dev/v1/query",
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
    except requests.RequestException:
        return []

    vulns = resp.json().get("vulns", [])
    results: list[dict[str, Any]] = []
    for vuln in vulns:
        aliases = vuln.get("aliases", [])
        cve = next((a for a in aliases if a.startswith("CVE-")), aliases[0] if aliases else vuln.get("id", ""))
        severity_list = vuln.get("severity", [])
        severity = severity_list[0].get("score", "unknown") if severity_list else "unknown"
        results.append({
            "id": vuln.get("id", ""),
            "cve": cve,
            "summary": vuln.get("summary", "No summary available"),
            "severity": severity,
        })
    return results


def check_dependencies(file_path: str) -> list[dict[str, Any]]:
    """Scan a dependency file for known vulnerabilities via OSV.dev.

    Args:
        file_path: Path to requirements.txt or package.json.

    Returns:
        List of packages with their vulnerability status.
    """
    if not os.path.exists(file_path):
        raise RuntimeError(f"File does not exist: {file_path}")

    basename = os.path.basename(file_path).lower()
    if basename == "requirements.txt":
        packages = _parse_requirements_txt(file_path)
        ecosystem = "PyPI"
    elif basename == "package.json":
        packages = _parse_package_json(file_path)
        ecosystem = "npm"
    else:
        raise RuntimeError(f"Unsupported dependency file: {basename}. Use requirements.txt or package.json.")

    results: list[dict[str, Any]] = []
    for pkg in packages:
        vulns = _query_osv(ecosystem, pkg["name"], pkg["version"])
        results.append({
            "package": pkg["name"],
            "version": pkg["version"] or "unspecified",
            "vulnerabilities_found": len(vulns),
            "vulnerabilities": vulns,
        })

    return results
