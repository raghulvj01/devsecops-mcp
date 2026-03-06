from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from typing import Any


def _find_semgrep_cmd() -> list[str]:
    """Find the best available semgrep command."""
    # First check relative to current Python executable (venv)
    bin_dir = os.path.dirname(sys.executable)
    if sys.platform == "win32":
        pysemgrep = os.path.join(bin_dir, "pysemgrep.exe")
        if os.path.exists(pysemgrep):
            return [pysemgrep]
        semgrep = os.path.join(bin_dir, "semgrep.exe")
        if os.path.exists(semgrep):
            return [semgrep]
    else:
        semgrep = os.path.join(bin_dir, "semgrep")
        if os.path.exists(semgrep):
            return [semgrep]

    # Then check PATH
    if sys.platform == "win32":
        pysemgrep_which = shutil.which("pysemgrep")
        if pysemgrep_which:
            return [pysemgrep_which]
    semgrep_which = shutil.which("semgrep")
    if semgrep_which:
        return [semgrep_which]
    
    return [sys.executable, "-m", "semgrep"]


def run_semgrep_scan(path: str, config: str = "auto") -> dict[str, Any]:
    """Run a Semgrep SAST scan on a file or directory.

    Args:
        path: File or directory path to scan.
        config: Semgrep ruleset config. Defaults to "auto" which uses
                recommended rules. Can also be a path to a custom
                rules file, or a registry identifier like "p/python",
                "p/javascript", "p/owasp-top-ten", "p/security-audit".

    Returns:
        Scan results as a JSON-compatible dict with findings summary.
    """
    cmd = _find_semgrep_cmd() + [
        "scan",
        "--json",
        "--config", config,
        path,
    ]

    # Set UTF-8 mode to avoid Windows charmap encoding errors
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            env=env,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "semgrep is not installed. Install it with: pip install semgrep"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Semgrep scan timed out after 300 seconds for path '{path}'"
        ) from exc

    try:
        stdout_text = result.stdout or ""
        output = json.loads(stdout_text)
    except json.JSONDecodeError:
        stderr_text = (result.stderr or "")[:1000]
        stdout_clip = (result.stdout or "")[:1000]
        raise RuntimeError(
            f"Semgrep scan failed to return valid JSON (exit code {result.returncode}).\n"
            f"STDERR: {stderr_text}\n"
            f"STDOUT: {stdout_clip}"
        )

    # Build a concise summary
    results = output.get("results", [])
    errors = output.get("errors", [])

    findings: list[dict[str, Any]] = []
    for r in results:
        findings.append({
            "rule_id": r.get("check_id", ""),
            "severity": r.get("extra", {}).get("severity", "unknown"),
            "message": r.get("extra", {}).get("message", ""),
            "file": r.get("path", ""),
            "start_line": r.get("start", {}).get("line"),
            "end_line": r.get("end", {}).get("line"),
            "matched_code": r.get("extra", {}).get("lines", ""),
        })

    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f["severity"].upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "path": path,
        "config": config,
        "total_findings": len(findings),
        "severity_summary": severity_counts,
        "findings": findings,
        "errors_count": len(errors),
    }
