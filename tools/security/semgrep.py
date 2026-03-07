from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from typing import Any


def _find_semgrep_cmd() -> list[str]:
    """Find the best available semgrep command."""
    # Check the project's local virtual environment first (critical for Claude Desktop)
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    venv_scripts = os.path.join(project_root, ".venv", "Scripts")
    venv_bin = os.path.join(project_root, ".venv", "bin")
    
    if sys.platform == "win32":
        venv_pysemgrep = os.path.join(venv_scripts, "pysemgrep.exe")
        if os.path.exists(venv_pysemgrep):
            return [venv_pysemgrep]
        venv_semgrep = os.path.join(venv_scripts, "semgrep.exe")
        if os.path.exists(venv_semgrep):
            return [venv_semgrep]
    else:
        venv_semgrep = os.path.join(venv_bin, "semgrep")
        if os.path.exists(venv_semgrep):
            return [venv_semgrep]

    # Check relative to current Python executable
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
        "--jobs=1",  # Fix Windows RPC IPC bug in semgrep-core
        "--quiet",   # Prevent interactive progress bars from deadlocking stdout pipe
        "--no-rewrite-rule-ids",
        "--no-git-ignore", # Scan all files regardless of git tracking status
        path,
    ]

    # Set UTF-8 mode to avoid Windows charmap encoding errors
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    # --config auto requires metrics to be enabled; Claude Desktop may
    # inherit SEMGREP_SEND_METRICS=off which causes a silent exit-code-2 crash.
    env["SEMGREP_SEND_METRICS"] = "on"
    env["SEMGREP_FORCE_COLOR"] = "0"  # no ANSI escapes in captured output
    
    # Strip dangerous global Python environment variables. If Claude Desktop 
    # executes us via global python, passing these down breaks pysemgrep.exe's venv.
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    # Also drop VIRTUAL_ENV if it points elsewhere
    if "VIRTUAL_ENV" in env:
        env.pop("VIRTUAL_ENV")

    # Ensure the venv Scripts dir and the semgrep bin dir (containing
    # semgrep-core.exe) are on PATH.  Claude Desktop often launches with a
    # minimal PATH that doesn't include either location.
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    extra_paths = []
    venv_scripts = os.path.join(project_root, ".venv", "Scripts")
    if os.path.isdir(venv_scripts):
        extra_paths.append(venv_scripts)
    # semgrep-core.exe lives inside the semgrep package
    semgrep_bin = os.path.join(
        project_root, ".venv", "Lib", "site-packages", "semgrep", "bin"
    )
    if os.path.isdir(semgrep_bin):
        extra_paths.append(semgrep_bin)
    if extra_paths:
        env["PATH"] = os.pathsep.join(extra_paths) + os.pathsep + env.get("PATH", "")

    import tempfile

    cmd_str = subprocess.list2cmdline(cmd)

    if sys.platform == "win32":
        # On Windows, pysemgrep spawns semgrep-core.exe via internal RPC
        # pipes.  When the parent process has no console (Claude Desktop /
        # MCP stdio mode), pipe inheritance is broken and semgrep-core
        # receives empty RPC input → "Expected a number, got ''".
        #
        # Fix: write a temp .bat file that runs semgrep and redirects
        # stdout/stderr to temp files.  The batch file runs in its own
        # cmd.exe session with proper pipe/console semantics.
        stdout_file = tempfile.NamedTemporaryFile(
            mode="w", suffix="_stdout.json", delete=False, dir=tempfile.gettempdir()
        )
        stderr_file = tempfile.NamedTemporaryFile(
            mode="w", suffix="_stderr.txt", delete=False, dir=tempfile.gettempdir()
        )
        bat_file = tempfile.NamedTemporaryFile(
            mode="w", suffix="_semgrep.bat", delete=False, dir=tempfile.gettempdir()
        )
        stdout_path = stdout_file.name; stdout_file.close()
        stderr_path = stderr_file.name; stderr_file.close()
        bat_path = bat_file.name

        # Write batch script that runs semgrep and captures output to files
        bat_file.write(f'@echo off\r\n{cmd_str} >"{stdout_path}" 2>"{stderr_path}"\r\n')
        bat_file.close()

        try:
            proc = subprocess.run(
                bat_path,
                timeout=300,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=True,
            )
            returncode = proc.returncode
            try:
                stdout_text = open(stdout_path, "r", encoding="utf-8", errors="replace").read()
            except Exception:
                stdout_text = ""
            try:
                stderr_text = open(stderr_path, "r", encoding="utf-8", errors="replace").read()
            except Exception:
                stderr_text = ""

            class _R:
                pass
            result = _R()
            result.stdout = stdout_text
            result.stderr = stderr_text
            result.returncode = returncode
        except FileNotFoundError:
            return {
                "path": path, "config": config,
                "error": "semgrep is not installed. Install it with: pip install semgrep",
                "total_findings": 0, "severity_summary": {}, "findings": [], "errors_count": 1,
            }
        except subprocess.TimeoutExpired:
            return {
                "path": path, "config": config,
                "error": f"Semgrep scan timed out after 300 seconds for path '{path}'",
                "total_findings": 0, "severity_summary": {}, "findings": [], "errors_count": 1,
            }
        finally:
            for f in (bat_path, stdout_path, stderr_path):
                try:
                    os.unlink(f)
                except Exception:
                    pass
    else:
        # Unix: normal subprocess with pipes works fine
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
                env=env,
                stdin=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            return {
                "path": path, "config": config,
                "error": "semgrep is not installed. Install it with: pip install semgrep",
                "total_findings": 0, "severity_summary": {}, "findings": [], "errors_count": 1,
            }
        except subprocess.TimeoutExpired:
            return {
                "path": path, "config": config,
                "error": f"Semgrep scan timed out after 300 seconds for path '{path}'",
                "total_findings": 0, "severity_summary": {}, "findings": [], "errors_count": 1,
            }

    try:
        stdout_text = result.stdout or ""
        output = json.loads(stdout_text)
    except json.JSONDecodeError:
        stderr_text = (result.stderr or "")[:2000]
        stdout_clip = (result.stdout or "")[:2000]
        return {
            "path": path,
            "config": config,
            "error": f"Semgrep failed to return valid JSON (exit code {result.returncode})",
            "stderr": stderr_text,
            "stdout_clip": stdout_clip,
            "command": cmd_str,
            "total_findings": 0,
            "severity_summary": {},
            "findings": [],
            "errors_count": 1,
        }

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
