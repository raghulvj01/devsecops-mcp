from __future__ import annotations

import os
import re
from typing import Any

# Common secret patterns with descriptive names
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"(?:^|[^A-Z0-9])(?:AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)")),
    ("AWS Secret Key", re.compile(
        r"""(?:aws_secret_access_key|secret_access_key|aws_secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""",
        re.IGNORECASE,
    )),
    ("Generic API Key", re.compile(
        r"""(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,60})['"]?""",
        re.IGNORECASE,
    )),
    ("Generic Token", re.compile(
        r"""(?:token|auth[_-]?token|access[_-]?token|bearer)\s*[=:]\s*['"]?([A-Za-z0-9_\-\.]{20,200})['"]?""",
        re.IGNORECASE,
    )),
    ("Generic Password", re.compile(
        r"""(?:password|passwd|pwd|secret)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?""",
        re.IGNORECASE,
    )),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("GitHub Token", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}")),
    ("Slack Token", re.compile(r"xox[bporas]-[A-Za-z0-9\-]{10,}")),
    ("Stripe Key", re.compile(r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{20,}")),
    ("SendGrid Key", re.compile(r"SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}")),
]

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".env", ".tox", "dist", "build"}
_SKIP_EXTENSIONS = {".pyc", ".pyo", ".so", ".dll", ".exe", ".bin", ".jpg", ".png", ".gif", ".ico", ".woff", ".ttf"}
_MAX_FILE_SIZE = 1_048_576  # 1 MB


def _redact(match_text: str, keep: int = 6) -> str:
    if len(match_text) <= keep:
        return "***REDACTED***"
    return match_text[:keep] + "***REDACTED***"


def _scan_file(file_path: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        if os.path.getsize(file_path) > _MAX_FILE_SIZE:
            return findings
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            for line_no, line in enumerate(fh, start=1):
                for pattern_name, pattern in _PATTERNS:
                    match = pattern.search(line)
                    if match:
                        matched_text = match.group(0).strip()
                        findings.append({
                            "file": file_path,
                            "line": line_no,
                            "pattern": pattern_name,
                            "match": _redact(matched_text),
                        })
    except (OSError, UnicodeDecodeError):
        pass
    return findings


def scan_secrets(path: str) -> list[dict[str, Any]]:
    """Scan a file or directory for exposed secrets using regex patterns.

    Args:
        path: Path to a file or directory to scan.

    Returns:
        List of findings, each with file, line, pattern name, and redacted match.
    """
    if not os.path.exists(path):
        raise RuntimeError(f"Path does not exist: {path}")

    findings: list[dict[str, Any]] = []
    if os.path.isfile(path):
        return _scan_file(path)

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in _SKIP_EXTENSIONS:
                continue
            full_path = os.path.join(root, fname)
            findings.extend(_scan_file(full_path))

    return findings
