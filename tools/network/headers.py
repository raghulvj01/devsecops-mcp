from __future__ import annotations

from typing import Any

import requests

_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections",
        "recommended": True,
    },
    "Content-Security-Policy": {
        "description": "Controls resources the browser is allowed to load",
        "recommended": True,
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "recommended": True,
        "expected_value": "nosniff",
    },
    "X-Frame-Options": {
        "description": "Controls whether the page can be embedded in iframes",
        "recommended": True,
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is sent",
        "recommended": True,
    },
    "Permissions-Policy": {
        "description": "Controls browser features available to the page",
        "recommended": True,
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (mostly deprecated but still checked)",
        "recommended": False,
    },
    "Cache-Control": {
        "description": "Controls caching behavior for sensitive data",
        "recommended": True,
    },
}


def check_http_headers(url: str) -> dict[str, Any]:
    """Audit HTTP security headers for a given URL.

    Args:
        url: The target URL to check (must include scheme, e.g. https://example.com).

    Returns:
        Dict with header analysis, score, and recommendations.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.head(url, timeout=10, allow_redirects=True)
    except requests.ConnectionError as exc:
        raise RuntimeError(f"Cannot connect to '{url}': {exc}") from exc
    except requests.Timeout as exc:
        raise RuntimeError(f"Request to '{url}' timed out") from exc

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    total_recommended = sum(1 for h in _SECURITY_HEADERS.values() if h["recommended"])
    present_recommended = 0

    results: list[dict[str, Any]] = []
    for header_name, info in _SECURITY_HEADERS.items():
        value = headers_lower.get(header_name.lower())
        is_present = value is not None
        if is_present and info["recommended"]:
            present_recommended += 1

        entry: dict[str, Any] = {
            "header": header_name,
            "present": is_present,
            "value": value or "",
            "description": info["description"],
        }

        expected = info.get("expected_value")
        if expected and is_present and value != expected:
            entry["warning"] = f"Expected '{expected}', got '{value}'"

        results.append(entry)

    score = round((present_recommended / total_recommended) * 100) if total_recommended else 0
    grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"

    missing = [r["header"] for r in results if not r["present"] and _SECURITY_HEADERS[r["header"]]["recommended"]]

    return {
        "url": url,
        "status_code": resp.status_code,
        "score": score,
        "grade": grade,
        "headers": results,
        "missing_recommended": missing,
    }
