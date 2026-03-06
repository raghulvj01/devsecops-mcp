from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any


def check_ssl_certificate(hostname: str, port: int = 443) -> dict[str, Any]:
    """Check the SSL/TLS certificate for a given hostname.

    Args:
        hostname: Domain name to check.
        port: TCP port (default 443).

    Returns:
        Certificate details including subject, issuer, validity, and expiry info.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except socket.gaierror as exc:
        raise RuntimeError(f"DNS resolution failed for '{hostname}': {exc}") from exc
    except socket.timeout as exc:
        raise RuntimeError(f"Connection to '{hostname}:{port}' timed out") from exc
    except ssl.SSLError as exc:
        raise RuntimeError(f"SSL error for '{hostname}:{port}': {exc}") from exc
    except OSError as exc:
        raise RuntimeError(f"Connection failed to '{hostname}:{port}': {exc}") from exc

    if not cert:
        raise RuntimeError(f"No certificate returned by '{hostname}:{port}'")

    def _format_name(name_tuples: tuple) -> str:
        parts = []
        for attr_group in name_tuples:
            for key, value in attr_group:
                parts.append(f"{key}={value}")
        return ", ".join(parts)

    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    now = datetime.now(tz=timezone.utc)
    days_until_expiry = (not_after - now).days

    san_entries = []
    for san_type, san_value in cert.get("subjectAltName", ()):
        san_entries.append(f"{san_type}:{san_value}")

    return {
        "hostname": hostname,
        "port": port,
        "subject": _format_name(cert.get("subject", ())),
        "issuer": _format_name(cert.get("issuer", ())),
        "serial_number": cert.get("serialNumber", ""),
        "version": cert.get("version", ""),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": days_until_expiry,
        "expired": days_until_expiry < 0,
        "subject_alt_names": san_entries,
        "protocol": "TLSv1.2+",
    }
