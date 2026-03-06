from __future__ import annotations

import socket
from typing import Any

_COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def port_scan(host: str, ports: str = "") -> list[dict[str, Any]]:
    """Perform a basic TCP connect scan on a host.

    Args:
        host: Target hostname or IP address.
        ports: Comma-separated port numbers. If empty, scans common service ports.

    Returns:
        List of port results with port number, status, and service name.
    """
    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise RuntimeError(f"Cannot resolve hostname '{host}': {exc}") from exc

    if ports:
        try:
            port_list = [int(p.strip()) for p in ports.split(",") if p.strip()]
        except ValueError as exc:
            raise RuntimeError(f"Invalid port specification: {exc}") from exc
    else:
        port_list = list(_COMMON_PORTS.keys())

    results: list[dict[str, Any]] = []
    for port in sorted(port_list):
        try:
            with socket.create_connection((host, port), timeout=2):
                status = "open"
        except (socket.timeout, ConnectionRefusedError, OSError):
            status = "closed"

        results.append({
            "port": port,
            "status": status,
            "service": _COMMON_PORTS.get(port, "unknown"),
        })

    return results
