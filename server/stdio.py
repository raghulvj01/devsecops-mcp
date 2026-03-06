"""Stdio entry-point for Claude Desktop and other MCP clients that launch the server as a subprocess."""
from __future__ import annotations

from server.main import mcp

if __name__ == "__main__":
    mcp.run(transport="stdio")
