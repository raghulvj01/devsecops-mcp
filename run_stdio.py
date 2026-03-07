"""Launcher script for Claude Desktop — ensures the project root is on sys.path."""
import sys
import os

# Set working directory and sys.path to the project root so that
# relative policy file paths (policies/roles.yaml etc.) resolve correctly
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(PROJECT_ROOT)
sys.path.insert(0, PROJECT_ROOT)

# Disable JWT auth for local stdio sessions (Claude Desktop cannot supply tokens)
os.environ.setdefault("MCP_AUTH_DISABLED", "true")

# Ensure the venv Scripts dir is on PATH so pysemgrep / semgrep-core are found
venv_scripts = os.path.join(PROJECT_ROOT, ".venv", "Scripts")
if os.path.isdir(venv_scripts) and venv_scripts not in os.environ.get("PATH", ""):
    os.environ["PATH"] = venv_scripts + os.pathsep + os.environ.get("PATH", "")

from server.main import mcp

if __name__ == "__main__":
    mcp.run(transport="stdio")
