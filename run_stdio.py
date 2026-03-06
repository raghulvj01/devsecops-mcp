"""Launcher script for Claude Desktop — ensures the project root is on sys.path."""
import sys
import os

# Set working directory and sys.path to the project root so that
# relative policy file paths (policies/roles.yaml etc.) resolve correctly
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(PROJECT_ROOT)
sys.path.insert(0, PROJECT_ROOT)

from server.main import mcp

if __name__ == "__main__":
    mcp.run(transport="stdio")
