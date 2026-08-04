"""
MCP Server for the Reverse Engineering Lab — antigravity integration.

Exposes all RE tools, agents, and knowledge base as MCP tools over stdio.
Designed to be launched by antigravity as a local MCP server.

Protocol: JSON-RPC 2.0 over stdin/stdout (MCP specification).

Usage:
    python -m mcp.antigravity_server
"""

import asyncio
import os
import sys
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Set environment variable to signal we are running under antigravity
os.environ["MCP_PLATFORM"] = "antigravity"

from mcp.opencode_server import main

if __name__ == "__main__":
    asyncio.run(main())
