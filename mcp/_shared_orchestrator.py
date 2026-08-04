"""
Module-level singleton orchestrator for the MCP server.

Ensures all MCP tool calls share the same ResearchOrchestrator instance
so that missions persist across re_create_mission / re_list_missions calls.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator import ResearchOrchestrator

_orchestrator: ResearchOrchestrator | None = None


def get_shared_orchestrator() -> ResearchOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = ResearchOrchestrator()
    return _orchestrator
