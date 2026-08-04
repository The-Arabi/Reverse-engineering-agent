"""
MCP Server for the Reverse Engineering Lab — opencode integration.

Exposes all RE tools, agents, and knowledge base as MCP tools over stdio.
Designed to be launched by opencode as a local MCP server.

Protocol: JSON-RPC 2.0 over stdin/stdout (MCP specification).

Usage:
    python -m mcp.opencode_server
"""

import asyncio
import json
import logging
import os
import sys
import threading
import traceback
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.tool_runner import (
    run_objdump, run_readelf, run_strings, run_file, run_binwalk,
    run_tshark, run_capinfos, run_gdb, run_hexdump, run_ghidra_headless,
    run_tool, get_available_tools, ToolResult,
)

PLATFORM = os.environ.get("MCP_PLATFORM", "opencode")
logger = logging.getLogger(f"mcp.{PLATFORM}_server")

# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

TOOLS: List[Dict[str, Any]] = []


def _tool(name: str, description: str, input_schema: Dict[str, Any]):
    """Decorator to register an MCP tool."""
    def decorator(func):
        TOOLS.append({
            "name": name,
            "description": description,
            "inputSchema": input_schema,
            "_handler": func,
        })
        return func
    return decorator


def _result(text: str) -> Dict[str, Any]:
    """Wrap text into MCP content result."""
    return {"content": [{"type": "text", "text": text}]}


def _error(text: str) -> Dict[str, Any]:
    """Wrap error into MCP content result with isError flag."""
    return {"content": [{"type": "text", "text": text}], "isError": True}


def _tool_result_to_text(r: ToolResult) -> str:
    """Convert a ToolResult to readable text."""
    parts = [f"Command: {r.command}"]
    if r.timed_out:
        parts.append(f"Status: TIMED OUT after {r.command}")
    elif not r.tool_available:
        parts.append(f"Status: TOOL NOT AVAILABLE — {r.stderr}")
    elif r.success:
        parts.append("Status: OK")
    else:
        parts.append(f"Status: FAILED (exit code {r.returncode})")
    if r.stdout.strip():
        parts.append(f"\n--- stdout ---\n{r.stdout.strip()}")
    if r.stderr.strip():
        parts.append(f"\n--- stderr ---\n{r.stderr.strip()}")
    return "\n".join(parts)


# ===========================================================================
# Tool implementations
# ===========================================================================

@_tool(
    "re_file_identify",
    "Identify file type, architecture, and format of a binary or file.",
    {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Path to the file to identify"},
        },
        "required": ["file_path"],
    },
)
async def file_identify(file_path: str) -> Dict[str, Any]:
    r = await run_file(file_path)
    return _result(_tool_result_to_text(r))


@_tool(
    "re_readelf",
    "Display ELF file structure: headers, sections, segments, symbols, and relocations.",
    {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Path to the ELF binary"},
            "headers": {"type": "boolean", "description": "Show ELF headers (default true)", "default": True},
            "sections": {"type": "boolean", "description": "Show section headers"},
            "segments": {"type": "boolean", "description": "Show program headers/segments"},
            "symbols": {"type": "boolean", "description": "Show symbol table"},
            "relocations": {"type": "boolean", "description": "Show relocations"},
            "all": {"type": "boolean", "description": "Show everything"},
        },
        "required": ["file_path"],
    },
)
async def readelf(
    file_path: str,
    headers: bool = True,
    sections: bool = False,
    segments: bool = False,
    symbols: bool = False,
    relocations: bool = False,
    all: bool = False,
) -> Dict[str, Any]:
    flags = []
    if all:
        flags.append("-a")
    else:
        if headers:
            flags.append("-h")
        if sections:
            flags.append("-S")
        if segments:
            flags.append("-l")
        if symbols:
            flags.append("-s")
        if relocations:
            flags.append("-r")
    if not flags:
        flags.append("-h")
    r = await run_readelf(file_path, flags)
    return _result(_tool_result_to_text(r))


@_tool(
    "re_objdump",
    "Disassemble binary code and inspect assembly-level details.",
    {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Path to the binary"},
            "disassemble": {"type": "boolean", "description": "Show disassembly (default true)", "default": True},
            "headers": {"type": "boolean", "description": "Show file headers"},
            "section_headers": {"type": "boolean", "description": "Show section headers"},
            "all_headers": {"type": "boolean", "description": "Show all headers"},
            "functions": {"type": "boolean", "description": "Disassemble only known functions"},
            "start_address": {"type": "string", "description": "Start address for disassembly (hex, e.g. 0x400000)"},
            "end_address": {"type": "string", "description": "End address for disassembly (hex)"},
            "extra_flags": {"type": "array", "items": {"type": "string"}, "description": "Additional objdump flags"},
        },
        "required": ["file_path"],
    },
)
async def objdump(
    file_path: str,
    disassemble: bool = True,
    headers: bool = False,
    section_headers: bool = False,
    all_headers: bool = False,
    functions: bool = False,
    start_address: Optional[str] = None,
    end_address: Optional[str] = None,
    extra_flags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    flags = []
    if all_headers:
        flags.append("-x")
    else:
        if headers:
            flags.append("-f")
        if section_headers:
            flags.append("-h")
    if disassemble:
        flags.append("-d")
        if functions:
            flags.append("-j", )
            flags.append(".text")
    if start_address:
        flags.append(f"--start-address={start_address}")
    if end_address:
        flags.append(f"--stop-address={end_address}")
    if extra_flags:
        flags.extend(extra_flags)
    r = await run_objdump(file_path, flags if flags else ["-d"])
    return _result(_tool_result_to_text(r))


@_tool(
    "re_strings",
    "Extract printable strings from a binary file.",
    {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Path to the file"},
            "min_length": {"type": "integer", "description": "Minimum string length (default 4)", "default": 4},
            "encoding": {"type": "string", "description": "Character encoding: s=7bit ASCII, S=8bit, l=16bit LE, b=32bit BE", "default": "s"},
            "filter_pattern": {"type": "string", "description": "Grep-style pattern to filter strings (applied client-side)"},
        },
        "required": ["file_path"],
    },
)
async def strings(
    file_path: str,
    min_length: int = 4,
    encoding: str = "s",
    filter_pattern: Optional[str] = None,
) -> Dict[str, Any]:
    r = await run_strings(file_path, min_length=min_length, encoding=encoding)
    if r.success and filter_pattern and r.stdout:
        import re
        pattern = re.compile(filter_pattern, re.IGNORECASE)
        lines = r.stdout.splitlines()
        filtered = [l for l in lines if pattern.search(l)]
        r.stdout = "\n".join(filtered)
    return _result(_tool_result_to_text(r))


@_tool(
    "re_hexdump",
    "View raw hex bytes of a file (hexdump -C).",
    {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Path to the file"},
            "length": {"type": "integer", "description": "Number of bytes to dump (default 256)", "default": 256},
            "offset": {"type": "integer", "description": "Byte offset to start from (default 0)", "default": 0},
        },
        "required": ["file_path"],
    },
)
async def hexdump(file_path: str, length: int = 256, offset: int = 0) -> Dict[str, Any]:
    cmd = ["hexdump", "-C"]
    if offset:
        cmd.extend(["-s", str(offset)])
    cmd.extend(["-n", str(length), file_path])
    r = await run_tool(cmd, timeout=30)
    return _result(_tool_result_to_text(r))


@_tool(
    "re_binwalk",
    "Scan or extract embedded files from firmware images using binwalk.",
    {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Path to the firmware image"},
            "extract": {"type": "boolean", "description": "Attempt to extract embedded files (default false)", "default": False},
            "scan_only": {"type": "boolean", "description": "Scan for signatures only (default true)", "default": True},
        },
        "required": ["file_path"],
    },
)
async def binwalk(file_path: str, extract: bool = False, scan_only: bool = True) -> Dict[str, Any]:
    r = await run_binwalk(file_path, extract=extract, scan_only=scan_only)
    return _result(_tool_result_to_text(r))


@_tool(
    "re_tshark",
    "Analyze network packet captures (pcap/pcapng) with tshark.",
    {
        "type": "object",
        "properties": {
            "pcap_file": {"type": "string", "description": "Path to the pcap/pcapng file"},
            "filters": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Display filters (e.g. 'http', 'tcp.port==80', 'dns')",
            },
            "fields": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific fields to extract (e.g. 'http.host', 'ip.src')",
            },
            "max_packets": {"type": "integer", "description": "Max packets to display (0=all)", "default": 0},
            "verbose": {"type": "boolean", "description": "Show detailed packet decode (default true)", "default": True},
        },
        "required": ["pcap_file"],
    },
)
async def tshark(
    pcap_file: str,
    filters: Optional[List[str]] = None,
    fields: Optional[List[str]] = None,
    max_packets: int = 0,
    verbose: bool = True,
) -> Dict[str, Any]:
    cmd = ["tshark", "-r", pcap_file]
    if fields:
        # Field mode: -T fields
        cmd.extend(["-T", "fields"])
        for f in fields:
            cmd.extend(["-e", f])
    elif verbose:
        cmd.append("-V")
    if filters:
        for f in filters:
            cmd.extend(["-Y", f])
    if max_packets > 0:
        cmd.extend(["-c", str(max_packets)])
    r = await run_tool(cmd, timeout=120)
    return _result(_tool_result_to_text(r))


@_tool(
    "re_capinfos",
    "Get metadata about a pcap capture file (duration, packets, size, etc.).",
    {
        "type": "object",
        "properties": {
            "pcap_file": {"type": "string", "description": "Path to the pcap/pcapng file"},
        },
        "required": ["pcap_file"],
    },
)
async def capinfos(pcap_file: str) -> Dict[str, Any]:
    r = await run_capinfos(pcap_file)
    return _result(_tool_result_to_text(r))


@_tool(
    "re_gdb",
    "Run GDB on a binary for analysis (batch mode). Can list functions, info, disassemble.",
    {
        "type": "object",
        "properties": {
            "binary_path": {"type": "string", "description": "Path to the binary"},
            "commands": {
                "type": "array",
                "items": {"type": "string"},
                "description": "GDB commands to run (e.g. 'info functions', 'disassemble main', 'info headers')",
            },
        },
        "required": ["binary_path"],
    },
)
async def gdb_analyze(binary_path: str, commands: Optional[List[str]] = None) -> Dict[str, Any]:
    if not commands:
        commands = ["info file", "info functions", "info sharedlibrary"]
    r = await run_gdb(binary_path, commands=commands)
    return _result(_tool_result_to_text(r))


@_tool(
    "re_ghidra",
    "Run Ghidra headless analysis on a binary (decompile, analyze, extract).",
    {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Path to the binary to analyze"},
            "scripts": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Ghidra script filenames to run (from mcp/ghidra_scripts/)",
            },
        },
        "required": ["file_path"],
    },
)
async def ghidra(file_path: str, scripts: Optional[List[str]] = None) -> Dict[str, Any]:
    r = await run_ghidra_headless(file_path, post_scripts=scripts)
    return _result(_tool_result_to_text(r))


@_tool(
    "re_available_tools",
    "Check which RE analysis tools are installed on the system.",
    {"type": "object", "properties": {}},
)
async def available_tools() -> Dict[str, Any]:
    tools = get_available_tools()
    lines = ["Installed RE Tools:"]
    for name, avail in sorted(tools.items()):
        status = "installed" if avail else "NOT FOUND"
        lines.append(f"  {name:25s} {status}")
    return _result("\n".join(lines))


@_tool(
    "re_run_command",
    "Run an arbitrary system command (for custom RE tools like radare2, strace, etc.).",
    {
        "type": "object",
        "properties": {
            "command": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Command and arguments (e.g. ['radare2', '-q', '-c', 'aaa; afl', '/path/to/bin'])",
            },
            "timeout": {"type": "integer", "description": "Timeout in seconds (default 60)", "default": 60},
        },
        "required": ["command"],
    },
)
async def run_custom_command(command: List[str], timeout: int = 60) -> Dict[str, Any]:
    r = await run_tool(command, timeout=timeout)
    return _result(_tool_result_to_text(r))


# ---------------------------------------------------------------------------
# Knowledge base tools
# ---------------------------------------------------------------------------

@_tool(
    "kb_add_fact",
    "Store a verified finding in the knowledge base.",
    {
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "Short title for the fact"},
            "description": {"type": "string", "description": "Detailed description"},
            "confidence": {"type": "number", "description": "Confidence 0.0-1.0 (default 0.8)", "default": 0.8},
            "evidence": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Evidence supporting this fact",
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Tags for categorization",
            },
            "source_agent": {"type": "string", "description": "Agent that found this (e.g. 'binary_analysis')"},
        },
        "required": ["title", "description"],
    },
)
async def kb_add_fact(
    title: str,
    description: str,
    confidence: float = 0.8,
    evidence: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    source_agent: Optional[str] = None,
) -> Dict[str, Any]:
    from knowledge_base import add_fact
    item_id = add_fact(
        title=title,
        description=description,
        confidence=confidence,
        evidence=evidence or [],
        source_references=[],
        tags=tags or [],
        source_agent=source_agent or PLATFORM,
    )
    return _result(f"Fact stored with ID: {item_id}")


@_tool(
    "kb_add_hypothesis",
    "Store a testable hypothesis in the knowledge base.",
    {
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "Short title for the hypothesis"},
            "description": {"type": "string", "description": "Detailed description"},
            "confidence": {"type": "number", "description": "Confidence 0.0-1.0 (default 0.5)", "default": 0.5},
            "basis": {"type": "string", "description": "What evidence supports this hypothesis"},
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Tags for categorization",
            },
            "source_agent": {"type": "string", "description": "Agent that proposed this"},
        },
        "required": ["title", "description", "basis"],
    },
)
async def kb_add_hypothesis(
    title: str,
    description: str,
    basis: str,
    confidence: float = 0.5,
    tags: Optional[List[str]] = None,
    source_agent: Optional[str] = None,
) -> Dict[str, Any]:
    from knowledge_base import add_hypothesis
    item_id = add_hypothesis(
        title=title,
        description=description,
        confidence=confidence,
        basis=basis,
        testable=True,
        prediction="",
        falsification_condition="",
        tags=tags or [],
        source_agent=source_agent or PLATFORM,
    )
    return _result(f"Hypothesis stored with ID: {item_id}")


@_tool(
    "kb_search",
    "Search the knowledge base by keyword query.",
    {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "limit": {"type": "integer", "description": "Max results (default 10)", "default": 10},
        },
        "required": ["query"],
    },
)
async def kb_search(query: str, limit: int = 10) -> Dict[str, Any]:
    from knowledge_base import kb
    results = kb.search_knowledge(query=query, limit=limit)
    if not results:
        return _result("No results found.")
    lines = [f"Found {len(results)} results:"]
    for item in results:
        lines.append(
            f"  [{item.type.value}] {item.title} "
            f"(confidence={item.confidence:.2f}, id={item.id})"
        )
        lines.append(f"    {item.description[:150]}")
    return _result("\n".join(lines))


@_tool(
    "kb_get_item",
    "Get a specific knowledge base item by ID.",
    {
        "type": "object",
        "properties": {
            "item_id": {"type": "string", "description": "Knowledge base item ID"},
        },
        "required": ["item_id"],
    },
)
async def kb_get_item(item_id: str) -> Dict[str, Any]:
    from knowledge_base import kb
    item = kb.get_knowledge_item(item_id)
    if item is None:
        return _error(f"Item not found: {item_id}")
    import json as _json
    data = {
        "id": item.id,
        "type": item.type.value,
        "title": item.title,
        "description": item.description,
        "confidence": item.confidence,
        "tags": item.tags,
        "source_agent": item.source_agent,
        "created_at": item.created_at,
    }
    return _result(_json.dumps(data, indent=2))


@_tool(
    "kb_statistics",
    "Get overall statistics about the knowledge base.",
    {"type": "object", "properties": {}},
)
async def kb_statistics() -> Dict[str, Any]:
    from knowledge_base import kb
    import json as _json
    stats = kb.get_statistics()
    return _result(_json.dumps(stats, indent=2))


@_tool(
    "kb_link_items",
    "Create a relationship link between two knowledge base items.",
    {
        "type": "object",
        "properties": {
            "source_id": {"type": "string", "description": "ID of the source item"},
            "target_id": {"type": "string", "description": "ID of the target item"},
            "relationship": {"type": "string", "description": "Relationship type (e.g. 'supports', 'contradicts', 'tests', 'derived_from')"},
        },
        "required": ["source_id", "target_id", "relationship"],
    },
)
async def kb_link_items(source_id: str, target_id: str, relationship: str) -> Dict[str, Any]:
    from knowledge_base import kb
    try:
        kb.link_items(source_id, target_id, relationship)
        return _result(f"Linked {source_id} --[{relationship}]--> {target_id}")
    except Exception as e:
        return _error(f"Failed to list missions: {e}")


@_tool(
    "re_llm_status",
    "Check LLM provider configuration: which provider is active, model, API key status.",
    {"type": "object", "properties": {}},
)
async def llm_status() -> Dict[str, Any]:
    import json as _json
    from providers import get_active_provider, PROVIDERS, migrate_legacy_env
    migrate_legacy_env()
    active = get_active_provider()
    info = {
        "active_provider": active.name if active else None,
        "active_model": active.default_model if active else None,
        "all_providers": {},
    }
    for name, prov in PROVIDERS.items():
        info["all_providers"][name] = {
            "display_name": prov.display_name,
            "has_key": prov.key_is_set(),
            "requires_api_key": prov.requires_api_key,
            "default_model": prov.default_model,
        }
    if active and active.name == "ollama":
        info["ollama_running"] = active.ollama_is_running()
    return _result(_json.dumps(info, indent=2))


# ---------------------------------------------------------------------------
# Debate tools
# ---------------------------------------------------------------------------

@_tool(
    "re_debate",
    "Run a structured multi-agent debate to resolve conflicting analysis findings.",
    {
        "type": "object",
        "properties": {
            "topic": {"type": "string", "description": "Debate topic or question"},
            "assertions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "assertion": {"type": "string"},
                        "agent_id": {"type": "string"},
                        "agent_name": {"type": "string"},
                        "agent_type": {"type": "string"},
                        "context": {"type": "string"},
                    },
                    "required": ["assertion", "agent_id"],
                },
                "description": "List of assertions from different agents (minimum 2)",
            },
            "max_rounds": {"type": "integer", "description": "Max debate rounds (default 3)", "default": 3},
        },
        "required": ["topic", "assertions"],
    },
)
async def debate(
    topic: str,
    assertions: List[Dict[str, Any]],
    max_rounds: int = 3,
) -> Dict[str, Any]:
    if len(assertions) < 2:
        return _error("Debate requires at least 2 assertions")
    from debate import MultiAgentDebate
    import json as _json
    db = MultiAgentDebate(llm_client=None)
    result = db.run_debate_offline(topic=topic, assertions=assertions)
    return _result(_json.dumps(result.to_dict(), indent=2))


# ---------------------------------------------------------------------------
# Setup & configuration tools
# ---------------------------------------------------------------------------

@_tool(
    "re_setup_status",
    "Check setup status: providers, installed RE tools, and .env configuration.",
    {"type": "object", "properties": {}},
)
async def setup_status() -> Dict[str, Any]:
    import json as _json
    from providers import PROVIDERS, detect_tools, get_active_provider, migrate_legacy_env
    migrate_legacy_env()
    active = get_active_provider()
    tools = detect_tools()
    env_path = Path(PROJECT_ROOT) / ".env"
    info = {
        "providers": {
            name: {
                "display_name": prov.display_name,
                "has_key": prov.key_is_set(),
                "requires_api_key": prov.requires_api_key,
            }
            for name, prov in PROVIDERS.items()
        },
        "active_provider": active.name if active else None,
        "tools": {t["name"]: t["installed"] for t in tools},
        "env_exists": env_path.exists(),
    }
    return _result(_json.dumps(info, indent=2))


@_tool(
    "re_validate_api_key",
    "Validate an API key for a specific LLM provider.",
    {
        "type": "object",
        "properties": {
            "provider": {"type": "string", "description": "Provider name (e.g. openai, anthropic)"},
            "api_key": {"type": "string", "description": "API key to validate"},
        },
        "required": ["provider"],
    },
)
async def validate_api_key(provider: str, api_key: str = "") -> Dict[str, Any]:
    from setup_wizard import validate_api_key as _validate
    ok, msg = await asyncio.get_event_loop().run_in_executor(None, _validate, provider, api_key)
    status = "valid" if ok else "invalid"
    return _result(f"Provider '{provider}' key: {status}. {msg}")


@_tool(
    "re_setup_provider",
    "Write provider configuration (API key, model) to the .env file.",
    {
        "type": "object",
        "properties": {
            "provider": {"type": "string", "description": "Provider name (e.g. openai, anthropic, ollama)"},
            "api_key": {"type": "string", "description": "API key (not needed for ollama)"},
            "model": {"type": "string", "description": "Model override (optional)"},
        },
        "required": ["provider"],
    },
)
async def setup_provider(provider: str, api_key: str = "", model: str = "") -> Dict[str, Any]:
    from providers import PROVIDERS
    prov = PROVIDERS.get(provider)
    if prov is None:
        return _error(f"Unknown provider: {provider}")
    env_path = Path(PROJECT_ROOT) / ".env"
    lines = []
    if env_path.exists():
        lines = env_path.read_text().splitlines()
    # Remove old provider entries
    lines = [l for l in lines if not l.startswith("LLM_PROVIDER=") and not l.startswith(f"{prov.api_key_env}=") and not l.startswith("LLM_MODEL=")]
    lines.append(f"LLM_PROVIDER={provider}")
    if api_key:
        lines.append(f"{prov.api_key_env}={api_key}")
    if model:
        lines.append(f"LLM_MODEL={model}")
    env_path.write_text("\n".join(lines) + "\n")
    return _result(f"Provider '{provider}' configured in .env")


# ---------------------------------------------------------------------------
# Monitoring tools
# ---------------------------------------------------------------------------

@_tool(
    "re_metrics",
    "View system metrics in JSON or Prometheus exposition format.",
    {
        "type": "object",
        "properties": {
            "format": {"type": "string", "description": "Output format: 'json' or 'prometheus' (default json)", "default": "json"},
        },
    },
)
async def metrics(format: str = "json") -> Dict[str, Any]:
    from monitoring import get_metrics
    mc = get_metrics()
    if format == "prometheus":
        return _result(mc.expose_prometheus())
    return _result(json.dumps(mc.expose_json(), indent=2))


@_tool(
    "re_system_status",
    "Get full orchestrator system status: agents, missions, debates, re-analyses, budgets.",
    {"type": "object", "properties": {}},
)
async def system_status() -> Dict[str, Any]:
    from mcp._shared_orchestrator import get_shared_orchestrator
    orch = get_shared_orchestrator()
    return _result(json.dumps(orch.get_system_status(), indent=2))


# ---------------------------------------------------------------------------
# Orchestration tools (missions)
# ---------------------------------------------------------------------------

@_tool(
    "re_create_mission",
    "Create a new research mission to track analysis work. Optionally specify a file_path to analyze and objectives for the mission agents to complete.",
    {
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "Mission title"},
            "description": {"type": "string", "description": "Mission description"},
            "tags": {"type": "array", "items": {"type": "string"}, "description": "Tags"},
            "file_path": {"type": "string", "description": "Path to the target file to analyze (stored in mission metadata)"},
            "objectives": {
                "type": "array",
                "description": "List of objectives for the mission. Each has: title, description, priority (critical/high/medium/low), assigned_agents (list of agent types: binary, firmware, network, cpu, kernel), dependencies (list of objective titles that must complete first)",
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "Objective title"},
                        "description": {"type": "string", "description": "What to investigate"},
                        "priority": {"type": "string", "enum": ["critical", "high", "medium", "low"], "default": "medium"},
                        "assigned_agents": {"type": "array", "items": {"type": "string"}, "description": "Agent types: binary, firmware, network, cpu, kernel"},
                        "dependencies": {"type": "array", "items": {"type": "string"}, "description": "Titles of objectives that must complete first"},
                    },
                    "required": ["title", "description"],
                },
            },
        },
        "required": ["title", "description"],
    },
)
async def create_mission(
    title: str,
    description: str,
    tags: Optional[List[str]] = None,
    file_path: Optional[str] = None,
    objectives: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    from mcp._shared_orchestrator import get_shared_orchestrator
    from orchestrator import ResearchObjective, Priority as ObjPriority

    orch = get_shared_orchestrator()

    metadata = {}
    if file_path:
        metadata["file_path"] = file_path

    mission_id = orch.create_mission(
        title=title,
        description=description,
        tags=tags or [],
        metadata=metadata,
    )

    # Add objectives if provided
    if objectives:
        obj_id_map = {}  # title → id
        for obj_def in objectives:
            obj_id = str(uuid.uuid4())
            obj_id_map[obj_def["title"]] = obj_id

        for obj_def in objectives:
            priority_str = obj_def.get("priority", "medium").lower()
            priority_map = {
                "critical": ObjPriority.CRITICAL,
                "high": ObjPriority.HIGH,
                "medium": ObjPriority.MEDIUM,
                "low": ObjPriority.LOW,
            }
            priority = priority_map.get(priority_str, ObjPriority.MEDIUM)

            # Resolve dependency titles to IDs
            dep_titles = obj_def.get("dependencies", [])
            dep_ids = [obj_id_map[t] for t in dep_titles if t in obj_id_map]

            obj = ResearchObjective(
                id=obj_id_map[obj_def["title"]],
                title=obj_def["title"],
                description=obj_def["description"],
                priority=priority,
                status="pending",
                assigned_agents=obj_def.get("assigned_agents", []),
                dependencies=dep_ids,
            )
            orch.add_objective_to_mission(mission_id, obj)

    mission = orch.get_mission_status(mission_id)
    obj_count = len(mission.objectives) if mission else 0
    lines = [f"Mission created with ID: {mission_id}"]
    if file_path:
        lines.append(f"Target file: {file_path}")
    if obj_count:
        lines.append(f"Objectives: {obj_count}")
        for obj in mission.objectives:
            agents_str = ", ".join(obj.assigned_agents) if obj.assigned_agents else "auto-detect"
            lines.append(f"  - [{obj.priority.name}] {obj.title} (agents: {agents_str})")
    lines.append(f"Use re_mission_update(mission_id=\"{mission_id}\", action=\"start\") to begin execution.")
    return _result("\n".join(lines))


@_tool(
    "re_list_missions",
    "List all research missions with their status.",
    {"type": "object", "properties": {}},
)
async def list_missions() -> Dict[str, Any]:
    from mcp._shared_orchestrator import get_shared_orchestrator
    orch = get_shared_orchestrator()
    missions = orch.list_missions()
    if not missions:
        return _result("No missions found.")
    lines = [f"Found {len(missions)} mission(s):"]
    for m in missions:
        lines.append(f"  [{m.status.value}] {m.title} (id={m.id})")
        lines.append(f"    {m.description[:120]}")
    return _result("\n".join(lines))


# ---------------------------------------------------------------------------
# Dashboard tools
# ---------------------------------------------------------------------------

@_tool(
    "re_web_dashboard",
    "Check if the web dashboard is running and get its URL.",
    {"type": "object", "properties": {}},
)
async def web_dashboard() -> Dict[str, Any]:
    import socket
    from config.settings import WEB_PORT
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        result = sock.connect_ex(("localhost", WEB_PORT))
        running = result == 0
    finally:
        sock.close()
    status = "running" if running else "not running"
    return _result(f"Web dashboard: {status} at http://localhost:{WEB_PORT}")


# ---------------------------------------------------------------------------
# Analysis agent tools
# ---------------------------------------------------------------------------

@_tool(
    "re_analyze",
    "Run a full analysis agent (binary, firmware, network, cpu, kernel) on a target file.",
    {
        "type": "object",
        "properties": {
            "agent_type": {
                "type": "string",
                "description": "Agent to run: binary, firmware, network, cpu, kernel",
                "enum": ["binary", "firmware", "network", "cpu", "kernel"],
            },
            "file_path": {"type": "string", "description": "Path to the target file to analyze"},
            "analysis_type": {"type": "string", "description": "Analysis depth: basic, full, quick (default basic)", "default": "basic"},
        },
        "required": ["agent_type", "file_path"],
    },
)
async def analyze(agent_type: str, file_path: str, analysis_type: str = "basic") -> Dict[str, Any]:
    from agents.base_agent import Task
    agent_map = {
        "binary": ("binary_analysis_agent", "BinaryAnalysisAgent"),
        "firmware": ("firmware_analysis_agent", "FirmwareAnalysisAgent"),
        "network": ("networking_agent", "NetworkingAgent"),
        "cpu": ("cpu_analysis_agent", "CpuAnalysisAgent"),
        "kernel": ("os_kernel_agent", "OsKernelAgent"),
    }
    if agent_type not in agent_map:
        return _error(f"Unknown agent type: {agent_type}. Use: {list(agent_map.keys())}")

    mod_name, class_name = agent_map[agent_type]
    try:
        mod = __import__(f"agents.{mod_name}", fromlist=[class_name])
        agent_cls = getattr(mod, class_name)
    except (ImportError, AttributeError) as e:
        return _error(f"Failed to load agent {agent_type}: {e}")

    agent = agent_cls(f"mcp_{agent_type}")
    try:
        await agent.initialize()
        task = Task(
            task_id=f"mcp_{agent_type}_{uuid.uuid4().hex[:8]}",
            description=f"MCP-initiated {agent_type} analysis of {file_path}",
            agent_type=f"{agent_type}_analysis",
            parameters={"file_path": file_path, "analysis_type": analysis_type},
        )
        result = await agent.execute_task(task)
        d = result.to_dict()
        d["reasoning_trace"] = result.reasoning_trace
        d["tools_used"] = result.tools_used
        d["confidence_score"] = result.confidence_score
        return _result(json.dumps(d, indent=2, default=str))
    except Exception as e:
        return _error(f"Analysis failed: {e}")
    finally:
        try:
            await agent.cleanup()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Mission management tools
# ---------------------------------------------------------------------------

@_tool(
    "re_mission_update",
    "Update a mission's status: start, pause, resume, or cancel. Starting a mission spawns a background task that executes all objectives with the appropriate agents. Use re_mission_detail to poll progress.",
    {
        "type": "object",
        "properties": {
            "mission_id": {"type": "string", "description": "Mission ID"},
            "action": {"type": "string", "description": "Action: start, pause, resume, cancel", "enum": ["start", "pause", "resume", "cancel"]},
        },
        "required": ["mission_id", "action"],
    },
)
async def mission_update(mission_id: str, action: str) -> Dict[str, Any]:
    from mcp._shared_orchestrator import get_shared_orchestrator
    orch = get_shared_orchestrator()
    try:
        if action == "start":
            await orch.start_mission(mission_id)
            mission = orch.get_mission_status(mission_id)
            objectives_count = len(mission.objectives) if mission else 0
            bg_running = mission_id in orch._mission_execution_tasks
            lines = [
                f"Mission started (status: {mission.status.value})",
                f"Objectives: {objectives_count}",
                f"Background execution: {'running' if bg_running else 'completed'}",
            ]
            if objectives_count > 0:
                for obj in mission.objectives:
                    lines.append(f"  - {obj.title} (status: {obj.status})")
            return _result("\n".join(lines))
        elif action == "pause":
            await orch.pause_mission(mission_id)
        elif action == "resume":
            await orch.resume_mission(mission_id)
        elif action == "cancel":
            await orch.cancel_mission(mission_id)
        else:
            return _error(f"Unknown action: {action}. Use: start, pause, resume, cancel")
        mission = orch.get_mission_status(mission_id)
        action_word = {"start": "started", "pause": "paused", "resume": "resumed", "cancel": "cancelled"}
        return _result(f"Mission {action_word[action]}. Status: {mission.status.value}")
    except Exception as e:
        return _error(f"Failed to {action} mission: {e}")


@_tool(
    "re_mission_detail",
    "Get detailed status of a specific mission including objectives, agents, and execution metadata.",
    {
        "type": "object",
        "properties": {
            "mission_id": {"type": "string", "description": "Mission ID"},
        },
        "required": ["mission_id"],
    },
)
async def mission_detail(mission_id: str) -> Dict[str, Any]:
    from mcp._shared_orchestrator import get_shared_orchestrator
    orch = get_shared_orchestrator()
    mission = orch.get_mission_status(mission_id)
    if mission is None:
        return _error(f"Mission not found: {mission_id}")
    objectives = []
    for o in mission.objectives:
        obj_data = {
            "id": o.id,
            "title": o.title,
            "description": o.description,
            "status": o.status,
            "priority": o.priority.name if hasattr(o.priority, 'name') else str(o.priority),
            "assigned_agents": o.assigned_agents,
            "dependencies": o.dependencies,
            "results": o.results,
        }
        objectives.append(obj_data)
    data = {
        "id": mission.id,
        "title": mission.title,
        "description": mission.description,
        "status": mission.status.value,
        "tags": mission.tags,
        "metadata": mission.metadata,
        "objectives": objectives,
        "agents": list(mission.agents.keys()),
        "start_time": mission.start_time,
        "end_time": mission.end_time,
        "is_running": mission_id in orch._mission_execution_tasks,
    }
    return _result(json.dumps(data, indent=2))


@_tool(
    "re_mission_progress",
    "Get real-time progress of a running or completed mission: tasks completed/failed, objective statuses, debate count.",
    {
        "type": "object",
        "properties": {
            "mission_id": {"type": "string", "description": "Mission ID"},
        },
        "required": ["mission_id"],
    },
)
async def mission_progress(mission_id: str) -> Dict[str, Any]:
    from mcp._shared_orchestrator import get_shared_orchestrator
    orch = get_shared_orchestrator()
    try:
        progress = await orch.get_mission_progress(mission_id)
        if "error" in progress:
            return _error(progress["error"])
        return _result(json.dumps(progress, indent=2))
    except Exception as e:
        return _error(f"Failed to get mission progress: {e}")


# ---------------------------------------------------------------------------
# Token budget tools
# ---------------------------------------------------------------------------

@_tool(
    "re_token_budget_status",
    "View token budget usage and limits for agents and missions.",
    {"type": "object", "properties": {}},
)
async def token_budget_status() -> Dict[str, Any]:
    from mcp._shared_orchestrator import get_shared_orchestrator
    orch = get_shared_orchestrator()
    if orch._token_budget_manager is None:
        return _result("Token budget manager is not enabled. Set TOKEN_BUDGET_ENABLED=true in .env")
    mgr = orch._token_budget_manager
    mission_id = orch.active_mission.id if orch.active_mission else None
    summary = mgr.get_usage_summary(mission_id=mission_id)
    return _result(json.dumps(summary, indent=2, default=str))


# ---------------------------------------------------------------------------
# Knowledge base extended tools
# ---------------------------------------------------------------------------

@_tool(
    "kb_add_experiment",
    "Store a structured experiment record in the knowledge base.",
    {
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "Experiment title"},
            "description": {"type": "string", "description": "What was tested"},
            "hypothesis_id": {"type": "string", "description": "ID of the hypothesis being tested"},
            "setup": {"type": "string", "description": "Test setup and conditions"},
            "procedure": {"type": "string", "description": "Steps performed"},
            "results": {"type": "string", "description": "Observed results"},
            "conclusion": {"type": "string", "description": "Conclusion drawn"},
            "tags": {"type": "array", "items": {"type": "string"}, "description": "Tags"},
            "source_agent": {"type": "string", "description": "Agent that ran this experiment"},
        },
        "required": ["title", "description"],
    },
)
async def kb_add_experiment(
    title: str,
    description: str,
    hypothesis_id: str = "",
    setup: str = "",
    procedure: str = "",
    results: str = "",
    conclusion: str = "",
    tags: Optional[List[str]] = None,
    source_agent: Optional[str] = None,
) -> Dict[str, Any]:
    from knowledge_base import add_experiment
    exp_id = add_experiment(
        title=title,
        description=description,
        confidence=0.7,
        hypothesis_id=hypothesis_id,
        setup=setup,
        procedure=procedure,
        results=results,
        conclusion=conclusion,
        tags=tags or [],
        source_agent=source_agent or PLATFORM,
    )
    return _result(f"Experiment stored with ID: {exp_id}")


@_tool(
    "kb_update_item",
    "Update an existing knowledge base item's description, confidence, or tags.",
    {
        "type": "object",
        "properties": {
            "item_id": {"type": "string", "description": "ID of the item to update"},
            "title": {"type": "string", "description": "New title (optional)"},
            "description": {"type": "string", "description": "New description (optional)"},
            "confidence": {"type": "number", "description": "New confidence 0.0-1.0 (optional)"},
            "tags": {"type": "array", "items": {"type": "string"}, "description": "New tags (optional)"},
        },
        "required": ["item_id"],
    },
)
async def kb_update_item(
    item_id: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    confidence: Optional[float] = None,
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    from knowledge_base import kb
    item = kb.get_knowledge_item(item_id)
    if item is None:
        return _error(f"Item not found: {item_id}")
    if title is not None:
        item.title = title
    if description is not None:
        item.description = description
    if confidence is not None:
        item.confidence = confidence
    if tags is not None:
        item.tags = tags
    kb.update_knowledge_item(item)
    return _result(f"Item {item_id} updated successfully")


@_tool(
    "kb_delete_item",
    "Delete a knowledge base item by ID.",
    {
        "type": "object",
        "properties": {
            "item_id": {"type": "string", "description": "ID of the item to delete"},
        },
        "required": ["item_id"],
    },
)
async def kb_delete_item(item_id: str) -> Dict[str, Any]:
    from knowledge_base import kb
    item = kb.get_knowledge_item(item_id)
    if item is None:
        return _error(f"Item not found: {item_id}")
    kb.delete_knowledge_item(item_id)
    return _result(f"Item {item_id} deleted successfully")


# ---------------------------------------------------------------------------
# Ghidra deep analysis tools
# ---------------------------------------------------------------------------

@_tool(
    "re_ghidra_decompile",
    "Decompile a specific function using Ghidra headless analysis.",
    {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Path to the binary"},
            "address": {"type": "string", "description": "Function address (e.g. '0x00401000')"},
        },
        "required": ["file_path", "address"],
    },
)
async def ghidra_decompile(file_path: str, address: str) -> Dict[str, Any]:
    from mcp.ghidra_server import _run_ghidra_script
    result = await _run_ghidra_script("decompile.py", file_path, extra_args={"GHIDRA_DECOMP_ADDR": address})
    return _result(json.dumps(result, indent=2, default=str))


@_tool(
    "re_ghidra_functions",
    "List all functions in a binary using Ghidra.",
    {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Path to the binary"},
        },
        "required": ["file_path"],
    },
)
async def ghidra_functions(file_path: str) -> Dict[str, Any]:
    from mcp.ghidra_server import _run_ghidra_script
    result = await _run_ghidra_script("list_functions.py", file_path)
    return _result(json.dumps(result, indent=2, default=str))


@_tool(
    "re_ghidra_xrefs",
    "Get cross-references to/from a specific address using Ghidra.",
    {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Path to the binary"},
            "address": {"type": "string", "description": "Address to analyze (e.g. '0x00401000')"},
        },
        "required": ["file_path", "address"],
    },
)
async def ghidra_xrefs(file_path: str, address: str) -> Dict[str, Any]:
    from mcp.ghidra_server import _run_ghidra_script
    result = await _run_ghidra_script("get_xrefs.py", file_path, extra_args={"GHIDRA_XREF_ADDR": address})
    return _result(json.dumps(result, indent=2, default=str))


@_tool(
    "re_ghidra_imports",
    "Get the import table of a binary using Ghidra.",
    {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Path to the binary"},
        },
        "required": ["file_path"],
    },
)
async def ghidra_imports(file_path: str) -> Dict[str, Any]:
    from mcp.ghidra_server import _run_ghidra_script
    result = await _run_ghidra_script("get_imports.py", file_path)
    return _result(json.dumps(result, indent=2, default=str))


# ---------------------------------------------------------------------------
# GDB deep analysis tools
# ---------------------------------------------------------------------------

@_tool(
    "re_gdb_symbols",
    "Get the symbol table of a binary (nm-style or readelf --symbols).",
    {
        "type": "object",
        "properties": {
            "binary_path": {"type": "string", "description": "Path to the binary"},
            "use_nm": {"type": "boolean", "description": "Use nm instead of readelf (default false)", "default": False},
            "symbol_type": {"type": "string", "description": "Filter by symbol type (t=text, d=data, b=bss)"},
        },
        "required": ["binary_path"],
    },
)
async def gdb_symbols(binary_path: str, use_nm: bool = False, symbol_type: Optional[str] = None) -> Dict[str, Any]:
    if use_nm:
        cmd = ["nm"]
        if symbol_type:
            cmd.extend(["-t", symbol_type])
        cmd.append(binary_path)
        r = await run_tool(cmd, timeout=30)
    else:
        r = await run_readelf(binary_path, ["--symbols"])
    return _result(_tool_result_to_text(r))


@_tool(
    "re_gdb_registers",
    "Get CPU register values by running GDB on a binary.",
    {
        "type": "object",
        "properties": {
            "binary_path": {"type": "string", "description": "Path to the binary"},
            "extra_commands": {"type": "array", "items": {"type": "string"}, "description": "Additional GDB commands before 'info registers'"},
        },
        "required": ["binary_path"],
    },
)
async def gdb_registers(binary_path: str, extra_commands: Optional[List[str]] = None) -> Dict[str, Any]:
    commands = (extra_commands or []) + ["info registers"]
    r = await run_gdb(binary_path, commands=commands)
    return _result(_tool_result_to_text(r))


@_tool(
    "re_gdb_backtrace",
    "Get a stack backtrace by running GDB on a binary.",
    {
        "type": "object",
        "properties": {
            "binary_path": {"type": "string", "description": "Path to the binary"},
            "pre_commands": {"type": "array", "items": {"type": "string"}, "description": "GDB commands to run before 'bt' (e.g. breakpoints, run args)"},
        },
        "required": ["binary_path"],
    },
)
async def gdb_backtrace(binary_path: str, pre_commands: Optional[List[str]] = None) -> Dict[str, Any]:
    commands = (pre_commands or []) + ["bt"]
    r = await run_gdb(binary_path, commands=commands)
    return _result(_tool_result_to_text(r))


@_tool(
    "re_gdb_memory",
    "Inspect memory at an address using GDB's 'x' command.",
    {
        "type": "object",
        "properties": {
            "binary_path": {"type": "string", "description": "Path to the binary"},
            "address": {"type": "string", "description": "Memory address (e.g. '0x7fffffffe000')"},
            "format": {"type": "string", "description": "Display format: x=hex, d=decimal, i=instruction, c=char (default x)", "default": "x"},
            "unit": {"type": "string", "description": "Unit size: b=byte, h=half, w=word, g=giant (default w)", "default": "w"},
            "count": {"type": "integer", "description": "Number of units to display (default 16)", "default": 16},
        },
        "required": ["binary_path", "address"],
    },
)
async def gdb_memory(
    binary_path: str,
    address: str,
    format: str = "x",
    unit: str = "w",
    count: int = 16,
) -> Dict[str, Any]:
    x_cmd = f"x/{count}{format}{unit} {address}"
    r = await run_gdb(binary_path, commands=[x_cmd])
    return _result(_tool_result_to_text(r))


# ---------------------------------------------------------------------------
# RAG semantic search tools
# ---------------------------------------------------------------------------

@_tool(
    "re_rag_search",
    "Semantic search across all analysis results using embeddings.",
    {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Natural language search query"},
            "top_k": {"type": "integer", "description": "Number of results (default 5)", "default": 5},
        },
        "required": ["query"],
    },
)
async def rag_search(query: str, top_k: int = 5) -> Dict[str, Any]:
    from rag_pipeline import RAGPipeline
    pipeline = RAGPipeline()
    results = await pipeline.retrieve_similar(query, top_k=top_k)
    if not results:
        return _result("No similar results found.")
    lines = [f"Found {len(results)} similar results:"]
    for entry in results:
        item = entry["item"]
        lines.append(f"  [{item.type.value}] {item.title} (score={entry['score']}, confidence={item.confidence:.2f})")
        lines.append(f"    {item.description[:200]}")
    return _result("\n".join(lines))


@_tool(
    "re_rag_context",
    "Build an LLM-ready context string from the most relevant KB items for a query.",
    {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "What you want context about"},
            "max_tokens": {"type": "integer", "description": "Max approximate tokens (default 3000)", "default": 3000},
        },
        "required": ["query"],
    },
)
async def rag_context(query: str, max_tokens: int = 3000) -> Dict[str, Any]:
    from rag_pipeline import RAGPipeline
    pipeline = RAGPipeline()
    context = await pipeline.build_context_for_analysis(query, max_tokens=max_tokens)
    return _result(context)


# ---------------------------------------------------------------------------
# Config tools
# ---------------------------------------------------------------------------

@_tool(
    "re_config_get",
    "View current configuration values (token budgets, embeddings, RAG, monitoring, etc.).",
    {"type": "object", "properties": {}},
)
async def config_get() -> Dict[str, Any]:
    from config import settings
    config_keys = [
        "TOKEN_BUDGET_ENABLED", "TOKEN_GLOBAL_LIMIT", "TOKEN_AGENT_LIMIT",
        "TOKEN_MISSION_LIMIT", "TOKEN_GLOBAL_RPM", "TOKEN_AGENT_RPM",
        "TOKEN_WARNING_THRESHOLD",
        "EMBEDDING_PROVIDER",
        "CRITIQUE_ENABLED", "CRITIQUE_CONFIDENCE_THRESHOLD",
        "KNOWLEDGE_EXTRACTION_ENABLED",
        "CONFIDENCE_TOOL_WEIGHT", "CONFIDENCE_LLM_WEIGHT", "CONFIDENCE_CRITIQUE_WEIGHT",
        "MONITORING_ENABLED", "METRICS_PORT", "METRICS_PATH",
        "PROMETHEUS_ENABLED", "GRAFANA_ENABLED", "GRAFANA_PORT",
        "REANALYZE_MAX_ATTEMPTS",
        "WEB_PORT", "WEB_HOST",
    ]
    config = {}
    for key in config_keys:
        val = getattr(settings, key, None)
        if val is not None:
            config[key] = val
    return _result(json.dumps(config, indent=2))


# ===========================================================================
# MCP Protocol handler
# ===========================================================================

def _build_tools_list() -> List[Dict[str, Any]]:
    """Return tool definitions without internal _handler."""
    return [
        {k: v for k, v in t.items() if k != "_handler"}
        for t in TOOLS
    ]


def _find_handler(name: str):
    """Find the handler function for a tool name."""
    for t in TOOLS:
        if t["name"] == name:
            return t["_handler"]
    return None


async def handle_message(msg: Dict[str, Any]) -> Dict[str, Any]:
    """Handle a single JSON-RPC message and return a response."""
    msg_id = msg.get("id")
    method = msg.get("method", "")
    params = msg.get("params", {})

    # --- initialize ---
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "re-lab-mcp",
                    "version": "1.0.0",
                },
            },
        }

    # --- notifications/initialized ---
    if method == "notifications/initialized":
        return None  # no response needed

    # --- tools/list ---
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": _build_tools_list()},
        }

    # --- tools/call ---
    if method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        handler = _find_handler(tool_name)
        if handler is None:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}],
                    "isError": True,
                },
            }

        try:
            result = await handler(**arguments)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": result,
            }
        except Exception as e:
            tb = traceback.format_exc()
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": f"Error executing {tool_name}: {e}\n\n{tb}"}],
                    "isError": True,
                },
            }

    # --- ping ---
    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    # --- unknown method ---
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


# ===========================================================================
# Main loop (stdio transport — newline-delimited JSON per MCP spec)
# ===========================================================================

def _read_stdin_forever(queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
    """Read newline-delimited JSON messages from stdin, enqueue parsed messages."""
    stdin = sys.stdin.buffer
    while True:
        try:
            raw = stdin.readline()
            if not raw:
                loop.call_soon_threadsafe(queue.put_nowait, None)
                return
            line = raw.decode("utf-8").strip()
            if not line:
                continue
            msg = json.loads(line)
            loop.call_soon_threadsafe(queue.put_nowait, msg)
        except EOFError:
            loop.call_soon_threadsafe(queue.put_nowait, None)
            return
        except Exception as e:
            logger.error(f"stdin reader error: {e}")
            loop.call_soon_threadsafe(queue.put_nowait, None)
            return


def _write_response(response: Dict[str, Any]):
    """Write a JSON-RPC response to stdout as newline-delimited JSON."""
    body = json.dumps(response)
    sys.stdout.buffer.write((body + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()


async def main():
    """Run the MCP server over stdin/stdout."""
    logging.basicConfig(
        level=logging.WARNING,
        format="%(name)s: %(message)s",
        stream=sys.stderr,
    )

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()

    # Start stdin reader in a daemon thread
    reader_thread = threading.Thread(target=_read_stdin_forever, args=(queue, loop), daemon=True)
    reader_thread.start()

    while True:
        msg = await queue.get()
        if msg is None:
            break  # EOF

        try:
            response = await handle_message(msg)
            if response is not None:
                _write_response(response)
        except Exception as e:
            logger.error(f"Error handling message: {e}", exc_info=True)
            try:
                _write_response({
                    "jsonrpc": "2.0",
                    "id": msg.get("id"),
                    "error": {"code": -32603, "message": str(e)},
                })
            except Exception:
                pass


if __name__ == "__main__":
    asyncio.run(main())
