"""
Ghidra MCP Server
Real integration with Ghidra headless analysis via analyzeHeadless.
"""

import asyncio
import json
import logging
import os
import tempfile
from typing import Dict, Any, List, Optional

from mcp.base_mcp import BaseMCPServer, BaseMCPClient, MCPError
from agents.tool_runner import run_tool, run_ghidra_headless, ToolResult
from config.settings import TOOL_PATHS, GHIDRA_PROJECTS_DIR

logger = logging.getLogger("mcp.ghidra")

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghidra_scripts")

GHIDRA_BIN = TOOL_PATHS.get("ghidra", "/opt/ghidra/support/analyzeHeadless")


def _parse_ghidra_output(output: str) -> Any:
    """Extract JSON payload from Ghidra headless script output.

    Scripts print GHIDRA_OUTPUT_START / GHIDRA_OUTPUT_END markers around JSON.
    """
    start_marker = "GHIDRA_OUTPUT_START"
    end_marker = "GHIDRA_OUTPUT_END"
    try:
        start_idx = output.index(start_marker) + len(start_marker)
        end_idx = output.index(end_marker)
        payload = output[start_idx:end_idx].strip()
        return json.loads(payload)
    except (ValueError, json.JSONDecodeError) as e:
        logger.debug(f"Could not parse Ghidra output markers: {e}")
        return output


async def _run_ghidra_script(
    script_name: str,
    file_path: str,
    extra_args: Optional[Dict[str, str]] = None,
    timeout: int = 300,
) -> Dict[str, Any]:
    """Run a single Ghidra headless script and return parsed JSON output."""
    if not os.path.isfile(GHIDRA_BIN):
        return {
            "error": (
                f"Ghidra not found at {GHIDRA_BIN}. "
                "Install Ghidra or set GHIDRA_PATH environment variable."
            ),
            "ghidra_path": GHIDRA_BIN,
        }

    script_path = os.path.join(SCRIPTS_DIR, script_name)
    if not os.path.isfile(script_path):
        return {"error": f"Script not found: {script_path}"}

    with tempfile.TemporaryDirectory(prefix="ghidra_mcp_") as tmp_dir:
        project_dir = str(GHIDRA_PROJECTS_DIR)
        os.makedirs(project_dir, exist_ok=True)

        env = os.environ.copy()
        if extra_args:
            for key, val in extra_args.items():
                env[key] = val

        cmd = [
            GHIDRA_BIN,
            project_dir,
            f"re_lab_{os.path.basename(file_path)}",
            "-import", file_path,
            "-postScript", script_path,
            "-deleteProject",
        ]

        result = await run_tool(cmd, timeout=timeout, env=env)

        if not result.tool_available:
            return {
                "error": (
                    "Ghidra analyzeHeadless not found on the system. "
                    "Install Ghidra and ensure the binary is on PATH or set GHIDRA_PATH."
                ),
                "stderr": result.stderr,
            }

        if result.returncode != 0:
            logger.warning(f"Ghidra script {script_name} returned code {result.returncode}")
            # Still try to parse stdout — scripts may output before a non-zero exit
            parsed = _parse_ghidra_output(result.stdout)
            if isinstance(parsed, str):
                return {
                    "error": f"Ghidra returned non-zero exit code {result.returncode}",
                    "stderr": result.stderr,
                    "stdout": result.stdout,
                }
            return {"result": parsed, "warnings": result.stderr}

        return {"result": _parse_ghidra_output(result.stdout)}


async def _run_ghidra_analyze_headless(
    file_path: str,
    scripts: Optional[List[str]] = None,
    timeout: int = 600,
) -> Dict[str, Any]:
    """Run analyzeHeadless with optional postScripts and return combined output."""
    if not os.path.isfile(GHIDRA_BIN):
        return {
            "error": (
                f"Ghidra not found at {GHIDRA_BIN}. "
                "Install Ghidra or set GHIDRA_PATH environment variable."
            ),
            "ghidra_path": GHIDRA_BIN,
        }

    with tempfile.TemporaryDirectory(prefix="ghidra_mcp_") as tmp_dir:
        project_dir = str(GHIDRA_PROJECTS_DIR)
        os.makedirs(project_dir, exist_ok=True)

        cmd = [
            GHIDRA_BIN,
            project_dir,
            f"re_lab_{os.path.basename(file_path)}",
            "-import", file_path,
            "-deleteProject",
        ]

        if scripts:
            cmd.extend(["-scriptPath", SCRIPTS_DIR])
            for s in scripts:
                cmd.extend(["-postScript", s])

        result = await run_tool(cmd, timeout=timeout)

        if not result.tool_available:
            return {
                "error": (
                    "Ghidra analyzeHeadless not found on the system. "
                    "Install Ghidra and ensure the binary is on PATH or set GHIDRA_PATH."
                ),
                "stderr": result.stderr,
            }

        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "result": _parse_ghidra_output(result.stdout),
        }


class GhidraMCPServer(BaseMCPServer):
    """MCP server wrapping Ghidra headless analysis capabilities."""

    def __init__(self, host: str = "localhost", port: int = 8001):
        super().__init__("ghidra", host, port)
        self._register_methods()

    def _register_methods(self):
        self.register_method("ping", self._ping)
        self.register_method("analyze_binary", self._analyze_binary)
        self.register_method("get_function", self._get_function)
        self.register_method("get_strings", self._get_strings)
        self.register_method("get_imports", self._get_imports)
        self.register_method("get_xrefs", self._get_xrefs)
        self.register_method("decompile", self._decompile)
        self.register_method("list_functions", self._list_functions)
        self.register_method("get_memory_map", self._get_memory_map)

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    async def _ping(self, params: Dict[str, Any]) -> bool:
        return True

    async def _analyze_binary(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Run Ghidra headless auto-analysis and extract structured results."""
        file_path = params.get("file_path")
        if not file_path:
            return {"error": "file_path is required"}
        if not os.path.isfile(file_path):
            return {"error": f"File not found: {file_path}"}

        self.logger.info(f"Analyzing binary with Ghidra: {file_path}")
        timeout = params.get("timeout", 600)

        result = await _run_ghidra_analyze_headless(
            file_path,
            scripts=["list_functions.py", "get_imports.py", "get_strings.py"],
            timeout=timeout,
        )

        if "error" in result:
            return result

        # When analyseHeadless runs multiple postScripts their outputs appear
        # sequentially in stdout.  Try to extract each JSON block.
        full_output = result.get("stdout", "")
        parsed_blocks = _extract_all_json_blocks(full_output)

        return {
            "file_path": file_path,
            "status": "completed" if result["returncode"] == 0 else "error",
            "functions": parsed_blocks.get("list_functions", []),
            "imports": parsed_blocks.get("get_imports", []),
            "strings": parsed_blocks.get("get_strings", []),
            "raw_output": full_output,
            "warnings": result.get("stderr", ""),
        }

    async def _get_function(self, params: Dict[str, Any]) -> Dict[str, Any]:
        address = params.get("address")
        file_path = params.get("file_path")
        if not address:
            return {"error": "address is required"}
        if not file_path:
            return {"error": "file_path is required"}
        if not os.path.isfile(file_path):
            return {"error": f"File not found: {file_path}"}

        self.logger.info(f"Getting function info at {address}")
        return await _run_ghidra_script(
            "get_function.py",
            file_path,
            extra_args={"GHIDRA_FUNC_ADDR": address},
            timeout=params.get("timeout", 300),
        )

    async def _get_strings(self, params: Dict[str, Any]) -> Dict[str, Any]:
        file_path = params.get("file_path")
        if not file_path:
            return {"error": "file_path is required"}
        if not os.path.isfile(file_path):
            return {"error": f"File not found: {file_path}"}

        self.logger.info(f"Extracting strings from {file_path}")
        return await _run_ghidra_script(
            "get_strings.py",
            file_path,
            timeout=params.get("timeout", 300),
        )

    async def _get_imports(self, params: Dict[str, Any]) -> Dict[str, Any]:
        file_path = params.get("file_path")
        if not file_path:
            return {"error": "file_path is required"}
        if not os.path.isfile(file_path):
            return {"error": f"File not found: {file_path}"}

        self.logger.info(f"Getting imports from {file_path}")
        return await _run_ghidra_script(
            "get_imports.py",
            file_path,
            timeout=params.get("timeout", 300),
        )

    async def _get_xrefs(self, params: Dict[str, Any]) -> Dict[str, Any]:
        address = params.get("address")
        file_path = params.get("file_path")
        if not address:
            return {"error": "address is required"}
        if not file_path:
            return {"error": "file_path is required"}
        if not os.path.isfile(file_path):
            return {"error": f"File not found: {file_path}"}

        self.logger.info(f"Getting xrefs for {address}")
        return await _run_ghidra_script(
            "get_xrefs.py",
            file_path,
            extra_args={"GHIDRA_XREF_ADDR": address},
            timeout=params.get("timeout", 300),
        )

    async def _decompile(self, params: Dict[str, Any]) -> Dict[str, Any]:
        address = params.get("address")
        file_path = params.get("file_path")
        if not address:
            return {"error": "address is required"}
        if not file_path:
            return {"error": "file_path is required"}
        if not os.path.isfile(file_path):
            return {"error": f"File not found: {file_path}"}

        self.logger.info(f"Decompiling function at {address}")
        return await _run_ghidra_script(
            "decompile.py",
            file_path,
            extra_args={"GHIDRA_DECOMP_ADDR": address},
            timeout=params.get("timeout", 300),
        )

    async def _list_functions(self, params: Dict[str, Any]) -> Dict[str, Any]:
        file_path = params.get("file_path")
        if not file_path:
            return {"error": "file_path is required"}
        if not os.path.isfile(file_path):
            return {"error": f"File not found: {file_path}"}

        self.logger.info(f"Listing functions in {file_path}")
        return await _run_ghidra_script(
            "list_functions.py",
            file_path,
            timeout=params.get("timeout", 300),
        )

    async def _get_memory_map(self, params: Dict[str, Any]) -> Dict[str, Any]:
        file_path = params.get("file_path")
        if not file_path:
            return {"error": "file_path is required"}
        if not os.path.isfile(file_path):
            return {"error": f"File not found: {file_path}"}

        self.logger.info(f"Getting memory map for {file_path}")
        return await _run_ghidra_script(
            "get_memory_map.py",
            file_path,
            timeout=params.get("timeout", 300),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_all_json_blocks(output: str) -> Dict[str, Any]:
    """Extract all GHIDRA_OUTPUT_START/END blocks from combined headless output.

    Each block is keyed by the script filename that produced it (best-effort).
    """
    blocks: Dict[str, Any] = {}
    start_marker = "GHIDRA_OUTPUT_START"
    end_marker = "GHIDRA_OUTPUT_END"

    idx = 0
    block_num = 0
    while True:
        start_pos = output.find(start_marker, idx)
        if start_pos == -1:
            break
        end_pos = output.find(end_marker, start_pos + len(start_marker))
        if end_pos == -1:
            break

        payload = output[start_pos + len(start_marker):end_pos].strip()
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            parsed = payload
        blocks[str(block_num)] = parsed
        block_num += 1
        idx = end_pos + len(end_marker)

    return blocks


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class GhidraMCPClient(BaseMCPClient):
    """Convenience client for calling GhidraMCPServer methods."""

    def __init__(self, host: str = "localhost", port: int = 8001):
        super().__init__("ghidra", host, port)

    async def ping(self) -> bool:
        return await self.call_method("ping")

    async def analyze_binary(self, file_path: str, **kwargs) -> Any:
        return await self.call_method("analyze_binary", {"file_path": file_path, **kwargs})

    async def get_function(self, file_path: str, address: str, **kwargs) -> Any:
        return await self.call_method("get_function", {"file_path": file_path, "address": address, **kwargs})

    async def get_strings(self, file_path: str, **kwargs) -> Any:
        return await self.call_method("get_strings", {"file_path": file_path, **kwargs})

    async def get_imports(self, file_path: str, **kwargs) -> Any:
        return await self.call_method("get_imports", {"file_path": file_path, **kwargs})

    async def get_xrefs(self, file_path: str, address: str, **kwargs) -> Any:
        return await self.call_method("get_xrefs", {"file_path": file_path, "address": address, **kwargs})

    async def decompile(self, file_path: str, address: str, **kwargs) -> Any:
        return await self.call_method("decompile", {"file_path": file_path, "address": address, **kwargs})

    async def list_functions(self, file_path: str, **kwargs) -> Any:
        return await self.call_method("list_functions", {"file_path": file_path, **kwargs})

    async def get_memory_map(self, file_path: str, **kwargs) -> Any:
        return await self.call_method("get_memory_map", {"file_path": file_path, **kwargs})


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import logging.config
    from config.settings import LOGGING_CONFIG

    logging.config.dictConfig(LOGGING_CONFIG)

    async def main():
        server = GhidraMCPServer(port=8001)
        await server.start()
        logger.info("Ghidra MCP server running on ws://localhost:8001")
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down Ghidra MCP server...")
        finally:
            await server.stop()

    asyncio.run(main())
