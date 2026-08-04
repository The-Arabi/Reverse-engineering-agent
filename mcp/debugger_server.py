"""
MCP Server for GDB-based debugging operations.
Provides real subprocess-backed debugging capabilities via the MCP protocol.
"""

import asyncio
import json
import logging
from typing import Dict, Any, List, Optional

from mcp.base_mcp import BaseMCPServer, BaseMCPClient
from agents.tool_runner import (
    run_tool,
    run_gdb,
    run_objdump,
    run_readelf,
    check_tool_available,
    ToolResult,
)

logger = logging.getLogger("mcp.debugger_server")


def _tool_result_to_dict(result: ToolResult) -> Dict[str, Any]:
    """Convert a ToolResult to a JSON-serialisable dict."""
    return {
        "command": result.command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "timed_out": result.timed_out,
        "tool_available": result.tool_available,
        "success": result.success,
    }


class DebuggerMCPServer(BaseMCPServer):
    """MCP server that exposes GDB and binutils debugging operations."""

    def __init__(self, host: str = "localhost", port: int = 8002):
        super().__init__("debugger", host, port)
        self._gdb_available: Optional[bool] = None
        self._breakpoints: Dict[str, List[str]] = {}
        self._register_methods()

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _ensure_gdb(self) -> Dict[str, Any]:
        """Return an error dict when GDB is not installed, else None."""
        if self._gdb_available is None:
            self._gdb_available = check_tool_available("gdb")
        if not self._gdb_available:
            return {"error": "GDB is not installed on this system"}
        return None

    def _bp_key(self, binary_path: str) -> str:
        return binary_path

    # ------------------------------------------------------------------
    # method registration
    # ------------------------------------------------------------------

    def _register_methods(self):
        self.register_method("ping", self._ping)
        self.register_method("run_gdb_batch", self._run_gdb_batch)
        self.register_method("disassemble", self._disassemble)
        self.register_method("get_symbols", self._get_symbols)
        self.register_method("get_sections", self._get_sections)
        self.register_method("get_segments", self._get_segments)
        self.register_method("set_breakpoint", self._set_breakpoint)
        self.register_method("backtrace", self._backtrace)
        self.register_method("info_registers", self._info_registers)
        self.register_method("inspect_memory", self._inspect_memory)

    # ------------------------------------------------------------------
    # method handlers
    # ------------------------------------------------------------------

    async def _ping(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status": "ok",
            "server": self.server_name,
            "gdb_available": check_tool_available("gdb"),
            "objdump_available": check_tool_available("objdump"),
            "readelf_available": check_tool_available("readelf"),
        }

    async def _run_gdb_batch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        gdb_err = self._ensure_gdb()
        if gdb_err:
            return gdb_err

        binary_path = params.get("binary_path")
        if not binary_path:
            return {"error": "binary_path is required"}

        commands: List[str] = params.get("commands", [])
        timeout = params.get("timeout", 120)

        result: ToolResult = await run_gdb(
            binary_path,
            commands=commands,
            batch_mode=True,
            timeout=timeout,
        )
        return _tool_result_to_dict(result)

    async def _disassemble(self, params: Dict[str, Any]) -> Dict[str, Any]:
        binary_path = params.get("binary_path")
        if not binary_path:
            return {"error": "binary_path is required"}

        func_name = params.get("function")
        start_addr = params.get("start_address")
        length = params.get("length")
        disassembly_range = params.get("range")

        flags: List[str] = ["-d"]

        if func_name:
            flags.extend(["-C", "--disassemble", func_name])
        elif start_addr:
            if length:
                flags.extend(["--start-address", start_addr, "--stop-address",
                               hex(int(start_addr, 16) + int(length))])
            elif disassembly_range:
                flags.extend(["--start-address", start_addr, "--stop-address",
                               disassembly_range])
            else:
                flags.extend(["--start-address", start_addr])

        result: ToolResult = await run_objdump(binary_path, flags=flags)
        return _tool_result_to_dict(result)

    async def _get_symbols(self, params: Dict[str, Any]) -> Dict[str, Any]:
        binary_path = params.get("binary_path")
        if not binary_path:
            return {"error": "binary_path is required"}

        use_nm = params.get("use_nm", False)
        symbol_type = params.get("type")

        if use_nm:
            cmd: List[str] = ["nm"]
            if symbol_type:
                cmd.extend(["-t", symbol_type])
            cmd.append(binary_path)
            result: ToolResult = await run_tool(cmd)
        else:
            flags: List[str] = ["--symbols"]
            result: ToolResult = await run_readelf(binary_path, flags=flags)

        return _tool_result_to_dict(result)

    async def _get_sections(self, params: Dict[str, Any]) -> Dict[str, Any]:
        binary_path = params.get("binary_path")
        if not binary_path:
            return {"error": "binary_path is required"}

        wide = params.get("wide", False)
        flags: List[str] = ["--sections"]
        if wide:
            flags.append("--wide")

        result: ToolResult = await run_readelf(binary_path, flags=flags)
        return _tool_result_to_dict(result)

    async def _get_segments(self, params: Dict[str, Any]) -> Dict[str, Any]:
        binary_path = params.get("binary_path")
        if not binary_path:
            return {"error": "binary_path is required"}

        wide = params.get("wide", False)
        flags: List[str] = ["--segments"]
        if wide:
            flags.append("--wide")

        result: ToolResult = await run_readelf(binary_path, flags=flags)
        return _tool_result_to_dict(result)

    async def _set_breakpoint(self, params: Dict[str, Any]) -> Dict[str, Any]:
        gdb_err = self._ensure_gdb()
        if gdb_err:
            return gdb_err

        binary_path = params.get("binary_path")
        if not binary_path:
            return {"error": "binary_path is required"}

        location = params.get("location")
        if not location:
            return {"error": "location is required (e.g. 'main', '0x401000', 'file.c:42')"}

        condition = params.get("condition")
        command = f"break {location}"
        if condition:
            command += f" if {condition}"

        key = self._bp_key(binary_path)
        self._breakpoints.setdefault(key, []).append(location)

        result: ToolResult = await run_gdb(
            binary_path,
            commands=[command],
            batch_mode=True,
        )
        return {
            "stored": True,
            "breakpoints": self._breakpoints.get(key, []),
            **_tool_result_to_dict(result),
        }

    async def _backtrace(self, params: Dict[str, Any]) -> Dict[str, Any]:
        gdb_err = self._ensure_gdb()
        if gdb_err:
            return gdb_err

        binary_path = params.get("binary_path")
        if not binary_path:
            return {"error": "binary_path is required"}

        commands = params.get("commands", [])
        commands.append("bt")
        timeout = params.get("timeout", 120)

        result: ToolResult = await run_gdb(
            binary_path,
            commands=commands,
            batch_mode=True,
            timeout=timeout,
        )
        return _tool_result_to_dict(result)

    async def _info_registers(self, params: Dict[str, Any]) -> Dict[str, Any]:
        gdb_err = self._ensure_gdb()
        if gdb_err:
            return gdb_err

        binary_path = params.get("binary_path")
        if not binary_path:
            return {"error": "binary_path is required"}

        extra_commands = params.get("commands", [])
        commands = extra_commands + ["info registers"]
        timeout = params.get("timeout", 120)

        result: ToolResult = await run_gdb(
            binary_path,
            commands=commands,
            batch_mode=True,
            timeout=timeout,
        )
        return _tool_result_to_dict(result)

    async def _inspect_memory(self, params: Dict[str, Any]) -> Dict[str, Any]:
        gdb_err = self._ensure_gdb()
        if gdb_err:
            return gdb_err

        binary_path = params.get("binary_path")
        if not binary_path:
            return {"error": "binary_path is required"}

        address = params.get("address")
        if not address:
            return {"error": "address is required (e.g. '0x7fffffffe000')"}

        fmt = params.get("format", "x")
        unit = params.get("unit", "w")
        count = params.get("count", 1)
        x_cmd = f"x/{count}{fmt}{unit} {address}"

        extra_commands = params.get("commands", [])
        commands = extra_commands + [x_cmd]
        timeout = params.get("timeout", 60)

        result: ToolResult = await run_gdb(
            binary_path,
            commands=commands,
            batch_mode=True,
            timeout=timeout,
        )
        return _tool_result_to_dict(result)


# ======================================================================
# Client
# ======================================================================

class DebuggerMCPClient(BaseMCPClient):
    """Client convenience wrapper for the Debugger MCP server."""

    def __init__(self, host: str = "localhost", port: int = 8002):
        super().__init__("debugger", host, port)

    async def ping(self) -> Any:
        return await self.call_method("ping")

    async def run_gdb_batch(self, binary_path: str, commands: List[str],
                            timeout: int = 120) -> Any:
        return await self.call_method("run_gdb_batch", {
            "binary_path": binary_path,
            "commands": commands,
            "timeout": timeout,
        })

    async def disassemble(self, binary_path: str,
                          function: Optional[str] = None,
                          start_address: Optional[str] = None,
                          length: Optional[int] = None) -> Any:
        params: Dict[str, Any] = {"binary_path": binary_path}
        if function:
            params["function"] = function
        if start_address:
            params["start_address"] = start_address
        if length is not None:
            params["length"] = length
        return await self.call_method("disassemble", params)

    async def get_symbols(self, binary_path: str, use_nm: bool = False,
                          type: Optional[str] = None) -> Any:
        return await self.call_method("get_symbols", {
            "binary_path": binary_path,
            "use_nm": use_nm,
            "type": type,
        })

    async def get_sections(self, binary_path: str, wide: bool = False) -> Any:
        return await self.call_method("get_sections", {
            "binary_path": binary_path,
            "wide": wide,
        })

    async def get_segments(self, binary_path: str, wide: bool = False) -> Any:
        return await self.call_method("get_segments", {
            "binary_path": binary_path,
            "wide": wide,
        })

    async def set_breakpoint(self, binary_path: str, location: str,
                             condition: Optional[str] = None) -> Any:
        params: Dict[str, Any] = {
            "binary_path": binary_path,
            "location": location,
        }
        if condition:
            params["condition"] = condition
        return await self.call_method("set_breakpoint", params)

    async def backtrace(self, binary_path: str,
                        commands: Optional[List[str]] = None,
                        timeout: int = 120) -> Any:
        return await self.call_method("backtrace", {
            "binary_path": binary_path,
            "commands": commands or [],
            "timeout": timeout,
        })

    async def info_registers(self, binary_path: str,
                             commands: Optional[List[str]] = None,
                             timeout: int = 120) -> Any:
        return await self.call_method("info_registers", {
            "binary_path": binary_path,
            "commands": commands or [],
            "timeout": timeout,
        })

    async def inspect_memory(self, binary_path: str, address: str,
                             format: str = "x", unit: str = "w",
                             count: int = 1,
                             commands: Optional[List[str]] = None) -> Any:
        params: Dict[str, Any] = {
            "binary_path": binary_path,
            "address": address,
            "format": format,
            "unit": unit,
            "count": count,
        }
        if commands:
            params["commands"] = commands
        return await self.call_method("inspect_memory", params)


# ======================================================================
# Entry-point
# ======================================================================

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="Debugger MCP Server")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8002)
    args = parser.parse_args()

    async def _main():
        server = DebuggerMCPServer(host=args.host, port=args.port)
        await server.start()
        logger.info(
            f"Debugger MCP server listening on {args.host}:{args.port}"
        )
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            await server.stop()

    asyncio.run(_main())
