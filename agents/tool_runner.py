"""
Shared subprocess utility for running reverse engineering tools.
All agents use this module for real tool invocations instead of fabricated data.
"""

import asyncio
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

logger = logging.getLogger("agents.tool_runner")


@dataclass
class ToolResult:
    """Result from a subprocess tool invocation."""
    command: str
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    tool_available: bool = True

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def output(self) -> str:
        return self.stdout


async def run_tool(
    cmd: List[str],
    timeout: int = 60,
    input_data: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> ToolResult:
    """Run a command-line tool asynchronously and return structured results."""
    cmd_str = " ".join(cmd)
    logger.debug(f"Running tool: {cmd_str}")

    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if input_data else None,
            env=merged_env,
        )

        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(input_data.encode() if input_data else None),
            timeout=timeout,
        )

        return ToolResult(
            command=cmd_str,
            returncode=proc.returncode or 0,
            stdout=stdout_bytes.decode(errors="replace"),
            stderr=stderr_bytes.decode(errors="replace"),
        )

    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        logger.warning(f"Tool timed out after {timeout}s: {cmd_str}")
        return ToolResult(
            command=cmd_str,
            returncode=-1,
            stdout="",
            stderr=f"Command timed out after {timeout}s",
            timed_out=True,
        )
    except FileNotFoundError:
        logger.warning(f"Tool not found: {cmd[0]}")
        return ToolResult(
            command=cmd_str,
            returncode=-1,
            stdout="",
            stderr=f"Tool not found: {cmd[0]}",
            tool_available=False,
        )
    except Exception as e:
        logger.error(f"Error running tool {cmd_str}: {e}")
        return ToolResult(
            command=cmd_str,
            returncode=-1,
            stdout="",
            stderr=str(e),
        )


def check_tool_available(tool_name: str) -> bool:
    """Check if a tool is available on the system PATH."""
    return shutil.which(tool_name) is not None


def find_tool(name: str, configured_path: Optional[str] = None) -> Optional[str]:
    """Find a tool binary, checking configured path first, then PATH."""
    if configured_path and os.path.isfile(configured_path) and os.access(configured_path, os.X_OK):
        return configured_path
    found = shutil.which(name)
    return found


# ---------------------------------------------------------------------------
# High-level wrappers for common RE tools
# ---------------------------------------------------------------------------

async def run_objdump(
    file_path: str,
    flags: Optional[List[str]] = None,
    timeout: int = 120,
) -> ToolResult:
    """Run objdump on a binary file."""
    cmd = ["objdump"]
    if flags:
        cmd.extend(flags)
    cmd.append(file_path)
    return await run_tool(cmd, timeout=timeout)


async def run_readelf(
    file_path: str,
    flags: Optional[List[str]] = None,
    timeout: int = 60,
) -> ToolResult:
    """Run readelf on a binary file."""
    cmd = ["readelf"]
    if flags:
        cmd.extend(flags)
    cmd.append(file_path)
    return await run_tool(cmd, timeout=timeout)


async def run_strings(
    file_path: str,
    min_length: int = 4,
    encoding: str = "s",
    timeout: int = 60,
) -> ToolResult:
    """Run strings on a file. encoding: 's'=7bit, 'S'=8bit, 'l'=16bit, 'b'=32bit."""
    cmd = ["strings", f"-n{min_length}", f"-e{encoding}", file_path]
    return await run_tool(cmd, timeout=timeout)


async def run_file(file_path: str, timeout: int = 30) -> ToolResult:
    """Run the file(1) command to identify file type."""
    return await run_tool(["file", file_path], timeout=timeout)


async def run_binwalk(
    file_path: str,
    extract: bool = False,
    scan_only: bool = False,
    timeout: int = 300,
) -> ToolResult:
    """Run binwalk on a firmware image."""
    cmd = ["binwalk"]
    if extract:
        cmd.append("-e")
    elif scan_only:
        cmd.append("--signature")
    cmd.append(file_path)
    return await run_tool(cmd, timeout=timeout)


async def run_tshark(
    pcap_file: str,
    filters: Optional[List[str]] = None,
    fields: Optional[List[str]] = None,
    max_packets: int = 0,
    decode_as: Optional[Dict[str, str]] = None,
    timeout: int = 120,
) -> ToolResult:
    """Run tshark to analyze a pcap/pcapng file."""
    cmd = ["tshark", "-r", pcap_file, "-V"]
    if filters:
        for f in filters:
            cmd.extend(["-Y", f])
    if fields:
        for field_name in fields:
            cmd.extend(["-T", "fields", "-e", field_name])
    if max_packets > 0:
        cmd.extend(["-c", str(max_packets)])
    if decode_as:
        for key, val in decode_as.items():
            cmd.extend(["-d", f"{key}={val}"])
    return await run_tool(cmd, timeout=timeout)


async def run_capinfos(pcap_file: str, timeout: int = 30) -> ToolResult:
    """Run capinfos to get capture file metadata."""
    return await run_tool(["capinfos", pcap_file], timeout=timeout)


async def run_tcpdump(
    pcap_file: str,
    count: int = 0,
    verbose: bool = True,
    timeout: int = 120,
) -> ToolResult:
    """Run tcpdump to read a capture file."""
    cmd = ["tcpdump", "-r", pcap_file, "-nn"]
    if verbose:
        cmd.append("-v")
    if count > 0:
        cmd.extend(["-c", str(count)])
    return await run_tool(cmd, timeout=timeout)


async def run_ghidra_headless(
    file_path: str,
    project_dir: str = "/tmp/ghidra_project",
    project_name: str = "re_lab_project",
    scripts: Optional[List[str]] = None,
    post_scripts: Optional[List[str]] = None,
    ghidra_path: Optional[str] = None,
    timeout: int = 600,
) -> ToolResult:
    """Run Ghidra in headless mode for analysis."""
    ghidra_bin = find_tool(
        "analyzeHeadless",
        ghidra_path or "/opt/ghidra/support/analyzeHeadless",
    )
    if not ghidra_bin:
        return ToolResult(
            command="analyzeHeadless",
            returncode=-1,
            stdout="",
            stderr="Ghidra analyzeHeadless not found. Install Ghidra or set ghidra_path.",
            tool_available=False,
        )

    os.makedirs(project_dir, exist_ok=True)
    cmd = [
        ghidra_bin,
        project_dir,
        project_name,
        "-import", file_path,
        "-postScript", ",".join(post_scripts) if post_scripts else "",
        "-scriptPath", os.path.dirname(os.path.abspath(__file__)),
        "-deleteProject",
    ]
    cmd = [c for c in cmd if c]  # remove empty strings

    if scripts:
        cmd.extend(["-scriptPath", os.path.dirname(os.path.abspath(__file__))])
        for s in scripts:
            cmd.extend(["-postScript", s])

    return await run_tool(cmd, timeout=timeout)


async def run_gdb(
    binary_path: str,
    commands: Optional[List[str]] = None,
    batch_mode: bool = True,
    timeout: int = 120,
) -> ToolResult:
    """Run GDB on a binary, optionally with GDB commands."""
    gdb_bin = find_tool("gdb", "/usr/bin/gdb")
    if not gdb_bin:
        return ToolResult(
            command="gdb",
            returncode=-1,
            stdout="",
            stderr="GDB not found. Install gdb.",
            tool_available=False,
        )

    cmd = [gdb_bin]
    if batch_mode:
        cmd.append("--batch")
    if commands:
        for c in commands:
            cmd.extend(["-ex", c])
    cmd.append(binary_path)

    return await run_tool(cmd, timeout=timeout)


async def run_hexdump(file_path: str, length: int = 256, timeout: int = 30) -> ToolResult:
    """Run hexdump on a file."""
    return await run_tool(
        ["hexdump", "-C", "-n", str(length), file_path],
        timeout=timeout,
    )


async def run_which(tool_name: str) -> str:
    """Return the path to a tool, or empty string if not found."""
    path = shutil.which(tool_name)
    return path or ""


def get_available_tools() -> Dict[str, bool]:
    """Check availability of all commonly used RE tools."""
    tools = [
        "objdump", "readelf", "strings", "file", "hexdump", "nm",
        "binwalk", "tshark", "capinfos", "tcpdump", "wireshark",
        "gdb", "lldb",
        "qemu-system-x86_64", "qemu-arm", "qemu-mips",
        "radare2", "r2",
        "nmap", "curl", "wget",
    ]
    return {t: check_tool_available(t) for t in tools}
