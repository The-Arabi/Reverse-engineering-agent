"""
Binary Analysis Agent Implementation
Specialized agent for analyzing executable files and firmware components.

All tool calls use real subprocess invocations via agents.tool_runner.
No placeholder or fabricated data is used.
"""

import asyncio
import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents.base_agent import AgentResult, AgentStatus, AnalysisAgent, Task
from agents.tool_runner import (
    check_tool_available,
    run_file,
    run_hexdump,
    run_objdump,
    run_readelf,
    run_strings,
    run_ghidra_headless,
)
from knowledge_base import add_fact, kb


class BinaryAnalysisAgent(AnalysisAgent):
    """Agent specialized in binary analysis using real RE tools via subprocess."""

    def __init__(self, agent_id: str = None, name: str = "Binary Analysis Agent"):
        super().__init__(
            agent_id=agent_id or f"binary_agent_{id(self)}",
            name=name,
            description=(
                "Analyzes executable files and firmware components to identify "
                "functions, imports, strings, and security-relevant code"
            ),
        )
        self.agent_type = "binary_analysis"
        self.supported_formats = {
            "PE", "ELF", "Mach-O", "binary", "firmware",
            "raw", "intelhex", "motorola", "tektronix",
        }
        self.analysis_tools: Dict[str, bool] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> bool:
        self.logger.info("Initializing Binary Analysis Agent")
        await self._check_available_tools()
        self.logger.info("Binary Analysis Agent initialized")
        return True

    async def cleanup(self) -> bool:
        self.logger.info("Binary Analysis Agent cleaned up")
        return True

    # ------------------------------------------------------------------
    # Tool availability
    # ------------------------------------------------------------------

    async def _check_available_tools(self):
        tool_names = ["objdump", "readelf", "strings", "file", "hexdump", "analyzeHeadless"]
        self.analysis_tools = {name: check_tool_available(name) for name in tool_names}
        available = sum(1 for v in self.analysis_tools.values() if v)
        self.logger.info(
            f"Available analysis tools: {available}/{len(self.analysis_tools)} – "
            f"{self.analysis_tools}"
        )

    # ------------------------------------------------------------------
    # Task entry point
    # ------------------------------------------------------------------

    async def execute_task(self, task: Task) -> AgentResult:
        self.logger.info(f"Executing binary analysis task: {task.description}")
        self.status = AgentStatus.PROCESSING

        result_obj = AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            status="failed",
        )

        try:
            params = task.parameters or {}
            file_path = params.get("file_path")
            analysis_type = params.get("analysis_type", "comprehensive")

            if not file_path:
                result_obj.error = "No file_path provided in task parameters"
                return result_obj

            if not Path(file_path).exists():
                result_obj.error = f"File not found: {file_path}"
                return result_obj

            result_obj.add_reasoning_step(
                "start_analysis",
                detail=f"analysis_type={analysis_type}, file={file_path}",
            )

            dispatch = {
                "basic": self._basic_analysis,
                "strings": self._string_analysis,
                "imports": self._import_analysis,
                "functions": self._function_analysis,
                "comprehensive": self._comprehensive_analysis,
            }
            handler = dispatch.get(analysis_type)
            if handler is None:
                result_obj.error = f"Unknown analysis type: {analysis_type}"
                return result_obj

            t0 = time.monotonic()
            result = await handler(file_path, params)
            elapsed = round(time.monotonic() - t0, 2)

            result_obj.add_reasoning_step(
                "analysis_complete",
                detail=f"analysis_type={analysis_type}, elapsed={elapsed}s",
            )

            await self._store_analysis_results(file_path, analysis_type, result)

            # LLM-powered interpretation
            tool_summary = self._build_tool_summary()
            llm_analysis = await self._run_llm_analysis(result)
            if llm_analysis:
                result_obj.add_reasoning_step(
                    "llm_interpretation",
                    detail=f"llm_findings={len(llm_analysis.get('key_findings', []))}",
                )
                result_obj.llm_analysis = llm_analysis

            # Self-critique
            critique = await self._run_self_critique(tool_summary, result)
            if critique:
                result_obj.add_reasoning_step(
                    "self_critique",
                    detail=f"score={critique.get('score', 'N/A')}",
                )
                result_obj.critique = critique

            # Knowledge extraction
            if llm_analysis:
                extraction = await self._run_knowledge_extraction(result, llm_analysis)
                if extraction:
                    result_obj.add_reasoning_step(
                        "knowledge_extraction",
                        detail=f"facts={len(extraction.get('facts_stored', []))}, "
                               f"hypotheses={len(extraction.get('hypotheses_stored', []))}",
                    )
                    result_obj.knowledge_extraction = extraction

            # Store in RAG pipeline
            await self._store_with_rag(
                result, tags=["binary_analysis", analysis_type]
            )

            result_obj.status = "completed"
            result_obj.result = result
            self._compute_confidence(result_obj)

        except Exception as e:
            self.logger.error(f"Error executing binary analysis task: {e}", exc_info=True)
            self.status = AgentStatus.ERROR
            result_obj.error = str(e)

        finally:
            if self.status != AgentStatus.ERROR:
                self.status = AgentStatus.IDLE

        return result_obj

    # ------------------------------------------------------------------
    # Basic analysis
    # ------------------------------------------------------------------

    async def _basic_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Performing basic analysis on {file_path}")
        result: Dict[str, Any] = {"file_path": file_path}

        # file(1) type identification
        file_result = await run_file(file_path)
        self.record_tool_output(
            "file", file_result.command,
            file_result.stdout, file_result.stderr, file_result.returncode,
        )
        result["file_type_raw"] = file_result.stdout.strip() if file_result.success else ""

        # Parse architecture / type from file(1) output
        file_line = result["file_type_raw"]
        result["file_type"] = _extract_file_type(file_line)
        result["architecture"] = _extract_arch(file_line)
        result["file_size"] = Path(file_path).stat().st_size

        # ELF header
        elf_header_raw = ""
        if "ELF" in file_line:
            header_result = await run_readelf(file_path, ["-h"])
            self.record_tool_output(
                "readelf", header_result.command,
                header_result.stdout, header_result.stderr, header_result.returncode,
            )
            elf_header_raw = header_result.stdout if header_result.success else ""
            result["elf_header"] = _parse_elf_header(elf_header_raw)
        else:
            result["elf_header"] = {}

        # Section headers
        sections_raw = ""
        if "ELF" in file_line:
            sec_result = await run_readelf(file_path, ["-S"])
            self.record_tool_output(
                "readelf", sec_result.command,
                sec_result.stdout, sec_result.stderr, sec_result.returncode,
            )
            sections_raw = sec_result.stdout if sec_result.success else ""
            result["sections"] = _parse_sections(sections_raw)
        else:
            result["sections"] = []

        # Quick strings count
        str_result = await run_strings(file_path, min_length=6)
        self.record_tool_output(
            "strings", str_result.command,
            str_result.stdout, str_result.stderr, str_result.returncode,
        )
        string_lines = [l for l in str_result.stdout.splitlines() if l.strip()] if str_result.success else []
        result["strings_quick_count"] = len(string_lines)

        return result

    # ------------------------------------------------------------------
    # String analysis
    # ------------------------------------------------------------------

    async def _string_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Performing string analysis on {file_path}")

        min_len = params.get("min_length", 4)

        str_result = await run_strings(file_path, min_length=min_len)
        self.record_tool_output(
            "strings", str_result.command,
            str_result.stdout, str_result.stderr, str_result.returncode,
        )

        if not str_result.success:
            self.logger.warning(f"strings failed: {str_result.stderr}")
            return {"file_path": file_path, "strings": [], "categories": {}, "error": str_result.stderr}

        raw_lines = [l for l in str_result.stdout.splitlines() if l.strip()]

        categories: Dict[str, List[str]] = {
            "urls": [],
            "file_paths": [],
            "ips": [],
            "emails": [],
            "potential_secrets": [],
            "format_strings": [],
        }

        url_re = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
        path_re = re.compile(r'^/(?:etc|usr|var|tmp|proc|dev|opt|home|root)/[^\s"\'<>]+$')
        ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        email_re = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        secret_re = re.compile(
            r'(?i)(?:password|passwd|secret|api.?key|token|auth|credential|'
            r'private.?key|access.?key)\s*[=:]\s*\S+'
        )
        fmt_re = re.compile(r'%[0-9]*\.?[0-9]*[diouxXeEfFgGaAcspn%]')

        categorized_strings = []
        for line in raw_lines:
            entry = {"value": line}
            matched_cats = []

            if url_re.search(line):
                categories["urls"].append(line)
                matched_cats.append("url")
            if path_re.search(line):
                categories["file_paths"].append(line)
                matched_cats.append("file_path")
            if ip_re.fullmatch(line.strip()):
                categories["ips"].append(line)
                matched_cats.append("ip")
            if email_re.search(line):
                categories["emails"].append(line)
                matched_cats.append("email")
            if secret_re.search(line):
                categories["potential_secrets"].append(line)
                matched_cats.append("potential_secret")
            if fmt_re.search(line) and len(line) < 80:
                categories["format_strings"].append(line)
                matched_cats.append("format_string")

            entry["categories"] = matched_cats
            categorized_strings.append(entry)

        return {
            "file_path": file_path,
            "total_strings": len(categorized_strings),
            "strings": categorized_strings,
            "categories": {k: len(v) for k, v in categories.items()},
            "category_details": categories,
        }

    # ------------------------------------------------------------------
    # Import / symbol analysis
    # ------------------------------------------------------------------

    async def _import_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Performing import analysis on {file_path}")

        imports: List[Dict[str, str]] = []
        file_line_result = await run_file(file_path)
        file_line = file_line_result.stdout if file_line_result.success else ""

        if "ELF" in file_line:
            # Dynamic symbols via readelf
            dyn_result = await run_readelf(file_path, ["--dyn-syms"])
            self.record_tool_output(
                "readelf", dyn_result.command,
                dyn_result.stdout, dyn_result.stderr, dyn_result.returncode,
            )
            if dyn_result.success:
                imports.extend(_parse_dyn_syms(dyn_result.stdout))

            # Also try objdump -T as a cross-check / fallback
            obj_result = await run_objdump(file_path, ["-T"])
            self.record_tool_output(
                "objdump", obj_result.command,
                obj_result.stdout, obj_result.stderr, obj_result.returncode,
            )
            if obj_result.success and not imports:
                imports.extend(_parse_objdump_dyn(obj_result.stdout))
        else:
            # Non-ELF: try objdump -T anyway
            obj_result = await run_objdump(file_path, ["-T"])
            self.record_tool_output(
                "objdump", obj_result.command,
                obj_result.stdout, obj_result.stderr, obj_result.returncode,
            )
            if obj_result.success:
                imports.extend(_parse_objdump_dyn(obj_result.stdout))

        dangerous = {"gets", "strcpy", "strcat", "sprintf", "vsprintf",
                      "system", "execve", "fork", "popen", "mktemp"}
        suspicious = [i for i in imports if i["name"].lower() in dangerous]

        # Group by version/library
        by_version: Dict[str, List[str]] = {}
        for imp in imports:
            ver = imp.get("version", "unknown")
            by_version.setdefault(ver, []).append(imp["name"])

        return {
            "file_path": file_path,
            "total_imports": len(imports),
            "imports": imports,
            "by_version": by_version,
            "suspicious_imports": suspicious,
        }

    # ------------------------------------------------------------------
    # Function / disassembly analysis
    # ------------------------------------------------------------------

    async def _function_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Performing function analysis on {file_path}")

        dis_result = await run_objdump(file_path, ["-d", "--no-show-raw-insn"])
        self.record_tool_output(
            "objdump", dis_result.command,
            dis_result.stdout, dis_result.stderr, dis_result.returncode,
        )

        if not dis_result.success:
            self.logger.warning(f"objdump disassembly failed: {dis_result.stderr}")
            return {
                "file_path": file_path,
                "total_functions": 0,
                "functions": [],
                "error": dis_result.stderr,
            }

        functions = _parse_functions_from_disassembly(dis_result.stdout)

        sizes = [f["estimated_size"] for f in functions if f["estimated_size"] > 0]
        total_size = sum(sizes)

        return {
            "file_path": file_path,
            "total_functions": len(functions),
            "functions": functions,
            "statistics": {
                "total_code_size": total_size,
                "average_function_size": round(total_size / len(sizes), 1) if sizes else 0,
                "largest_function": max(functions, key=lambda f: f["estimated_size"]) if functions else None,
                "smallest_function": min(functions, key=lambda f: f["estimated_size"]) if functions else None,
            },
            "entry_points": [f for f in functions if f.get("is_entry_point")],
        }

    # ------------------------------------------------------------------
    # Comprehensive analysis (combines all)
    # ------------------------------------------------------------------

    async def _comprehensive_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Performing comprehensive analysis on {file_path}")

        basic = await self._basic_analysis(file_path, params)
        strings_data = await self._string_analysis(file_path, params)
        imports_data = await self._import_analysis(file_path, params)
        functions_data = await self._function_analysis(file_path, params)

        # Try Ghidra if available
        ghidra_data = await self.try_ghidra_analysis(file_path)

        return {
            "file_path": file_path,
            "basic_info": basic,
            "strings": strings_data,
            "imports": imports_data,
            "functions": functions_data,
            "ghidra": ghidra_data,
            "summary": {
                "file_type": basic.get("file_type", "unknown"),
                "architecture": basic.get("architecture", "unknown"),
                "total_functions": functions_data.get("total_functions", 0),
                "total_imports": imports_data.get("total_imports", 0),
                "strings_found": strings_data.get("total_strings", 0),
                "suspicious_imports": len(imports_data.get("suspicious_imports", [])),
                "potential_secrets_in_strings": strings_data.get("categories", {}).get("potential_secrets", 0),
                "ghidra_available": ghidra_data is not None,
            },
        }

    # ------------------------------------------------------------------
    # Ghidra headless analysis
    # ------------------------------------------------------------------

    async def try_ghidra_analysis(self, file_path: str, timeout: int = 300) -> Optional[Dict[str, Any]]:
        """Attempt Ghidra headless analysis. Returns dict or None if unavailable."""
        if not self.analysis_tools.get("analyzeHeadless", False):
            self.logger.info("Ghidra analyzeHeadless not available, skipping")
            return None

        self.logger.info(f"Running Ghidra headless analysis on {file_path}")
        result = await run_ghidra_headless(file_path, timeout=timeout)
        self.record_tool_output(
            "ghidra", result.command,
            result.stdout, result.stderr, result.returncode,
        )

        if not result.success:
            self.logger.warning(f"Ghidra headless failed: {result.stderr[:500]}")
            return None

        return {
            "available": True,
            "output": result.stdout[:10000],
            "raw": result.stdout,
        }

    # ------------------------------------------------------------------
    # Knowledge-base storage
    # ------------------------------------------------------------------

    async def _store_analysis_results(self, file_path: str, analysis_type: str, result: Dict[str, Any]):
        try:
            file_name = Path(file_path).name

            key_findings: List[str] = []
            summary = result.get("summary") or result.get("basic_info", {})
            if isinstance(summary, dict):
                for key in ("architecture", "file_type"):
                    if key in summary:
                        key_findings.append(f"{key}: {summary[key]}")
            key_findings.append(f"analysis_type: {analysis_type}")

            fact_id = add_fact(
                title=f"Binary analysis of {file_name}",
                description=(
                    f"Completed {analysis_type} analysis of {file_path}. "
                    + "; ".join(key_findings)
                ),
                confidence=0.8,
                evidence=[f"Analysis of {file_path} using {analysis_type} analysis"],
                source_references=[file_path],
                tags=["binary_analysis", analysis_type, "automated_analysis"],
                source_agent=self.agent_id,
            )

            # Store security-relevant findings separately
            imports_data = result.get("imports", {})
            suspicious = imports_data.get("suspicious_imports", []) if isinstance(imports_data, dict) else []
            for imp in suspicious:
                name = imp.get("name", str(imp)) if isinstance(imp, dict) else str(imp)
                add_fact(
                    title=f"Suspicious import: {name}",
                    description=f"Binary {file_name} imports potentially dangerous function '{name}'",
                    confidence=0.75,
                    evidence=[f"Static import analysis of {file_path}"],
                    source_references=[file_path],
                    tags=["security", "dangerous_import", "binary_analysis"],
                    source_agent=self.agent_id,
                )

            secrets = result.get("strings", {}).get("category_details", {}).get("potential_secrets", [])
            for secret in secrets[:10]:  # cap at 10
                add_fact(
                    title=f"Potential secret in strings: {file_name}",
                    description=f"Found potential secret/credential string: {secret[:120]}",
                    confidence=0.6,
                    evidence=[f"String analysis of {file_path}"],
                    source_references=[file_path],
                    tags=["security", "potential_secret", "binary_analysis"],
                    source_agent=self.agent_id,
                )

            self.logger.info(f"Stored analysis results in KB (fact_id={fact_id})")

        except Exception as e:
            self.logger.error(f"Failed to store analysis results: {e}")

    # ------------------------------------------------------------------
    # Capabilities
    # ------------------------------------------------------------------

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "agent_type": self.agent_type,
            "supported_analyses": [
                "basic", "strings", "imports", "functions", "comprehensive",
            ],
            "supported_formats": list(self.supported_formats),
            "available_tools": {k: v for k, v in self.analysis_tools.items() if v},
        }


# ======================================================================
# Parsing helpers
# ======================================================================

def _extract_file_type(file_line: str) -> str:
    """Extract a clean file type string from file(1) output."""
    if not file_line:
        return "unknown"
    # file(1) format: "path: ELF 64-bit LSB ..."
    parts = file_line.split(":", 1)
    if len(parts) == 2:
        return parts[1].strip()
    return file_line.strip()


def _extract_arch(file_line: str) -> str:
    """Best-effort architecture extraction from file(1) output."""
    lower = file_line.lower()
    if "x86-64" in lower or "x86_64" in lower:
        return "x86-64"
    if "x86" in lower or "80386" in lower or "i386" in lower or "i686" in lower:
        return "x86"
    if "aarch64" in lower or "arm64" in lower:
        return "AArch64"
    if "arm" in lower:
        return "ARM"
    if "mips" in lower:
        return "MIPS"
    if "powerpc" in lower or "ppc" in lower:
        return "PowerPC"
    if "risc-v" in lower or "riscv" in lower:
        return "RISC-V"
    if "sparc" in lower:
        return "SPARC"
    return "unknown"


def _parse_elf_header(raw: str) -> Dict[str, Any]:
    """Parse readelf -h output into a dict."""
    header: Dict[str, Any] = {}
    for line in raw.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()
        if not key:
            continue
        normalized = key.lower().replace(" ", "_")
        header[normalized] = val
    return header


def _parse_sections(raw: str) -> List[Dict[str, str]]:
    """Parse readelf -S output into a list of section dicts."""
    sections: List[Dict[str, str]] = []
    in_table = False
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("Nr") and "Name" in stripped:
            in_table = True
            continue
        if in_table and stripped.startswith("["):
            # Typical format: [ 0] .text PROGBITS 0000000000401000 00001000 ...
            # Extract bracketed index and then split remaining by whitespace
            bracket_end = stripped.find("]")
            if bracket_end == -1:
                continue
            rest = stripped[bracket_end + 1:].split()
            if len(rest) >= 6:
                sections.append({
                    "name": rest[0],
                    "type": rest[1],
                    "addr": rest[2],
                    "offset": rest[3],
                    "size": rest[4],
                    "flags": rest[5] if len(rest) > 5 else "",
                })
        elif in_table and not stripped.startswith("Key"):
            # Could be end of table
            if stripped == "" or stripped.startswith("Key") or stripped.startswith("---"):
                in_table = False
    return sections


def _parse_dyn_syms(raw: str) -> List[Dict[str, str]]:
    """Parse readelf --dyn-syms output."""
    imports: List[Dict[str, str]] = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[0].isdigit():
            name = parts[7]
            # Skip hidden/und symbols that are actually undefined (imports)
            # In dyn-syms, UND means undefined => imported
            if parts[3] == "UND" or "UND" in line:
                imports.append({
                    "name": name,
                    "value": parts[1],
                    "size": parts[2],
                    "type": parts[4] if len(parts) > 4 else "",
                    "bind": parts[5] if len(parts) > 5 else "",
                    "version": parts[7] if len(parts) > 7 else "",
                })
    return imports


def _parse_objdump_dyn(raw: str) -> List[Dict[str, str]]:
    """Parse objdump -T output for dynamic symbols."""
    imports: List[Dict[str, str]] = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].startswith("0"):
            name = parts[-1]
            if not name.startswith("*"):
                imports.append({
                    "name": name,
                    "value": parts[0],
                    "type": parts[3] if len(parts) > 3 else "",
                })
    return imports


def _parse_functions_from_disassembly(raw: str) -> List[Dict[str, Any]]:
    """
    Detect function boundaries from objdump -d output.
    Looks for '<function_name>:' labels and estimates size by counting
    instructions until the next label.
    """
    functions: List[Dict[str, Any]] = []
    func_pattern = re.compile(r'^([0-9a-fA-F]+)\s+<([^>]+)>:')

    current_func = None
    current_addr = None
    instruction_count = 0

    for line in raw.splitlines():
        m = func_pattern.match(line)
        if m:
            # Save previous function
            if current_func is not None:
                functions.append({
                    "address": current_addr,
                    "name": current_func,
                    "estimated_size": instruction_count,
                    "is_entry_point": current_func in ("_start", "__libc_csu_init"),
                })
            current_addr = m.group(1)
            current_func = m.group(2)
            instruction_count = 0
        elif current_func is not None:
            stripped = line.strip()
            if stripped and not stripped.startswith("Disassembly") and stripped != "":
                instruction_count += 1

    # Don't forget the last function
    if current_func is not None:
        functions.append({
            "address": current_addr,
            "name": current_func,
            "estimated_size": instruction_count,
            "is_entry_point": current_func in ("_start", "__libc_csu_init"),
        })

    return functions


# ======================================================================
# Factory
# ======================================================================

def create_binary_analysis_agent(agent_id: str = None) -> BinaryAnalysisAgent:
    return BinaryAnalysisAgent(agent_id=agent_id)


# ======================================================================
# Test
# ======================================================================

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")

    async def main():
        agent = create_binary_analysis_agent("binary_agent_001")
        print(f"Created agent: {agent.agent_id}")

        if await agent.initialize():
            print("Agent initialized successfully")
        else:
            print("Failed to initialize agent")
            return

        print(f"Available tools: {json.dumps(agent.analysis_tools, indent=2)}")
        print(f"Capabilities: {json.dumps(agent.get_capabilities(), indent=2)}")

        test_file = sys.argv[1] if len(sys.argv) > 1 else "/tmp/test_binary"
        if not Path(test_file).exists():
            print(f"Test file not found: {test_file}")
            print("Usage: python binary_analysis_agent.py <binary_path>")
            return

        task = Task(
            task_id="test_task_001",
            description="Comprehensive analysis of test binary",
            agent_type="binary_analysis",
            priority=2,
            parameters={"file_path": test_file, "analysis_type": "comprehensive"},
        )

        print("Executing test task...")
        result = await agent.execute_task(task)
        print(f"Status: {result.status}")
        print(f"Error: {result.error}")
        print(f"Tools used: {result.tools_used}")
        print(f"Reasoning trace: {json.dumps(result.reasoning_trace, indent=2)}")
        if result.result:
            # Print summary only to keep output manageable
            summary = result.result.get("summary")
            if summary:
                print(f"Summary: {json.dumps(summary, indent=2)}")
            else:
                print(f"Result keys: {list(result.result.keys())}")

        await agent.cleanup()
        print("Done")

    asyncio.run(main())
