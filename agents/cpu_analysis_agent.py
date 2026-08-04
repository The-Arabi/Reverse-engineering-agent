"""
CPU Analysis Agent Implementation
Specialized agent for analyzing CPU binaries, instruction sets, and microarchitectural behavior using real tool calls.
"""

import asyncio
import logging
import re
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from agents.base_agent import AnalysisAgent, AgentStatus, Task, AgentResult
from agents.tool_runner import (
    run_objdump,
    run_readelf,
    run_file,
    run_strings,
    run_hexdump,
    check_tool_available,
)
from knowledge_base import add_fact, add_hypothesis, kb


BRANCH_MNEMONICS = {
    "b", "bl", "bx", "blx", "br", "blr", "ret", "jz", "jnz", "je", "jne",
    "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "jo", "jno",
    "js", "jns", "jp", "jnp", "loop", "loope", "loopne", "jmp", "call",
    "beq", "bne", "bgt", "bge", "blt", "ble", "bhi", "bhs", "blo", "bls",
    "bpl", "bmi", "bvs", "bcc", "bcs", "bvc",
}

LOAD_MNEMONICS = {
    "ldr", "ldrb", "ldrh", "ldrd", "ldrsh", "ldrsb", "ldp",
    "mov", "movw", "movt", "movz", "movk", "mrs", "msr",
    "pop", "lbu", "lhu", "lw", "lh", "lb",
    "ld", "ldl", "lds", "les", "lfs", "lgs",
    "movzx", "movsx", "movsxd", "cmov", "set",
}

STORE_MNEMONICS = {
    "str", "strb", "strh", "strd", "stp", "push",
    "stw", "sth", "sb", "sw",
    "st", "stl", "sts",
}

ALU_MNEMONICS = {
    "add", "sub", "mul", "div", "sdiv", "udiv", "mla", "mls",
    "and", "orr", "eor", "bic", "orn", "mvn", "lsl", "lsr", "asr", "ror",
    "cmp", "cmn", "tst", "teq",
    "neg", "abs", "clz", "rbit", "rev",
    "inc", "dec", "adc", "sbc",
    "not", "shl", "shr", "sar", "rol", "ror", "imul", "idiv",
    "xor", "test", "lea", "nop", "lea",
    "madd", "msub", "umull", "smull",
}


class CpuAnalysisAgent(AnalysisAgent):
    """Agent specialized in CPU analysis using real tool invocations."""

    def __init__(self, agent_id: str = None, name: str = "CPU Analysis Agent"):
        super().__init__(
            agent_id=agent_id or f"cpu_agent_{id(self)}",
            name=name,
            description="Analyzes CPU binaries, instruction sets, execution traces, and microarchitectural behavior"
        )
        self.agent_type = "cpu_analysis"
        self.supported_formats = {
            "binary", "elf", "pe", "mach-o", "hex", "bin", "raw",
            "shellcode", "firmware", "bootloader",
        }
        self.analysis_tools: Dict[str, bool] = {}

    async def initialize(self) -> bool:
        self.logger.info("Initializing CPU Analysis Agent")
        await self._check_available_tools()
        self.logger.info("CPUAnalysisAgent initialized successfully")
        return True

    async def _check_available_tools(self):
        tool_names = {
            "qemu": "qemu-arm",
            "unicorn": "unicorn",
            "capstone": "capstone",
            "keystone": "keystone",
            "objdump": "objdump",
            "strings": "strings",
            "hexdump": "hexdump",
        }
        self.analysis_tools = {}
        for key, binary in tool_names.items():
            self.analysis_tools[key] = check_tool_available(binary)

        available = sum(1 for v in self.analysis_tools.values() if v)
        self.logger.info(f"Available CPU analysis tools: {available}/{len(self.analysis_tools)}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_objdump_instructions(output: str) -> List[Dict[str, str]]:
        """Parse objdump disassembly lines into structured instruction dicts."""
        instructions: List[Dict[str, str]] = []
        for line in output.splitlines():
            line = line.rstrip()
            m = re.match(
                r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{2,})\s+(\S+)(?:\s+(.*))?$",
                line,
            )
            if m:
                instructions.append({
                    "address": m.group(1),
                    "bytes": m.group(2),
                    "mnemonic": m.group(3).lower(),
                    "operands": (m.group(4) or "").strip(),
                })
        return instructions

    @staticmethod
    def _classify_instruction(mnemonic: str) -> str:
        m = mnemonic.lower().rstrip(",")
        if m in BRANCH_MNEMONICS:
            return "branch"
        if m in LOAD_MNEMONICS:
            return "load"
        if m in STORE_MNEMONICS:
            return "store"
        if m in ALU_MNEMONICS:
            return "alu"
        return "other"

    @staticmethod
    def _parse_elf_machine(output: str) -> Tuple[str, str, str]:
        """Parse readelf -h output for machine, class, endianness."""
        machine = "Unknown"
        bit_width = "Unknown"
        endianness = "Unknown"
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("Class:"):
                val = stripped.split(":", 1)[1].strip()
                if "32" in val:
                    bit_width = "32-bit"
                elif "64" in val:
                    bit_width = "64-bit"
            elif stripped.startswith("Data:"):
                val = stripped.split(":", 1)[1].strip()
                if "little" in val.lower():
                    endianness = "Little-endian"
                elif "big" in val.lower():
                    endianness = "Big-endian"
            elif stripped.startswith("Machine:"):
                machine = stripped.split(":", 1)[1].strip()
        return machine, bit_width, endianness

    @staticmethod
    def _parse_entry_point(output: str) -> str:
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("Entry point"):
                return stripped.split(":", 1)[1].strip()
        return "0x0"

    @staticmethod
    def _parse_readelf_sections(output: str) -> List[Dict[str, str]]:
        """Parse readelf -S output into a list of section dicts."""
        sections: List[Dict[str, str]] = []
        in_table = False
        header_seen = False
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("Flags:") or stripped.startswith("Key"):
                continue
            if "Nr " in line and "Name" in line and "Type" in line:
                in_table = True
                header_seen = True
                continue
            if not in_table or not header_seen:
                continue
            if stripped == "" or stripped.startswith("====="):
                in_table = False
                continue
            parts = stripped.split()
            if len(parts) < 6:
                continue
            try:
                idx = int(parts[0])
            except ValueError:
                continue
            sections.append({
                "index": parts[0],
                "name": parts[1],
                "type": parts[2],
                "address": parts[3],
                "offset": parts[4],
                "size": parts[5],
                "flags": " ".join(parts[6:]) if len(parts) > 6 else "",
            })
        return sections

    @staticmethod
    def _parse_jump_targets(disasm_output: str) -> List[str]:
        """Extract target addresses from branch instructions."""
        targets: List[str] = []
        for line in disasm_output.splitlines():
            m = re.search(
                r"(?:b\w*|j\w*|call|blx)\s+([0-9a-fA-F]+)",
                line, re.IGNORECASE,
            )
            if m:
                targets.append(m.group(1))
        return targets

    @staticmethod
    def _count_basic_blocks(disasm_output: str) -> int:
        """Heuristic: count labels and branch targets as basic block leaders."""
        leaders: set = set()
        for line in disasm_output.splitlines():
            m = re.match(r"^\s*([0-9a-fA-F]+):", line)
            if m:
                addr = m.group(1)
                leaders.add(addr)
            if re.search(r"\bret\b|\bblr\b|\bpop\s+\{.*pc", line, re.IGNORECASE):
                m2 = re.match(r"^\s*([0-9a-fA-F]+):", line)
                if m2:
                    leaders.add(m2.group(1))
        return len(leaders) if leaders else 1

    # ------------------------------------------------------------------
    # execute_task
    # ------------------------------------------------------------------

    async def execute_task(self, task: Task) -> AgentResult:
        self.logger.info(f"Executing CPU analysis task: {task.description}")
        self.status = AgentStatus.PROCESSING

        result = AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            status="failed",
        )

        params = task.parameters or {}
        file_path = params.get("file_path")
        analysis_type = params.get("analysis_type", "comprehensive")

        if not file_path:
            result.error = "No file_path provided in task parameters"
            self.status = AgentStatus.IDLE
            return result

        if not Path(file_path).exists():
            result.error = f"File not found: {file_path}"
            self.status = AgentStatus.IDLE
            return result

        try:
            result.add_reasoning_step(
                "start_analysis",
                detail={"file_path": file_path, "analysis_type": analysis_type},
            )

            dispatch = {
                "basic": self._basic_analysis,
                "disassembly": self._disassembly_analysis,
                "emulation": self._emulation_analysis,
                "control_flow": self._control_flow_analysis,
                "memory_access": self._memory_access_analysis,
                "side_channel": self._side_channel_analysis,
                "comprehensive": self._comprehensive_analysis,
            }

            handler = dispatch.get(analysis_type)
            if handler is None:
                result.error = f"Unknown analysis type: {analysis_type}"
                self.status = AgentStatus.IDLE
                return result

            analysis_data = await handler(file_path, params)

            await self._store_analysis_results(file_path, analysis_type, analysis_data)

            tool_summary = self._build_tool_summary()

            llm_analysis = await self._run_llm_analysis(analysis_data)
            if llm_analysis:
                result.add_reasoning_step(
                    "llm_interpretation",
                    detail=f"llm_findings={len(llm_analysis.get('key_findings', []))}",
                )
                result.llm_analysis = llm_analysis

            critique = await self._run_self_critique(tool_summary, analysis_data)
            if critique:
                result.add_reasoning_step(
                    "self_critique",
                    detail=f"score={critique.get('score', 'N/A')}",
                )
                result.critique = critique

            if llm_analysis:
                extraction = await self._run_knowledge_extraction(analysis_data, llm_analysis)
                if extraction:
                    result.add_reasoning_step(
                        "knowledge_extraction",
                        detail=f"facts={len(extraction.get('facts_stored', []))}, "
                               f"hypotheses={len(extraction.get('hypotheses_stored', []))}",
                    )
                    result.knowledge_extraction = extraction

            await self._store_with_rag(
                analysis_data, tags=["cpu_analysis", analysis_type]
            )

            result.status = "completed"
            result.result = analysis_data
            self._compute_confidence(result)
            result.add_reasoning_step(
                "analysis_complete",
                detail={"analysis_type": analysis_type, "keys": list(analysis_data.keys())},
            )

        except Exception as e:
            self.logger.error(f"Error executing CPU analysis task: {e}", exc_info=True)
            self.status = AgentStatus.ERROR
            result.error = str(e)
        finally:
            if self.status != AgentStatus.ERROR:
                self.status = AgentStatus.IDLE

        return result

    # ------------------------------------------------------------------
    # Analysis methods
    # ------------------------------------------------------------------

    async def _basic_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Running basic analysis on {file_path}")
        tools_used: List[str] = []

        result: Dict[str, Any] = {
            "file_path": file_path,
            "file_size": Path(file_path).stat().st_size,
            "file_format": "Unknown",
            "file_description": "",
            "architecture": "Unknown",
            "bit_width": "Unknown",
            "endianess": "Unknown",
            "entry_point": "0x0",
            "sections": [],
            "strings": [],
        }

        file_result = await run_file(file_path)
        tools_used.append("file")
        if file_result.success:
            result["file_description"] = file_result.stdout.strip()
            desc = result["file_description"].lower()
            if "elf" in desc:
                result["file_format"] = "ELF"
            elif "pe32" in desc or "windows" in desc:
                result["file_format"] = "PE"
            elif "mach-o" in desc:
                result["file_format"] = "Mach-O"
            elif "data" in desc:
                result["file_format"] = "Raw Binary"
            else:
                result["file_format"] = desc.split(":")[1].strip() if ":" in desc else desc

        readelf_header = await run_readelf(file_path, ["-h"])
        tools_used.append("readelf")
        if readelf_header.success:
            machine, bit_width, endianness = self._parse_elf_machine(readelf_header.stdout)
            result["architecture"] = machine
            result["bit_width"] = bit_width
            result["endianess"] = endianness
            result["entry_point"] = self._parse_entry_point(readelf_header.stdout)

        readelf_sections = await run_readelf(file_path, ["-S"])
        if readelf_sections.success:
            result["sections"] = self._parse_readelf_sections(readelf_sections.stdout)

        strings_result = await run_strings(file_path, min_length=5)
        tools_used.append("strings")
        if strings_result.success:
            lines = [s.strip() for s in strings_result.stdout.splitlines() if s.strip()]
            result["strings"] = lines[:200]

        self.record_tool_output("file", f"file {file_path}", file_result.stdout, file_result.stderr)
        self.record_tool_output("readelf", f"readelf -h {file_path}", readelf_header.stdout, readelf_header.stderr)
        self.record_tool_output("strings", f"strings -n5 {file_path}", strings_result.stdout, strings_result.stderr)

        result["_tools_used"] = tools_used
        return result

    async def _disassembly_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Running disassembly analysis on {file_path}")
        tools_used: List[str] = []

        result: Dict[str, Any] = {
            "file_path": file_path,
            "analysis_type": "disassembly",
            "disassembled_instructions": [],
            "instruction_statistics": {},
            "function_boundaries": [],
            "control_flow_graph": {},
            "potential_vulnerabilities": [],
        }

        objdump_result = await run_objdump(
            file_path, ["-d", "-M", "no-aliases", "--no-show-raw-insn"]
        )
        tools_used.append("objdump")
        self.record_tool_output("objdump", f"objdump -d -M no-aliases --no-show-raw-insn {file_path}",
                                objdump_result.stdout, objdump_result.stderr)

        if not objdump_result.success:
            result["_tools_used"] = tools_used
            return result

        instructions = self._parse_objdump_instructions(objdump_result.stdout)
        result["disassembled_instructions"] = instructions

        type_counts: Dict[str, int] = {"branch": 0, "load": 0, "store": 0, "alu": 0, "other": 0}
        for instr in instructions:
            cat = self._classify_instruction(instr["mnemonic"])
            type_counts[cat] = type_counts.get(cat, 0) + 1

        result["instruction_statistics"] = {
            "total_instructions": len(instructions),
            "by_type": type_counts,
        }

        functions = self._detect_function_boundaries(objdump_result.stdout)
        result["function_boundaries"] = functions

        call_sites = []
        for instr in instructions:
            if instr["mnemonic"] in ("bl", "call", "blx", "blr"):
                call_sites.append({
                    "address": "0x" + instr["address"],
                    "target": instr["operands"],
                    "type": "direct",
                })
        result["control_flow_graph"] = {
            "function_calls": call_sites,
            "total_functions": len(functions),
        }

        vulns: List[Dict[str, str]] = []
        for instr in instructions:
            if instr["mnemonic"] in ("sprintf", "strcpy", "gets", "strcat"):
                vulns.append({
                    "type": "unsafe_function_call",
                    "address": "0x" + instr["address"],
                    "mnemonic": instr["mnemonic"],
                    "operands": instr["operands"],
                    "description": f"Potentially unsafe function call: {instr['mnemonic']} {instr['operands']}",
                })
        result["potential_vulnerabilities"] = vulns
        result["_tools_used"] = tools_used
        return result

    async def _emulation_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Running emulation analysis on {file_path}")
        result: Dict[str, Any] = {
            "file_path": file_path,
            "analysis_type": "emulation",
            "status": "simulated",
            "note": "Requires QEMU/Unicorn runtime environment; not yet wired for real execution.",
            "execution_trace": [],
            "register_changes": {},
            "memory_accesses": [],
            "system_calls": [],
        }
        result["_tools_used"] = []
        return result

    async def _control_flow_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Running control flow analysis on {file_path}")
        tools_used: List[str] = []

        result: Dict[str, Any] = {
            "file_path": file_path,
            "analysis_type": "control_flow",
            "control_flow_metrics": {},
            "branch_targets": [],
            "conditional_branches": [],
            "indirect_branches": [],
            "basic_block_count": 0,
            "loops_detected": [],
        }

        objdump_result = await run_objdump(file_path, ["-d"])
        tools_used.append("objdump")
        self.record_tool_output("objdump", f"objdump -d {file_path}",
                                objdump_result.stdout, objdump_result.stderr)

        if not objdump_result.success:
            result["_tools_used"] = tools_used
            return result

        disasm_text = objdump_result.stdout

        targets = self._parse_jump_targets(disasm_text)
        result["branch_targets"] = list(set(targets))

        conditional: List[Dict[str, str]] = []
        indirect: List[Dict[str, str]] = []
        for line in disasm_text.splitlines():
            m = re.match(r"^\s*([0-9a-fA-F]+):\s+\S+\s+(\S+)(?:\s+(.*))?$", line)
            if not m:
                continue
            addr = m.group(1)
            mnemonic = m.group(2).lower()
            operands = m.group(3) or ""

            if mnemonic in ("beq", "bne", "bgt", "bge", "blt", "ble", "bhi", "bhs", "blo", "bls",
                            "bpl", "bmi", "bvs", "bcc", "bcs", "bvc",
                            "jz", "jnz", "je", "jne", "jg", "jge", "jl", "jle",
                            "ja", "jae", "jb", "jbe", "loope", "loopne"):
                target = operands.split()[0] if operands else ""
                conditional.append({"address": "0x" + addr, "instruction": mnemonic, "target": target})

            if mnemonic in ("bx", "blx", "br", "blr", "jmp") or (
                mnemonic == "bl" and re.search(r"r\d|lr|\[", operands)
            ):
                indirect.append({"address": "0x" + addr, "instruction": mnemonic, "operands": operands.strip()})

        result["conditional_branches"] = conditional
        result["indirect_branches"] = indirect

        basic_blocks = self._count_basic_blocks(disasm_text)
        result["basic_block_count"] = basic_blocks

        loops = self._detect_loops(disasm_text, conditional)
        result["loops_detected"] = loops

        result["control_flow_metrics"] = {
            "cyclomatic_complexity": len(conditional) + 1,
            "basic_block_count": basic_blocks,
            "conditional_branch_count": len(conditional),
            "indirect_branch_count": len(indirect),
            "unique_branch_targets": len(set(targets)),
        }
        result["_tools_used"] = tools_used
        return result

    async def _memory_access_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Running memory access analysis on {file_path}")
        result: Dict[str, Any] = {
            "file_path": file_path,
            "analysis_type": "memory_access",
            "status": "simulated",
            "note": "Full memory access analysis requires dynamic tracing (e.g. QEMU/Valgrind).",
            "stack_usage": {},
            "heap_allocations": [],
            "potential_memory_issues": [],
        }
        result["_tools_used"] = []
        return result

    async def _side_channel_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Running side-channel analysis on {file_path}")
        result: Dict[str, Any] = {
            "file_path": file_path,
            "analysis_type": "side_channel",
            "status": "simulated",
            "note": "Side-channel analysis requires dynamic measurement tools not yet integrated.",
            "timing_variations": [],
            "constant_time_violations": [],
            "cache_vulnerabilities": [],
        }
        result["_tools_used"] = []
        return result

    async def _comprehensive_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Running comprehensive CPU analysis on {file_path}")

        basic = await self._basic_analysis(file_path, {})
        disasm = await self._disassembly_analysis(file_path, {})
        emu = await self._emulation_analysis(file_path, {})
        cf = await self._control_flow_analysis(file_path, {})
        mem = await self._memory_access_analysis(file_path, {})
        sc = await self._side_channel_analysis(file_path, {})

        all_tools: List[str] = []
        for sub in (basic, disasm, emu, cf, mem, sc):
            all_tools.extend(sub.get("_tools_used", []))
        unique_tools = list(dict.fromkeys(all_tools))

        result: Dict[str, Any] = {
            "file_path": file_path,
            "basic_info": basic,
            "disassembly": disasm,
            "emulation": emu,
            "control_flow": cf,
            "memory_access": mem,
            "side_channel": sc,
            "_tools_used": unique_tools,
            "summary": {
                "file_format": basic.get("file_format", "unknown"),
                "architecture": basic.get("architecture", "unknown"),
                "bit_width": basic.get("bit_width", "unknown"),
                "endianess": basic.get("endianess", "unknown"),
                "entry_point": basic.get("entry_point", "0x0"),
                "functions_identified": len(disasm.get("function_boundaries", [])),
                "total_instructions": disasm.get("instruction_statistics", {}).get("total_instructions", 0),
                "cyclomatic_complexity": cf.get("control_flow_metrics", {}).get("cyclomatic_complexity", 0),
                "basic_block_count": cf.get("basic_block_count", 0),
                "conditional_branches": len(cf.get("conditional_branches", [])),
                "indirect_branches": len(cf.get("indirect_branches", [])),
            },
        }
        return result

    # ------------------------------------------------------------------
    # Function / loop detection helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_function_boundaries(disasm_output: str) -> List[Dict[str, str]]:
        """Detect function boundaries by scanning for common prologue/epilogue patterns."""
        functions: List[Dict[str, str]] = []
        current_start: Optional[str] = None
        current_name: str = ""

        for line in disasm_output.splitlines():
            label_m = re.match(r"^([0-9a-fA-F]+) <(.+?)>:", line)
            if label_m:
                if current_start is not None:
                    functions.append({
                        "start": "0x" + current_start,
                        "end_address": "0x" + label_m.group(1),
                        "name": current_name,
                    })
                current_start = label_m.group(1)
                current_name = label_m.group(2)
                continue

            addr_m = re.match(r"^\s*([0-9a-fA-F]+):", line)
            if addr_m:
                current_end = addr_m.group(1)

        if current_start is not None:
            functions.append({
                "start": "0x" + current_start,
                "end_address": "0x" + (current_end if current_end else current_start),
                "name": current_name,
            })

        return functions

    @staticmethod
    def _detect_loops(disasm_text: str, conditional_branches: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Detect potential loops by checking if a branch target is earlier in the disassembly."""
        addr_sequence: List[str] = []
        for line in disasm_text.splitlines():
            m = re.match(r"^\s*([0-9a-fA-F]+):", line)
            if m:
                addr_sequence.append(m.group(1))

        addr_index = {a: i for i, a in enumerate(addr_sequence)}
        loops: List[Dict[str, str]] = []
        seen: set = set()

        for branch in conditional_branches:
            target_hex = branch.get("target", "").strip().lower().lstrip("0x")
            if not target_hex:
                continue
            if target_hex in seen:
                continue
            branch_addr = branch["address"].lower().lstrip("0x")
            if target_hex in addr_index and branch_addr in addr_index:
                if addr_index[target_hex] < addr_index[branch_addr]:
                    loops.append({
                        "start_address": branch["address"],
                        "back_edge_target": "0x" + target_hex,
                        "instruction": branch["instruction"],
                    })
                    seen.add(target_hex)

        return loops

    # ------------------------------------------------------------------
    # Knowledge base storage
    # ------------------------------------------------------------------

    async def _store_analysis_results(self, file_path: str, analysis_type: str, result: Dict[str, Any]):
        try:
            file_name = Path(file_path).name
            summary = result.get("summary", {})
            findings: List[str] = []
            for key in ("file_format", "architecture", "bit_width", "endianess"):
                val = summary.get(key)
                if val and val != "unknown" and val != "Unknown":
                    findings.append(f"{key}: {val}")
            if summary.get("functions_identified"):
                findings.append(f"functions: {summary['functions_identified']}")
            if summary.get("cyclomatic_complexity"):
                findings.append(f"complexity: {summary['cyclomatic_complexity']}")

            desc = f"Completed {analysis_type} analysis of {file_path}. " + "; ".join(findings)

            fact_id = add_fact(
                title=f"CPU analysis of {file_name}",
                description=desc,
                confidence=0.8,
                evidence=[f"CPU analysis of {file_path} using {analysis_type}"],
                source_references=[file_path],
                tags=["cpu_analysis", analysis_type, "automated_analysis"],
                source_agent=self.agent_id,
            )
            self.logger.info(f"Stored CPU analysis results (fact ID: {fact_id})")
        except Exception as e:
            self.logger.error(f"Failed to store CPU analysis results: {e}")

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "agent_type": self.agent_type,
            "supported_analyses": [
                "basic", "disassembly", "emulation", "control_flow",
                "memory_access", "side_channel", "comprehensive",
            ],
            "supported_formats": list(self.supported_formats),
            "available_tools": {k: v for k, v in self.analysis_tools.items() if v},
        }

    async def cleanup(self) -> bool:
        self.logger.info("CPU Analysis Agent cleaned up")
        return True


def create_cpu_analysis_agent(agent_id: str = None) -> CpuAnalysisAgent:
    return CpuAnalysisAgent(agent_id=agent_id)


if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO)

    async def test_cpu_analysis_agent():
        agent = create_cpu_analysis_agent("cpu_agent_001")
        print(f"Created agent: {agent.agent_id}")

        if await agent.initialize():
            print("Agent initialized successfully")
        else:
            print("Failed to initialize agent")
            return

        capabilities = agent.get_capabilities()
        print(f"Agent capabilities: {json.dumps(capabilities, indent=2)}")

        test_task = Task(
            task_id="test_task_001",
            description="Analyze binary for control flow and vulnerabilities",
            agent_type="cpu_analysis",
            priority=2,
            parameters={
                "file_path": "/tmp/test_binary.elf",
                "analysis_type": "control_flow",
            },
        )

        print("Executing test task...")
        result = await agent.execute_task(test_task)
        print(f"Task status: {result.status}")
        print(f"Tools used: {result.tools_used}")
        print(f"Reasoning trace: {json.dumps(result.reasoning_trace, indent=2)}")
        if result.error:
            print(f"Error: {result.error}")

        await agent.cleanup()
        print("Agent cleaned up")

    asyncio.run(test_cpu_analysis_agent())
