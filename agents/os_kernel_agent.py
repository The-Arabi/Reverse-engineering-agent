"""
OS Kernel Agent Implementation
Specialized agent for analyzing operating system kernels, system calls, and kernel-level behavior
"""

import asyncio
import logging
import re
from typing import Dict, Any, List, Optional
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


class OsKernelAgent(AnalysisAgent):
    """Agent specialized in OS kernel analysis using crash, objdump, readelf, strings, and related tools"""

    def __init__(self, agent_id: str = None, name: str = "OS Kernel Agent"):
        super().__init__(
            agent_id=agent_id or f"kernel_agent_{id(self)}",
            name=name,
            description="Analyzes operating system kernels, system calls, kernel modules, and low-level system behavior",
        )
        self.agent_type = "os_kernel"
        self.supported_formats = {
            "vmlinuz", "bzImage", "kernel", "elf", "ko", "kallsyms",
            "system_map", "proc", "sys", "dev", "core_dump", "vmcore",
        }
        self.analysis_tools: Dict[str, bool] = {}

    async def initialize(self) -> bool:
        """Initialize the OS kernel agent"""
        try:
            self.logger.info("Initializing OS Kernel Agent")
            await self._check_available_tools()
            self.logger.info("OS Kernel Agent initialized successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize OS Kernel Agent: {e}")
            return False

    async def _check_available_tools(self):
        """Check which analysis tools are available on the system"""
        self.analysis_tools = {
            "objdump": check_tool_available("objdump"),
            "readelf": check_tool_available("readelf"),
            "strings": check_tool_available("strings"),
            "file": check_tool_available("file"),
            "hexdump": check_tool_available("hexdump"),
        }
        available_count = sum(1 for v in self.analysis_tools.values() if v)
        self.logger.info(
            f"Available OS kernel analysis tools: {available_count}/{len(self.analysis_tools)}"
        )

    async def execute_task(self, task: Task) -> AgentResult:
        """Execute an OS kernel analysis task"""
        self.logger.info(f"Executing OS kernel analysis task: {task.description}")
        self.status = AgentStatus.PROCESSING

        tools_used: List[str] = []
        reasoning_trace: List[Dict[str, Any]] = []

        try:
            params = task.parameters or {}
            file_path = params.get("file_path")
            analysis_type = params.get("analysis_type", "comprehensive")

            if not file_path:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    status="failed",
                    error="No file_path provided in task parameters",
                    result={},
                )

            if not Path(file_path).exists():
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    status="failed",
                    error=f"File not found: {file_path}",
                    result={},
                )

            reasoning_trace.append({
                "step": "dispatch",
                "detail": f"analysis_type={analysis_type}, file={file_path}",
            })

            analysis_map = {
                "basic": self._basic_analysis,
                "system_calls": self._system_call_analysis,
                "modules": self._kernel_module_analysis,
                "memory_management": self._memory_management_analysis,
                "scheduling": self._scheduling_analysis,
                "security": self._security_analysis,
                "drivers": self._driver_analysis,
                "comprehensive": self._comprehensive_analysis,
            }

            if analysis_type not in analysis_map:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    status="failed",
                    error=f"Unknown analysis type: {analysis_type}",
                    result={},
                )

            analysis_result = await analysis_map[analysis_type](file_path, params)

            await self._store_analysis_results(file_path, analysis_type, analysis_result)

            tool_summary = self._build_tool_summary()

            llm_analysis = await self._run_llm_analysis(analysis_result)
            if llm_analysis:
                reasoning_trace.append({
                    "step": "llm_interpretation",
                    "detail": f"llm_findings={len(llm_analysis.get('key_findings', []))}",
                })

            critique = await self._run_self_critique(tool_summary, analysis_result)
            if critique:
                reasoning_trace.append({
                    "step": "self_critique",
                    "detail": f"score={critique.get('score', 'N/A')}",
                })

            knowledge_extraction = None
            if llm_analysis:
                knowledge_extraction = await self._run_knowledge_extraction(analysis_result, llm_analysis)
                if knowledge_extraction:
                    reasoning_trace.append({
                        "step": "knowledge_extraction",
                        "detail": f"facts={len(knowledge_extraction.get('facts_stored', []))}, "
                                   f"hypotheses={len(knowledge_extraction.get('hypotheses_stored', []))}",
                    })

            await self._store_with_rag(
                analysis_result, tags=["os_kernel", analysis_type]
            )

            self.status = AgentStatus.IDLE
            agent_result = AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                status="completed",
                result=analysis_result,
                reasoning_trace=reasoning_trace,
                tools_used=tools_used,
                llm_analysis=llm_analysis,
                critique=critique,
                knowledge_extraction=knowledge_extraction,
            )
            self._compute_confidence(agent_result)
            return agent_result

        except Exception as e:
            self.logger.error(
                f"Error executing OS kernel analysis task: {e}", exc_info=True
            )
            self.status = AgentStatus.ERROR
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                status="failed",
                error=str(e),
                result={},
                reasoning_trace=reasoning_trace,
                tools_used=tools_used,
            )
        finally:
            if self.status != AgentStatus.ERROR:
                self.status = AgentStatus.IDLE

    async def cleanup(self) -> bool:
        """Clean up resources"""
        self.logger.info("OS Kernel Agent cleaned up")
        return True

    # ------------------------------------------------------------------
    # Basic analysis
    # ------------------------------------------------------------------

    async def _basic_analysis(
        self, file_path: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform basic kernel analysis: file type, version strings, ELF header"""
        self.logger.info(f"Performing basic kernel analysis on {file_path}")

        file_result = await run_file(file_path)
        file_type = file_result.stdout.strip() if file_result.success else "Unknown"

        strings_result = await run_strings(file_path, min_length=8)
        all_strings = strings_result.stdout.splitlines() if strings_result.success else []

        kernel_version = "Unknown"
        compiler_info = "Unknown"
        architecture = "Unknown"

        version_pattern = re.compile(
            r"Linux version\s+(\d+\.\d+[\.\d]*)", re.IGNORECASE
        )
        for line in all_strings:
            m = version_pattern.search(line)
            if m:
                kernel_version = m.group(1)
                break

        compiler_pattern = re.compile(
            r"(GCC|gcc|Clang|clang)\s+version\s+([\d.]+)", re.IGNORECASE
        )
        for line in all_strings:
            m = compiler_pattern.search(line)
            if m:
                compiler_info = f"{m.group(1)} version {m.group(2)}"
                break

        arch_pattern = re.compile(
            r"(x86_64|aarch64|armv[4-8]|i[3-6]86|mips|powerpc|s390|riscv)",
            re.IGNORECASE,
        )
        for line in all_strings:
            m = arch_pattern.search(line)
            if m:
                architecture = m.group(1).lower()
                break

        is_elf = False
        elf_header_info: Dict[str, Any] = {}
        if "ELF" in file_type:
            is_elf = True
            readelf_result = await run_readelf(file_path, ["-h"])
            if readelf_result.success:
                elf_header_info = _parse_elf_header(readelf_result.stdout)
                if not architecture or architecture == "Unknown":
                    machine = elf_header_info.get("Machine", "")
                    machine_map = {
                        "X86-64": "x86_64",
                        "Intel 80386": "i386",
                        "AArch64": "aarch64",
                        "ARM": "armv7",
                        "MIPS R3000": "mips",
                        "PowerPC": "powerpc",
                        "IBM S/390": "s390",
                        "RISC-V": "riscv",
                    }
                    for key, val in machine_map.items():
                        if key.lower() in machine.lower():
                            architecture = val
                            break

        config_options = {}
        config_pattern = re.compile(r"CONFIG_(\w+)=(\w+)")
        for line in all_strings:
            m = config_pattern.search(line)
            if m:
                config_options[m.group(1)] = m.group(2)

        boot_args = ""
        for line in all_strings:
            if "BOOT_IMAGE" in line or "root=" in line:
                boot_args = line.strip()
                break

        result = {
            "file_path": file_path,
            "file_size": Path(file_path).stat().st_size,
            "file_type": file_type,
            "kernel_version": kernel_version,
            "architecture": architecture,
            "compiler": compiler_info,
            "is_elf": is_elf,
            "elf_header": elf_header_info,
            "config_options_found": config_options,
            "boot_args": boot_args,
            "strings_count": len(all_strings),
        }
        return result

    # ------------------------------------------------------------------
    # System call analysis
    # ------------------------------------------------------------------

    async def _system_call_analysis(
        self, file_path: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze system call patterns via disassembly and strings"""
        self.logger.info(f"Performing system call analysis on {file_path}")

        syscall_invocations: List[str] = []
        try:
            objdump_result = await run_objdump(
                file_path, ["-d", "-j", ".text"], timeout=180
            )
            if objdump_result.success:
                for line in objdump_result.stdout.splitlines():
                    lower = line.lower()
                    if any(
                        pat in lower
                        for pat in ("svc #0", "svc 0", "int $0x80", "syscall", "sysenter")
                    ):
                        syscall_invocations.append(line.strip())
        except Exception as e:
            self.logger.warning(f"objdump disassembly failed: {e}")

        syscall_names_found: List[str] = []
        strings_result = await run_strings(file_path, min_length=6)
        if strings_result.success:
            name_pattern = re.compile(
                r"^(sys_[a-z_0-9]+|__x64_sys_[a-z_0-9]+|__arm64_sys_[a-z_0-9]+)$"
            )
            seen = set()
            for line in strings_result.stdout.splitlines():
                m = name_pattern.match(line.strip())
                if m:
                    name = m.group(1)
                    if name not in seen:
                        seen.add(name)
                        syscall_names_found.append(name)

        return {
            "file_path": file_path,
            "analysis_type": "system_calls",
            "syscall_instructions_found": len(syscall_invocations),
            "syscall_instructions_sample": syscall_invocations[:50],
            "syscall_names_from_strings": sorted(syscall_names_found),
            "syscall_names_count": len(syscall_names_found),
        }

    # ------------------------------------------------------------------
    # Kernel module analysis
    # ------------------------------------------------------------------

    async def _kernel_module_analysis(
        self, file_path: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze kernel modules via symbol table and module-related strings"""
        self.logger.info(f"Performing kernel module analysis on {file_path}")

        exported_symbols: List[Dict[str, str]] = []
        readelf_result = await run_readelf(file_path, ["--symbols"])
        if readelf_result.success:
            for line in readelf_result.stdout.splitlines():
                if not line.startswith("    ") and not line.startswith("  "):
                    continue
                parts = line.split()
                if len(parts) < 8:
                    continue
                sym_name = parts[-1]
                sym_type = parts[-2] if len(parts) > 2 else ""
                sym_bind = parts[-3] if len(parts) > 3 else ""
                sym_size = parts[-4] if len(parts) > 4 else ""
                sym_val = parts[-5] if len(parts) > 5 else ""
                if sym_type in ("FUNC", "OBJECT"):
                    exported_symbols.append({
                        "name": sym_name,
                        "type": sym_type,
                        "binding": sym_bind,
                        "value": sym_val,
                        "size": sym_size,
                    })

        module_strings_found: List[str] = []
        strings_result = await run_strings(file_path, min_length=8)
        if strings_result.success:
            module_pattern = re.compile(
                r"(module_|_init|_exit|insmod|rmmod|modprobe|MODULE_LICENSE|MODULE_AUTHOR|EXPORT_SYMBOL)",
                re.IGNORECASE,
            )
            seen = set()
            for line in strings_result.stdout.splitlines():
                if module_pattern.search(line) and line.strip() not in seen:
                    seen.add(line.strip())
                    module_strings_found.append(line.strip())

        license_strings = [
            s for s in module_strings_found if "LICENSE" in s.upper()
        ]

        return {
            "file_path": file_path,
            "analysis_type": "modules",
            "exported_symbols_count": len(exported_symbols),
            "exported_symbols_sample": exported_symbols[:100],
            "module_related_strings": module_strings_found[:200],
            "license_strings": license_strings,
        }

    # ------------------------------------------------------------------
    # Memory management (simulated – needs live kernel / crash dump)
    # ------------------------------------------------------------------

    async def _memory_management_analysis(
        self, file_path: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze kernel memory management. Simulated – requires live kernel or crash dump."""
        self.logger.info(f"Performing memory management analysis on {file_path}")

        mem_strings: List[str] = []
        strings_result = await run_strings(file_path, min_length=8)
        if strings_result.success:
            mem_keywords = (
                "slab", "vmalloc", "kmem_cache", "page_alloc", "swap",
                "oom", "kasan", "kmemleak", "hugetlb", "cma",
            )
            for line in strings_result.stdout.splitlines():
                if any(kw in line.lower() for kw in mem_keywords):
                    mem_strings.append(line.strip())

        return {
            "file_path": file_path,
            "analysis_type": "memory_management",
            "note": "Live kernel or crash dump required for full analysis",
            "memory_related_strings": mem_strings[:200],
            "virtual_memory_layout": {},
            "slab_allocator": {},
            "page_allocator": {},
            "memory_protections": {},
            "potential_issues": [],
        }

    # ------------------------------------------------------------------
    # Scheduling (simulated – needs live kernel / crash dump)
    # ------------------------------------------------------------------

    async def _scheduling_analysis(
        self, file_path: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze process scheduling. Simulated – requires live kernel or crash dump."""
        self.logger.info(f"Performing scheduling analysis on {file_path}")

        sched_strings: List[str] = []
        strings_result = await run_strings(file_path, min_length=8)
        if strings_result.success:
            sched_keywords = (
                "scheduler", "cfs", "rt_sched", "deadline", "fair",
                "runqueue", "context_switch", "load_balance",
            )
            for line in strings_result.stdout.splitlines():
                if any(kw in line.lower() for kw in sched_keywords):
                    sched_strings.append(line.strip())

        return {
            "file_path": file_path,
            "analysis_type": "scheduling",
            "note": "Live kernel or crash dump required for full analysis",
            "scheduler_type": "Unknown",
            "scheduling_related_strings": sched_strings[:200],
            "run_queue_stats": {},
            "scheduling_entities": [],
            "load_balancing": {},
            "real_time_scheduling": {},
            "potential_issues": [],
        }

    # ------------------------------------------------------------------
    # Security analysis
    # ------------------------------------------------------------------

    async def _security_analysis(
        self, file_path: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze kernel security features via disassembly patterns and strings"""
        self.logger.info(f"Performing security analysis on {file_path}")

        security_patterns_found: List[str] = []
        try:
            objdump_result = await run_objdump(file_path, ["-d"], timeout=300)
            if objdump_result.success:
                security_asm_patterns = [
                    (r"smep", "SMEP (Supervisor Mode Execution Prevention) hint"),
                    (r"smap", "SMAP (Supervisor Mode Access Prevention) hint"),
                    (r"encl[uu]", "SGX enclave instruction"),
                    (r"lxsAVE", "XSAVE area load (FPU state protection)"),
                    (r"swapgs", "GS base swap (kernel/userspace transition)"),
                    (r"sysret", "SYSRET instruction"),
                    (r"swapgs", "GS base swap"),
                ]
                seen = set()
                for line in objdump_result.stdout.splitlines():
                    lower = line.lower()
                    for pat, desc in security_asm_patterns:
                        if pat.lower() in lower and desc not in seen:
                            seen.add(desc)
                            security_patterns_found.append(
                                {"pattern": desc, "assembly": line.strip()}
                            )
        except Exception as e:
            self.logger.warning(f"Security disassembly failed: {e}")

        security_config_strings: List[str] = []
        config_security_keys = (
            "KASAN", "KASLR", "KASAN_INLINE", "KASAN_OUTLINE",
            "PANIC_ON_OOPS", "HARDENED_USERCOPY", "STRICT_DEVMEM",
            "IO_STRICT_DEVMEM", "STATIC_USERMODEHELPER", "STACKPROTECTOR",
            "RODATA", "DEBUG_RODATA", "PAGEALLOC", "DEBUG_PAGEALLOC",
            "RETPOLINE", "MITIGATION", "CFI_CLANG", "SHADOW_CALL_STACK",
            "ARM64_PAN", "ARM64_UAO",
        )
        strings_result = await run_strings(file_path, min_length=6)
        if strings_result.success:
            seen = set()
            for line in strings_result.stdout.splitlines():
                upper = line.upper().strip()
                for key in config_security_keys:
                    if key in upper and line.strip() not in seen:
                        seen.add(line.strip())
                        security_config_strings.append(line.strip())

        mitigations: Dict[str, Any] = {}
        for s in security_config_strings:
            upper = s.upper()
            if "KASLR" in upper:
                mitigations["KASLR"] = True
            if "KASAN" in upper:
                mitigations["KASAN"] = True
            if "RETPOLINE" in upper:
                mitigations["RETPOLINE"] = True
            if "SMEP" in upper:
                mitigations["SMEP"] = True
            if "SMAP" in upper:
                mitigations["SMAP"] = True
            if "PAN" in upper:
                mitigations["PAN"] = True
            if "STACKPROTECTOR" in upper:
                mitigations["STACKPROTECTOR"] = True
            if "PAGEALLOC" in upper and "DEBUG" in upper:
                mitigations["DEBUG_PAGEALLOC"] = True
            if "RODATA" in upper:
                mitigations["READ_ONLY_DATA"] = True
            if "SHADOW_CALL_STACK" in upper:
                mitigations["SHADOW_CALL_STACK"] = True

        return {
            "file_path": file_path,
            "analysis_type": "security",
            "security_asm_patterns": security_patterns_found,
            "security_config_strings": security_config_strings[:200],
            "detected_mitigations": mitigations,
            "attack_surface": {
                "syscall_invocations_detected": "see system_calls analysis",
            },
            "recommendations": _generate_security_recommendations(mitigations),
        }

    # ------------------------------------------------------------------
    # Driver analysis (simulated)
    # ------------------------------------------------------------------

    async def _driver_analysis(
        self, file_path: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze kernel drivers. Partially simulated."""
        self.logger.info(f"Performing driver analysis on {file_path}")

        driver_strings: List[str] = []
        strings_result = await run_strings(file_path, min_length=8)
        if strings_result.success:
            driver_pattern = re.compile(
                r"(drivers/|\.ko\b|pci_driver|platform_driver|usb_driver|net_device_ops)",
            )
            seen = set()
            for line in strings_result.stdout.splitlines():
                if driver_pattern.search(line) and line.strip() not in seen:
                    seen.add(line.strip())
                    driver_strings.append(line.strip())

        return {
            "file_path": file_path,
            "analysis_type": "drivers",
            "driver_related_strings": driver_strings[:200],
            "drivers_found": [],
            "driver_interfaces": {},
            "resource_usage": {},
            "potential_issues": [],
        }

    # ------------------------------------------------------------------
    # Comprehensive analysis
    # ------------------------------------------------------------------

    async def _comprehensive_analysis(
        self, file_path: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform comprehensive OS kernel analysis"""
        self.logger.info(f"Performing comprehensive kernel analysis on {file_path}")

        basic_result = await self._basic_analysis(file_path, {})
        syscall_result = await self._system_call_analysis(file_path, {})
        module_result = await self._kernel_module_analysis(file_path, {})
        mem_result = await self._memory_management_analysis(file_path, {})
        sched_result = await self._scheduling_analysis(file_path, {})
        sec_result = await self._security_analysis(file_path, {})
        driver_result = await self._driver_analysis(file_path, {})

        result = {
            "file_path": file_path,
            "basic_info": basic_result,
            "system_calls": syscall_result,
            "modules": module_result,
            "memory_management": mem_result,
            "scheduling": sched_result,
            "security": sec_result,
            "drivers": driver_result,
            "summary": {
                "kernel_version": basic_result.get("kernel_version", "unknown"),
                "architecture": basic_result.get("architecture", "unknown"),
                "compiler": basic_result.get("compiler", "unknown"),
                "file_type": basic_result.get("file_type", "unknown"),
                "is_elf": basic_result.get("is_elf", False),
                "syscall_instructions": syscall_result.get(
                    "syscall_instructions_found", 0
                ),
                "syscall_names_count": syscall_result.get("syscall_names_count", 0),
                "exported_symbols": module_result.get("exported_symbols_count", 0),
                "detected_mitigations": list(
                    sec_result.get("detected_mitigations", {}).keys()
                ),
            },
        }
        return result

    # ------------------------------------------------------------------
    # Knowledge base storage
    # ------------------------------------------------------------------

    async def _store_analysis_results(
        self, file_path: str, analysis_type: str, result: Dict[str, Any]
    ):
        """Store analysis results in the knowledge base"""
        try:
            fact_title = f"OS kernel analysis of {Path(file_path).name}"
            fact_description = (
                f"Completed {analysis_type} analysis of OS kernel file {file_path}"
            )

            key_findings = []
            if "summary" in result:
                summary = result["summary"]
                key_findings.append(f"Version: {summary.get('kernel_version', 'unknown')}")
                key_findings.append(f"Architecture: {summary.get('architecture', 'unknown')}")
                key_findings.append(f"Compiler: {summary.get('compiler', 'unknown')}")
            if "basic_info" in result:
                basic = result["basic_info"]
                key_findings.append(f"File type: {basic.get('file_type', 'unknown')}")
                key_findings.append(f"Strings count: {basic.get('strings_count', 0)}")
            if "system_calls" in result:
                sc = result["system_calls"]
                key_findings.append(
                    f"Syscall instructions: {sc.get('syscall_instructions_found', 0)}"
                )
                key_findings.append(
                    f"Syscall names found: {sc.get('syscall_names_count', 0)}"
                )
            if "security" in result:
                sec = result["security"]
                key_findings.append(
                    f"Mitigations: {list(sec.get('detected_mitigations', {}).keys())}"
                )

            fact_description += ". " + "; ".join(key_findings)

            fact_id = add_fact(
                title=fact_title,
                description=fact_description,
                confidence=0.8,
                evidence=[f"OS kernel analysis of {file_path} using {analysis_type} analysis"],
                source_references=[file_path],
                tags=["os_kernel", analysis_type, "automated_analysis"],
                source_agent=self.agent_id,
            )

            self.logger.info(
                f"Stored OS kernel analysis results in knowledge base (fact ID: {fact_id})"
            )
        except Exception as e:
            self.logger.error(f"Failed to store OS kernel analysis results: {e}")

    # ------------------------------------------------------------------
    # Capabilities / info
    # ------------------------------------------------------------------

    def get_capabilities(self) -> Dict[str, Any]:
        """Get the capabilities of this agent"""
        return {
            "agent_type": self.agent_type,
            "supported_analyses": [
                "basic", "system_calls", "modules", "memory_management",
                "scheduling", "security", "drivers", "comprehensive",
            ],
            "supported_formats": list(self.supported_formats),
            "available_tools": {
                k: v for k, v in self.analysis_tools.items() if v
            },
        }


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _parse_elf_header(readelf_output: str) -> Dict[str, str]:
    """Parse `readelf -h` output into a dict."""
    info: Dict[str, str] = {}
    for line in readelf_output.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            info[key.strip()] = value.strip()
    return info


def _generate_security_recommendations(
    detected_mitigations: Dict[str, Any],
) -> List[Dict[str, str]]:
    """Generate security recommendations based on what was detected (or missing)."""
    recommendations: List[Dict[str, str]] = []
    required = {
        "KASLR": "Enable KASLR for kernel address space layout randomization",
        "RETPOLINE": "Enable RETPOLINE to mitigate Spectre v2",
        "STACKPROTECTOR": "Enable stack protector for stack buffer overflow detection",
        "READ_ONLY_DATA": "Enable read-only data section to prevent kernel text corruption",
        "HARDENED_USERCOPY": "Enable hardened usercopy to bound-check copies from userspace",
    }
    for feature, reason in required.items():
        if feature not in detected_mitigations:
            recommendations.append({
                "feature": feature,
                "action": reason,
                "severity": "high",
            })

    if "KASAN" not in detected_mitigations:
        recommendations.append({
            "feature": "KASAN",
            "action": "Consider enabling KASAN for runtime memory error detection (debug builds)",
            "severity": "medium",
        })
    if "DEBUG_PAGEALLOC" not in detected_mitigations:
        recommendations.append({
            "feature": "DEBUG_PAGEALLOC",
            "action": "Consider enabling DEBUG_PAGEALLOC to detect use-after-free (debug builds)",
            "severity": "low",
        })
    return recommendations


# --------------------------------------------------------------------------
# Factory
# --------------------------------------------------------------------------

def create_os_kernel_agent(agent_id: str = None) -> OsKernelAgent:
    """Create an OS kernel agent"""
    return OsKernelAgent(agent_id=agent_id)


# --------------------------------------------------------------------------
# Manual test
# --------------------------------------------------------------------------

if __name__ == "__main__":
    import logging
    import json

    logging.basicConfig(level=logging.INFO)

    async def test_os_kernel_agent():
        agent = create_os_kernel_agent("kernel_agent_001")
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
            description="Analyze kernel binary",
            agent_type="os_kernel",
            priority=2,
            parameters={
                "file_path": "/boot/vmlinuz-$(uname -r)",
                "analysis_type": "comprehensive",
            },
        )

        print("Executing test task...")
        result = await agent.execute_task(test_task)
        print(f"Task result: {json.dumps(result.__dict__, indent=2, default=str)}")

        await agent.cleanup()
        print("Agent cleaned up")

    asyncio.run(test_os_kernel_agent())
