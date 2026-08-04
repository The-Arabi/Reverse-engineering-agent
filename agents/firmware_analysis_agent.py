"""
Firmware Analysis Agent Implementation
Specialized agent for analyzing firmware images using real tool calls
"""

import asyncio
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents.base_agent import AnalysisAgent, AgentResult, AgentStatus, Task
from agents.tool_runner import (
    check_tool_available,
    run_binwalk,
    run_file,
    run_hexdump,
    run_strings,
)
from knowledge_base import add_fact, add_hypothesis, kb

logger = logging.getLogger(__name__)


class FirmwareAnalysisAgent(AnalysisAgent):
    """Agent specialized in firmware analysis using binwalk, strings, and file commands."""

    def __init__(self, agent_id: str = None, name: str = "Firmware Analysis Agent"):
        super().__init__(
            agent_id=agent_id or f"firmware_agent_{id(self)}",
            name=name,
            description="Analyzes firmware images to extract file systems, identify components, and understand structure",
        )
        self.agent_type = "firmware_analysis"
        self.supported_formats = {
            "binary", "firmware", "img", "bin", "elf", "squashfs",
            "cramfs", "jffs2", "yaffs2", "ext4", "ntfs", "fat",
        }
        self.analysis_tools: Dict[str, bool] = {
            "binwalk": False,
            "strings": False,
            "file": False,
            "hexdump": False,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> bool:
        """Initialize the firmware analysis agent."""
        try:
            self.logger.info("Initializing Firmware Analysis Agent")
            await self._check_available_tools()
            self.logger.info("Firmware Analysis Agent initialized successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize Firmware Analysis Agent: {e}")
            return False

    async def _check_available_tools(self) -> None:
        """Check which analysis tools are actually installed on PATH."""
        self.analysis_tools = {
            "binwalk": check_tool_available("binwalk"),
            "strings": check_tool_available("strings"),
            "file": check_tool_available("file"),
            "hexdump": check_tool_available("hexdump"),
        }
        available = sum(1 for v in self.analysis_tools.values() if v)
        self.logger.info(
            f"Available firmware analysis tools: {available}/{len(self.analysis_tools)}"
        )

    async def cleanup(self) -> bool:
        """Clean up resources."""
        self.logger.info("Firmware Analysis Agent cleaned up")
        return True

    # ------------------------------------------------------------------
    # Task execution
    # ------------------------------------------------------------------

    async def execute_task(self, task: Task) -> AgentResult:
        """Execute a firmware analysis task."""
        self.logger.info(f"Executing firmware analysis task: {task.description}")
        self.status = AgentStatus.PROCESSING

        result = AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            status="pending",
        )

        try:
            params = task.parameters or {}
            file_path = params.get("file_path")
            analysis_type = params.get("analysis_type", "comprehensive")

            if not file_path:
                result.status = "failed"
                result.error = "No file_path provided in task parameters"
                return result

            if not Path(file_path).exists():
                result.status = "failed"
                result.error = f"File not found: {file_path}"
                return result

            result.add_reasoning_step(
                "receive_task",
                detail=f"analysis_type={analysis_type}, file={file_path}",
            )

            if analysis_type == "basic":
                data = await self._basic_analysis(file_path, result)
            elif analysis_type == "filesystem":
                data = await self._filesystem_analysis(file_path, result)
            elif analysis_type == "components":
                data = await self._component_analysis(file_path, result)
            elif analysis_type == "security":
                data = await self._security_analysis(file_path, result)
            elif analysis_type == "comprehensive":
                data = await self._comprehensive_analysis(file_path, result)
            else:
                result.status = "failed"
                result.error = f"Unknown analysis type: {analysis_type}"
                return result

            await self._store_analysis_results(file_path, analysis_type, data)

            tool_summary = self._build_tool_summary()

            llm_analysis = await self._run_llm_analysis(data)
            if llm_analysis:
                result.add_reasoning_step(
                    "llm_interpretation",
                    detail=f"llm_findings={len(llm_analysis.get('key_findings', []))}",
                )
                result.llm_analysis = llm_analysis

            critique = await self._run_self_critique(tool_summary, data)
            if critique:
                result.add_reasoning_step(
                    "self_critique",
                    detail=f"score={critique.get('score', 'N/A')}",
                )
                result.critique = critique

            if llm_analysis:
                extraction = await self._run_knowledge_extraction(data, llm_analysis)
                if extraction:
                    result.add_reasoning_step(
                        "knowledge_extraction",
                        detail=f"facts={len(extraction.get('facts_stored', []))}, "
                               f"hypotheses={len(extraction.get('hypotheses_stored', []))}",
                    )
                    result.knowledge_extraction = extraction

            await self._store_with_rag(
                data, tags=["firmware_analysis", analysis_type]
            )

            result.status = "completed"
            result.result = data
            self._compute_confidence(result)
            result.add_reasoning_step("analysis_complete", detail=f"analysis_type={analysis_type}")

        except Exception as e:
            self.logger.error(f"Error executing firmware analysis task: {e}", exc_info=True)
            self.status = AgentStatus.ERROR
            result.status = "failed"
            result.error = str(e)
        finally:
            if self.status != AgentStatus.ERROR:
                self.status = AgentStatus.IDLE

        return result

    # ------------------------------------------------------------------
    # Basic analysis
    # ------------------------------------------------------------------

    async def _basic_analysis(
        self, file_path: str, result: AgentResult
    ) -> Dict[str, Any]:
        """Run file(1) and binwalk --signature to identify the firmware."""
        result.add_reasoning_step("basic_analysis_start", detail=file_path)

        file_info = await run_file(file_path)
        self.record_tool_output("file", file_info.command, file_info.stdout, file_info.stderr, file_info.returncode)
        result.add_reasoning_step(
            "run_file",
            detail=file_info.stdout.strip(),
            tool="file",
        )

        file_type = file_info.stdout.strip() if file_info.success else "Unknown"

        size = os.path.getsize(file_path)
        result.add_reasoning_step("file_size", detail=f"{size} bytes ({size / (1024*1024):.2f} MB)")

        signatures: List[Dict[str, str]] = []
        binwalk_scan = await run_binwalk(file_path, scan_only=True)
        self.record_tool_output(
            "binwalk", binwalk_scan.command,
            binwalk_scan.stdout, binwalk_scan.stderr, binwalk_scan.returncode,
        )
        result.add_reasoning_step(
            "binwalk_scan",
            detail=f"{len(binwalk_scan.stdout.splitlines())} lines of output",
            tool="binwalk",
        )

        if binwalk_scan.success:
            for line in binwalk_scan.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    try:
                        offset = int(parts[0])
                        signatures.append({
                            "offset": f"0x{offset:08X}",
                            "size": parts[1] if len(parts) > 1 else "",
                            "description": parts[2] if len(parts) > 2 else "",
                        })
                    except ValueError:
                        if parts[0].startswith("0x"):
                            signatures.append({
                                "offset": parts[0],
                                "size": parts[1] if len(parts) > 1 else "",
                                "description": parts[2] if len(parts) > 2 else "",
                            })

        result.add_reasoning_step(
            "signatures_identified",
            detail=f"{len(signatures)} signatures found",
        )

        architecture = "Unknown"
        for sig in signatures:
            desc = sig["description"].lower()
            if "arm" in desc:
                architecture = "ARM"
            elif "mips" in desc:
                architecture = "MIPS"
            elif "x86" in desc:
                architecture = "x86"
            elif "powerpc" in desc:
                architecture = "PowerPC"

        file_system_types = []
        compression_types = []
        for sig in signatures:
            desc = sig["description"].lower()
            if any(fs in desc for fs in ("squashfs", "jffs2", "yaffs", "cramfs", "ext2", "ext3", "ext4", "romfs")):
                file_system_types.append(sig["description"])
            if any(c in desc for c in ("gzip", "lzma", "lzma", "bzip2", "xz", "zlib", "zstd")):
                compression_types.append(sig["description"])

        return {
            "file_path": file_path,
            "file_size": size,
            "file_type": file_type,
            "architecture": architecture,
            "signatures": signatures,
            "file_system_signatures": file_system_types,
            "compression_signatures": compression_types,
            "binwalk_raw": binwalk_scan.stdout if binwalk_scan.success else "",
            "analysis_timestamp": datetime.now().isoformat(),
        }

    # ------------------------------------------------------------------
    # Filesystem extraction & analysis
    # ------------------------------------------------------------------

    async def _filesystem_analysis(
        self, file_path: str, result: AgentResult
    ) -> Dict[str, Any]:
        """Extract firmware and walk the resulting directory tree."""
        result.add_reasoning_step("filesystem_analysis_start", detail=file_path)

        extract_dir = str(Path(file_path).parent / f"{Path(file_path).name}_extracted")
        os.makedirs(extract_dir, exist_ok=True)

        result.add_reasoning_step("binwalk_extract", detail=f"target dir: {extract_dir}", tool="binwalk")
        extract_res = await run_binwalk(file_path, extract=True)
        self.record_tool_output(
            "binwalk", extract_res.command,
            extract_res.stdout, extract_res.stderr, extract_res.returncode,
        )

        result.add_reasoning_step(
            "binwalk_extract_result",
            detail=f"returncode={extract_res.returncode}",
        )

        extracted_files: List[Dict[str, Any]] = []
        search_dir = extract_dir

        for candidate in [
            extract_dir,
            str(Path(file_path).parent / "squashfs-root"),
            str(Path(file_path).parent / f"{Path(file_path).name}.extracted"),
        ]:
            if os.path.isdir(candidate):
                search_dir = candidate
                break

        if os.path.isdir(search_dir):
            for root, dirs, files in os.walk(search_dir):
                for fname in files:
                    full_path = os.path.join(root, fname)
                    rel_path = os.path.relpath(full_path, search_dir)
                    try:
                        fstat = os.stat(full_path)
                    except OSError:
                        continue

                    ftype = "file"
                    fl = fname.lower()
                    if os.access(full_path, os.X_OK):
                        ftype = "executable"
                    elif any(fl.endswith(ext) for ext in (".conf", ".cfg", ".ini", ".json", ".yaml", ".yml", ".xml")):
                        ftype = "config"
                    elif fl.endswith((".so", ".so.", ".so.0", ".so.1", ".a")):
                        ftype = "library"
                    elif fl.endswith((".html", ".htm", ".js", ".css")):
                        ftype = "web"
                    elif fl.endswith((".sh", ".bash", ".rc", "S99*", "rcS")):
                        ftype = "script"
                    elif fl.endswith((".pem", ".key", ".crt", ".cer")):
                        ftype = "certificate"
                    elif fl.endswith((".txt", ".log")):
                        ftype = "text"

                    extracted_files.append({
                        "path": f"/{rel_path}",
                        "size": fstat.st_size,
                        "type": ftype,
                        "executable": os.access(full_path, os.X_OK),
                    })

        result.add_reasoning_step(
            "files_categorized",
            detail=f"{len(extracted_files)} files found under {search_dir}",
        )

        interesting = self._find_interesting_files(extracted_files)
        result.add_reasoning_step(
            "interesting_files_identified",
            detail=f"{len(interesting)} interesting files",
        )

        categories = {"executables": [], "configs": [], "libraries": [], "scripts": [], "certificates": [], "web": []}
        for f in extracted_files:
            t = f["type"]
            if t == "executable":
                categories["executables"].append(f["path"])
            elif t == "config":
                categories["configs"].append(f["path"])
            elif t == "library":
                categories["libraries"].append(f["path"])
            elif t == "script":
                categories["scripts"].append(f["path"])
            elif t == "certificate":
                categories["certificates"].append(f["path"])
            elif t == "web":
                categories["web"].append(f["path"])

        return {
            "file_path": file_path,
            "extraction_dir": search_dir,
            "extraction_returncode": extract_res.returncode,
            "extracted_files": extracted_files,
            "file_categories": categories,
            "interesting_files": interesting,
            "binwalk_output": extract_res.stdout if extract_res.success else "",
            "analysis_timestamp": datetime.now().isoformat(),
        }

    @staticmethod
    def _find_interesting_files(files: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Heuristically pick out files of security interest."""
        interesting: List[Dict[str, str]] = []
        interesting_patterns = {
            "passwd": "User account data",
            "shadow": "Password hashes",
            "hosts": "Network configuration",
            "wpa_supplicant": "Wi-Fi credentials",
            "hostapd": "Access-point configuration",
            "dropbear": "SSH server binary",
            "sshd": "SSH daemon configuration",
            "telnetd": "Telnet daemon (insecure)",
            "busybox": "Multi-call binary (common attack surface)",
            "httpd": "HTTP daemon",
            "lighttpd": "HTTP daemon",
            "u-boot": "U-Boot bootloader",
            "init.d": "Init scripts",
            "rcS": "System startup script",
            "S99": "Startup script",
            ".pem": "Private key material",
            ".key": "Private key material",
            "credentials": "Credentials file",
            "secret": "Secret / API key",
            "password": "Password file",
            "cert.pem": "Certificate",
            "mosquitto.conf": "MQTT broker config",
        }

        for f in files:
            path_lower = f["path"].lower()
            for pattern, reason in interesting_patterns.items():
                if pattern in path_lower:
                    interesting.append({"path": f["path"], "reason": reason})
                    break

        return interesting

    # ------------------------------------------------------------------
    # Component analysis
    # ------------------------------------------------------------------

    async def _component_analysis(
        self, file_path: str, result: AgentResult
    ) -> Dict[str, Any]:
        """Use binwalk scan to identify bootloader, kernel, and filesystem regions."""
        result.add_reasoning_step("component_analysis_start", detail=file_path)

        scan = await run_binwalk(file_path, scan_only=True)
        self.record_tool_output("binwalk", scan.command, scan.stdout, scan.stderr, scan.returncode)
        result.add_reasoning_step("binwalk_component_scan", detail=scan.stdout[:500] if scan.success else "failed", tool="binwalk")

        bootloader = None
        kernel = None
        rootfs = None
        other_components: List[Dict[str, str]] = []

        if scan.success:
            for line in scan.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                desc_lower = line.lower()
                parts = line.split(None, 2)
                offset = parts[0] if parts else ""

                if any(k in desc_lower for k in ("u-boot", "bootloader", "boot loader")):
                    bootloader = {"description": line, "offset": offset}
                elif any(k in desc_lower for k in ("linux kernel", "kernel image", "zimage", "uimage", "lzma")):
                    if "kernel" not in desc_lower and kernel is None:
                        pass
                    kernel = {"description": line, "offset": offset}
                elif any(k in desc_lower for k in ("squashfs", "jffs2", "yaffs", "cramfs", "romfs", "ext2", "ext3", "ext4", "rootfs")):
                    rootfs = {"description": line, "offset": offset}
                else:
                    other_components.append({"description": line, "offset": offset})

        result.add_reasoning_step(
            "components_identified",
            detail={
                "bootloader": bool(bootloader),
                "kernel": bool(kernel),
                "rootfs": bool(rootfs),
                "other": len(other_components),
            },
        )

        components_summary = {
            "bootloader": bootloader,
            "kernel": kernel,
            "rootfs": rootfs,
            "other_components": other_components,
            "binwalk_raw": scan.stdout if scan.success else "",
            "analysis_timestamp": datetime.now().isoformat(),
        }

        extraction_dir = str(Path(file_path).parent / f"{Path(file_path).name}_extracted")
        for candidate in [extraction_dir, str(Path(file_path).parent / "squashfs-root")]:
            if os.path.isdir(candidate):
                components_summary["extracted_dir"] = candidate
                break

        return components_summary

    # ------------------------------------------------------------------
    # Security analysis
    # ------------------------------------------------------------------

    async def _security_analysis(
        self, file_path: str, result: AgentResult
    ) -> Dict[str, Any]:
        """Scan firmware for secrets, debug strings, and vulnerable patterns."""
        result.add_reasoning_step("security_analysis_start", detail=file_path)

        secrets: List[Dict[str, str]] = []
        debug_interfaces: List[Dict[str, str]] = []
        vulnerable_patterns: List[Dict[str, str]] = []

        strings_res = await run_strings(file_path, min_length=6)
        self.record_tool_output(
            "strings", strings_res.command,
            strings_res.stdout, strings_res.stderr, strings_res.returncode,
        )
        result.add_reasoning_step(
            "strings_scanned",
            detail=f"{len(strings_res.stdout.splitlines())} strings extracted",
            tool="strings",
        )

        if strings_res.success:
            all_strings = strings_res.stdout.splitlines()

            secret_patterns = {
                "password": [
                    r"(?i)password\s*[=:]\s*\S+",
                    r"(?i)passwd\s*[=:]\s*\S+",
                    r"(?i)pwd\s*[=:]\s*\S+",
                ],
                "api_key": [
                    r"(?i)api[_-]?key\s*[=:]\s*\S+",
                    r"(?i)apikey\s*[=:]\s*\S+",
                    r"(?i)secret[_-]?key\s*[=:]\s*\S+",
                ],
                "token": [
                    r"(?i)token\s*[=:]\s*\S+",
                    r"(?i)access[_-]?token\s*[=:]\s*\S+",
                    r"(?i)bearer\s+\S+",
                ],
                "private_key": [
                    "BEGIN.*PRIVATE KEY",
                    "BEGIN RSA KEY",
                    "BEGIN DSA KEY",
                    "BEGIN EC KEY",
                ],
                "wi_fi_key": [
                    r"(?i)wpa[_-]?psk\s*[=:]\s*\S+",
                    r"(?i)psk\s*[=:]\s*\S+",
                    r"(?i)wireless.*key\s*[=:]\s*\S+",
                ],
                "certificate": [
                    "BEGIN CERTIFICATE",
                    "BEGIN X509",
                ],
                "mqtt_password": [
                    r"(?i)mqtt.*pass",
                    r"(?i)mqtt.*pwd",
                ],
            }

            import re
            for s in all_strings:
                for secret_type, patterns in secret_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, s):
                            secrets.append({
                                "type": secret_type,
                                "value": s.strip()[:200],
                                "context": "",
                            })
                            break

            debug_patterns = [
                ("UART", r"(?i)uart"),
                ("JTAG", r"(?i)jtag"),
                ("serial", r"(?i)serial.*console"),
                ("gdb", r"(?i)gdb.*server"),
                ("telnet", r"(?i)telnetd?"),
                ("console", r"(?i)console\s*="),
                ("debug", r"(?i)debug\s*mode"),
            ]
            for label, pat in debug_patterns:
                for s in all_strings:
                    if re.search(pat, s):
                        debug_interfaces.append({
                            "type": label,
                            "evidence": s.strip()[:200],
                        })
                        break

            vuln_indicators = {
                "telnet_enabled": r"(?i)telnetd",
                "hardcoded_root_password": r"(?i)root:0:0:",
                "open_debug_port": r"(?i)(jtag|uart|serial.*debug)",
                "weak_encryption": r"(?i)(des|md5|sha1(?!_|-))",
                "default_credentials": r"(?i)(admin:admin|root:root|user:user|default.*pass)",
                "insecure_protocol": r"(?i)(http://|ftp://|telnet://)",
                "updater_without_verification": r"(?i)(curl|wget).*\|.*sh",
                "shell_injection_risk": r"(?i)system\(|popen\(|exec\(",
            }
            for label, pat in vuln_indicators.items():
                for s in all_strings:
                    if re.search(pat, s):
                        vulnerable_patterns.append({
                            "indicator": label,
                            "evidence": s.strip()[:200],
                        })
                        break

        result.add_reasoning_step(
            "secrets_found",
            detail=f"{len(secrets)} potential secrets",
        )
        result.add_reasoning_step(
            "debug_interfaces_found",
            detail=f"{len(debug_interfaces)} debug interfaces",
        )
        result.add_reasoning_step(
            "vulnerable_patterns_found",
            detail=f"{len(vulnerable_patterns)} indicators",
        )

        risk = "low"
        if len(secrets) > 2 or len(vulnerable_patterns) > 3:
            risk = "high"
        elif len(secrets) > 0 or len(vulnerable_patterns) > 0 or len(debug_interfaces) > 0:
            risk = "medium"

        return {
            "file_path": file_path,
            "hardcoded_secrets": secrets,
            "debug_interfaces": debug_interfaces,
            "vulnerable_patterns": vulnerable_patterns,
            "strings_extracted_count": len(strings_res.stdout.splitlines()) if strings_res.success else 0,
            "risk_assessment": risk,
            "analysis_timestamp": datetime.now().isoformat(),
        }

    # ------------------------------------------------------------------
    # Comprehensive analysis
    # ------------------------------------------------------------------

    async def _comprehensive_analysis(
        self, file_path: str, result: AgentResult
    ) -> Dict[str, Any]:
        """Run all analysis phases and merge results."""
        result.add_reasoning_step("comprehensive_analysis_start", detail=file_path)

        basic = await self._basic_analysis(file_path, result)
        filesystem = await self._filesystem_analysis(file_path, result)
        components = await self._component_analysis(file_path, result)
        security = await self._security_analysis(file_path, result)

        result.add_reasoning_step(
            "comprehensive_analysis_complete",
            detail={
                "basic_signatures": len(basic.get("signatures", [])),
                "files_extracted": len(filesystem.get("extracted_files", [])),
                "security_risk": security.get("risk_assessment", "unknown"),
            },
        )

        return {
            "file_path": file_path,
            "basic_info": basic,
            "file_system": filesystem,
            "components": components,
            "security_assessment": security,
            "analysis_timestamp": datetime.now().isoformat(),
            "summary": {
                "file_type": basic.get("file_type", "unknown"),
                "architecture": basic.get("architecture", "unknown"),
                "signatures_found": len(basic.get("signatures", [])),
                "files_extracted": len(filesystem.get("extracted_files", [])),
                "interesting_files": len(filesystem.get("interesting_files", [])),
                "components": {
                    "bootloader": bool(components.get("bootloader")),
                    "kernel": bool(components.get("kernel")),
                    "rootfs": bool(components.get("rootfs")),
                },
                "security_risk": security.get("risk_assessment", "unknown"),
                "secrets_found": len(security.get("hardcoded_secrets", [])),
                "debug_interfaces": len(security.get("debug_interfaces", [])),
                "vulnerable_patterns": len(security.get("vulnerable_patterns", [])),
            },
        }

    # ------------------------------------------------------------------
    # Knowledge base storage
    # ------------------------------------------------------------------

    async def _store_analysis_results(
        self, file_path: str, analysis_type: str, data: Dict[str, Any]
    ) -> None:
        """Persist analysis results in the shared knowledge base."""
        try:
            title = f"Firmware analysis of {Path(file_path).name}"
            description = f"Completed {analysis_type} analysis of {file_path}"

            summary = data.get("summary", {})
            if summary:
                parts = []
                for key in ("file_type", "architecture", "security_risk"):
                    if key in summary:
                        parts.append(f"{key}: {summary[key]}")
                if parts:
                    description += ". " + "; ".join(parts)

            fact_id = add_fact(
                title=title,
                description=description,
                confidence=0.8,
                evidence=[f"Analysis of {file_path} using {analysis_type}"],
                source_references=[file_path],
                tags=["firmware_analysis", analysis_type, "automated"],
                source_agent=self.agent_id,
            )

            security = data.get("security_assessment", {})
            for secret in security.get("hardcoded_secrets", []):
                add_fact(
                    title=f"Hardcoded secret ({secret.get('type', 'unknown')})",
                    description=f"Found {secret.get('type')} in {Path(file_path).name}",
                    confidence=0.9,
                    evidence=[secret.get("value", "")[:100]],
                    source_references=[file_path],
                    tags=["secret", "hardcoded", "firmware"],
                    source_agent=self.agent_id,
                )

            for vuln in security.get("vulnerable_patterns", []):
                add_fact(
                    title=f"Vulnerability indicator: {vuln.get('indicator', 'unknown')}",
                    description=vuln.get("evidence", ""),
                    confidence=0.7,
                    evidence=[vuln.get("evidence", "")],
                    source_references=[file_path],
                    tags=["vulnerability", "firmware"],
                    source_agent=self.agent_id,
                )

            self.logger.info(f"Stored firmware analysis results (fact_id={fact_id})")

        except Exception as e:
            self.logger.error(f"Failed to store firmware analysis results: {e}")

    # ------------------------------------------------------------------
    # Capabilities
    # ------------------------------------------------------------------

    def get_capabilities(self) -> Dict[str, Any]:
        """Get the capabilities of this agent."""
        return {
            "agent_type": self.agent_type,
            "supported_analyses": ["basic", "filesystem", "components", "security", "comprehensive"],
            "supported_formats": list(self.supported_formats),
            "available_tools": {k: v for k, v in self.analysis_tools.items() if v},
        }


# Factory function for easy creation
def create_firmware_analysis_agent(agent_id: str = None) -> FirmwareAnalysisAgent:
    """Create a firmware analysis agent."""
    return FirmwareAnalysisAgent(agent_id=agent_id)


if __name__ == "__main__":
    import json
    import sys

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    async def test():
        agent = create_firmware_analysis_agent("test_fw_agent")
        print(f"Agent: {agent.agent_id}")

        if not await agent.initialize():
            print("Init failed")
            return

        print(f"Tools: {json.dumps(agent.analysis_tools, indent=2)}")

        target = sys.argv[1] if len(sys.argv) > 1 else "/tmp/test_firmware.bin"
        if not Path(target).exists():
            print(f"File not found: {target}")
            await agent.cleanup()
            return

        task = Task(
            task_id="test_fw_001",
            description="Comprehensive firmware analysis",
            agent_type="firmware_analysis",
            priority=2,
            parameters={"file_path": target, "analysis_type": "comprehensive"},
        )

        result = await agent.execute_task(task)
        print(json.dumps(result.to_dict(), indent=2, default=str))
        await agent.cleanup()

    asyncio.run(test())
