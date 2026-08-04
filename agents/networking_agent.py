"""
Networking Agent Implementation
Specialized agent for analyzing network traffic, protocols, and network device behavior
using real tshark, capinfos, tcpdump, and file(1) tool invocations.
"""

import asyncio
import logging
from collections import Counter
from typing import Dict, Any, List, Optional
from pathlib import Path

from agents.base_agent import AnalysisAgent, AgentStatus, Task, AgentResult
from agents.tool_runner import run_tshark, run_capinfos, run_tcpdump, run_file, check_tool_available
from knowledge_base import add_fact


class NetworkingAgent(AnalysisAgent):
    """Agent specialized in network analysis using packet capture analysis, protocol dissection, and traffic generation"""

    def __init__(self, agent_id: str = None, name: str = "Networking Agent"):
        super().__init__(
            agent_id=agent_id or f"network_agent_{id(self)}",
            name=name,
            description="Analyzes network traffic, protocols, packets, and network device behavior"
        )
        self.agent_type = "networking"
        self.supported_formats = {
            "pcap", "pcapng", "cap", "tcpdump", "wireshark",
            "snoop", "netmon", "blf",
        }
        self.analysis_tools: Dict[str, bool] = {}

    async def initialize(self) -> bool:
        try:
            self.logger.info("Initializing Networking Agent")
            await self._check_available_tools()
            self.logger.info("Networking Agent initialized successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize Networking Agent: {e}")
            return False

    async def _check_available_tools(self):
        tools = ["tshark", "capinfos", "tcpdump", "file"]
        self.analysis_tools = {t: check_tool_available(t) for t in tools}
        available = sum(1 for v in self.analysis_tools.values() if v)
        self.logger.info(f"Available networking tools: {available}/{len(self.analysis_tools)}")

    # ------------------------------------------------------------------
    # Main task entry point
    # ------------------------------------------------------------------

    async def execute_task(self, task: Task) -> AgentResult:
        self.logger.info(f"Executing networking task: {task.description}")
        self.status = AgentStatus.PROCESSING

        agent_result = AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            status="failed",
        )

        try:
            params = task.parameters or {}
            file_path = params.get("file_path")
            analysis_type = params.get("analysis_type", "comprehensive")

            if not file_path:
                agent_result.error = "No file_path provided in task parameters"
                return agent_result

            if not Path(file_path).exists():
                agent_result.error = f"File not found: {file_path}"
                return agent_result

            agent_result.add_reasoning_step(
                "validate_input",
                detail={"file_path": file_path, "analysis_type": analysis_type},
            )

            if analysis_type == "basic":
                result = await self._basic_analysis(file_path, params)
            elif analysis_type == "protocol":
                result = await self._protocol_analysis(file_path, params)
            elif analysis_type == "security":
                result = await self._security_analysis(file_path, params)
            elif analysis_type == "performance":
                result = await self._performance_analysis(file_path, params)
            elif analysis_type == "voip":
                result = await self._voip_analysis(file_path, params)
            elif analysis_type == "malware":
                result = await self._malware_analysis(file_path, params)
            elif analysis_type == "comprehensive":
                result = await self._comprehensive_analysis(file_path, params)
            else:
                agent_result.error = f"Unknown analysis type: {analysis_type}"
                return agent_result

            await self._store_analysis_results(file_path, analysis_type, result)

            tool_summary = self._build_tool_summary()

            llm_analysis = await self._run_llm_analysis(result)
            if llm_analysis:
                agent_result.add_reasoning_step(
                    "llm_interpretation",
                    detail=f"llm_findings={len(llm_analysis.get('key_findings', []))}",
                )
                agent_result.llm_analysis = llm_analysis

            critique = await self._run_self_critique(tool_summary, result)
            if critique:
                agent_result.add_reasoning_step(
                    "self_critique",
                    detail=f"score={critique.get('score', 'N/A')}",
                )
                agent_result.critique = critique

            if llm_analysis:
                extraction = await self._run_knowledge_extraction(result, llm_analysis)
                if extraction:
                    agent_result.add_reasoning_step(
                        "knowledge_extraction",
                        detail=f"facts={len(extraction.get('facts_stored', []))}, "
                               f"hypotheses={len(extraction.get('hypotheses_stored', []))}",
                    )
                    agent_result.knowledge_extraction = extraction

            await self._store_with_rag(
                result, tags=["networking", analysis_type]
            )

            agent_result.status = "completed"
            agent_result.result = result
            self._compute_confidence(agent_result)
            agent_result.add_reasoning_step(
                "analysis_complete",
                detail=f"{analysis_type} analysis finished",
            )

        except Exception as e:
            self.logger.error(f"Error in networking task: {e}", exc_info=True)
            self.status = AgentStatus.ERROR
            agent_result.error = str(e)

        finally:
            if self.status != AgentStatus.ERROR:
                self.status = AgentStatus.IDLE

        return agent_result

    async def cleanup(self) -> bool:
        self.logger.info("Networking Agent cleaned up")
        return True

    # ------------------------------------------------------------------
    # Basic analysis – real capinfos + tshark field extraction
    # ------------------------------------------------------------------

    async def _basic_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Basic analysis on {file_path}")
        result: Dict[str, Any] = {
            "file_path": file_path,
            "file_size": 0,
            "capture_info": {},
            "packet_counts": {},
            "protocols_present": [],
            "conversations": {},
            "endpoints": {},
        }

        # --- file(1) type identification ---
        file_result = await run_file(file_path)
        result["file_type"] = file_result.stdout.strip() if file_result.success else "unknown"

        # --- capinfos metadata ---
        cap_result = await run_capinfos(file_path)
        if cap_result.success:
            result["capture_info"] = _parse_capinfos(cap_result.stdout)
            result["file_size"] = Path(file_path).stat().st_size
        else:
            result["capture_info"] = {"raw": cap_result.stderr}

        # --- tshark per-packet field extraction ---
        fields = [
            "frame.number",
            "frame.time",
            "ip.src",
            "ip.dst",
            "frame.protocols",
            "_ws.col.Info",
        ]
        pkt_result = await run_tshark(file_path, fields=fields, timeout=180)

        protocol_counter: Counter = Counter()
        src_ip_counter: Counter = Counter()
        dst_ip_counter: Counter = Counter()
        packet_lines: List[str] = []

        if pkt_result.success:
            packet_lines = [l for l in pkt_result.stdout.splitlines() if l.strip()]
            result["packet_counts"]["total"] = len(packet_lines)

            for line in packet_lines:
                parts = line.split("\t")
                # fields order: frame.number, frame.time, ip.src, ip.dst, frame.protocols, info
                if len(parts) >= 5:
                    proto_field = parts[4]  # e.g. "eth:ip:tcp:http"
                    for proto in proto_field.split(":"):
                        protocol_counter[proto] += 1
                    if parts[2] and parts[2] != "ip.src":
                        src_ip_counter[parts[2]] += 1
                    if parts[3] and parts[3] != "ip.dst":
                        dst_ip_counter[parts[3]] += 1
        else:
            result["packet_counts"]["total"] = 0

        result["protocols_present"] = sorted(protocol_counter.keys())
        result["packet_counts"]["by_protocol"] = dict(protocol_counter.most_common())

        # Top talkers
        combined = src_ip_counter + dst_ip_counter
        result["conversations"]["top_talkers"] = [
            {"address": ip, "packets": cnt}
            for ip, cnt in combined.most_common(20)
        ]
        result["endpoints"]["unique_src_ips"] = len(src_ip_counter)
        result["endpoints"]["unique_dst_ips"] = len(dst_ip_counter)
        result["endpoints"]["top_src_ips"] = [
            {"ip": ip, "packets": cnt}
            for ip, cnt in src_ip_counter.most_common(10)
        ]

        return result

    # ------------------------------------------------------------------
    # Protocol analysis – real tshark filters per protocol
    # ------------------------------------------------------------------

    async def _protocol_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Protocol analysis on {file_path}")
        result: Dict[str, Any] = {
            "file_path": file_path,
            "analysis_type": "protocol",
            "tcp": {},
            "dns": {},
            "http": {},
            "tls": {},
            "retransmissions": {},
            "handshake_analysis": {},
            "anomalies": [],
        }

        # --- TCP analysis ---
        tcp_result = await run_tshark(file_path, filters=["tcp"], fields=[
            "frame.number", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
            "tcp.flags", "tcp.analysis.retransmission", "tcp.analysis.duplicate_ack",
            "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.reset",
        ], timeout=180)
        if tcp_result.success:
            result["tcp"] = _parse_tcp_output(tcp_result.stdout)

        # --- DNS analysis ---
        dns_result = await run_tshark(file_path, filters=["dns"], fields=[
            "frame.number", "ip.src", "ip.dst",
            "dns.qry.name", "dns.resp.name", "dns.flags.response",
            "dns.qry.type", "dns.a", "dns.flags.rcode",
        ], timeout=180)
        if dns_result.success:
            result["dns"] = _parse_dns_output(dns_result.stdout)

        # --- HTTP analysis ---
        http_result = await run_tshark(file_path, filters=["http"], fields=[
            "frame.number", "ip.src", "ip.dst",
            "http.request.method", "http.response.code",
            "http.host", "http.request.uri", "http.content_type",
            "http.user_agent",
        ], timeout=180)
        if http_result.success:
            result["http"] = _parse_http_output(http_result.stdout)

        # --- TLS analysis ---
        tls_result = await run_tshark(file_path, filters=["tls"], fields=[
            "frame.number", "ip.src", "ip.dst",
            "tls.handshake.type", "tls.record.version",
            "tls.handshake.ciphersuite", "tls.alert_message",
        ], timeout=180)
        if tls_result.success:
            result["tls"] = _parse_tls_output(tls_result.stdout)

        # --- Retransmissions & handshake summary ---
        result["retransmissions"] = result["tcp"].get("retransmissions", {})
        result["handshake_analysis"] = {
            "tcp_syn_count": result["tcp"].get("syn_count", 0),
            "tcp_fin_count": result["tcp"].get("fin_count", 0),
            "tcp_rst_count": result["tcp"].get("rst_count", 0),
            "tls_handshake_count": result["tls"].get("handshake_count", 0),
            "tls_alert_count": result["tls"].get("alert_count", 0),
        }

        return result

    # ------------------------------------------------------------------
    # Security analysis – real tshark pattern detection
    # ------------------------------------------------------------------

    async def _security_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Security analysis on {file_path}")
        result: Dict[str, Any] = {
            "file_path": file_path,
            "analysis_type": "security",
            "port_scans": [],
            "brute_force": [],
            "suspicious_dns": [],
            "tcp_flag_anomalies": [],
            "raw_findings": [],
        }

        # --- SYN scan detection: many SYNs to different ports from one source ---
        syn_result = await run_tshark(file_path, filters=["tcp.flags.syn==1 && tcp.flags.ack==0"], fields=[
            "frame.number", "ip.src", "ip.dst", "tcp.dstport", "frame.time",
        ], timeout=180)
        if syn_result.success:
            result["port_scans"] = _detect_port_scans(syn_result.stdout)

        # --- Brute force detection: repeated connections to same port ---
        auth_result = await run_tshark(file_path, filters=["tcp"], fields=[
            "ip.src", "ip.dst", "tcp.dstport", "tcp.flags",
        ], timeout=180)
        if auth_result.success:
            result["brute_force"] = _detect_brute_force(auth_result.stdout)

        # --- DNS tunneling indicators: long subdomains ---
        dns_long_result = await run_tshark(file_path, filters=["dns.qry.name"], fields=[
            "frame.number", "ip.src", "dns.qry.name", "dns.qry.type",
        ], timeout=180)
        if dns_long_result.success:
            result["suspicious_dns"] = _detect_dns_tunneling(dns_long_result.stdout)

        # --- TCP flag anomalies: NULL, XMAS, FIN scans ---
        flag_anomaly_result = await run_tshark(file_path, filters=["tcp"], fields=[
            "frame.number", "ip.src", "ip.dst", "tcp.flags", "tcp.srcport", "tcp.dstport",
        ], timeout=180)
        if flag_anomaly_result.success:
            result["tcp_flag_anomalies"] = _detect_flag_anomalies(flag_anomaly_result.stdout)

        return result

    # ------------------------------------------------------------------
    # Simulated analyses (need specialised tools not yet available)
    # ------------------------------------------------------------------

    async def _performance_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Performance analysis on {file_path} (simulated)")
        return {
            "file_path": file_path,
            "analysis_type": "performance",
            "note": "Simulated – requires dedicated latency/jitter measurement tools",
            "latency_analysis": {"average_latency_ms": 0, "percentiles": {}},
            "jitter_analysis": {"average_jitter_ms": 0},
            "throughput_analysis": {"overall_mbps": 0},
            "packet_loss": {"overall_percent": 0},
            "tcp_performance": {"retransmission_rate": "0%"},
        }

    async def _voip_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"VoIP analysis on {file_path} (simulated)")
        return {
            "file_path": file_path,
            "analysis_type": "voip",
            "note": "Simulated – requires SIP/RTP specialised decoder",
            "calls": [],
            "call_quality_metrics": {},
            "issues": [],
        }

    async def _malware_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Malware analysis on {file_path} (simulated)")
        return {
            "file_path": file_path,
            "analysis_type": "malware",
            "note": "Simulated – requires threat intel feeds and sandbox integration",
            "c2_beacons": [],
            "exfiltration_attempts": [],
            "suspicious_dns": [],
        }

    # ------------------------------------------------------------------
    # Comprehensive – runs all analysis types
    # ------------------------------------------------------------------

    async def _comprehensive_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Comprehensive analysis on {file_path}")

        basic = await self._basic_analysis(file_path, params)
        protocol = await self._protocol_analysis(file_path, params)
        security = await self._security_analysis(file_path, params)
        performance = await self._performance_analysis(file_path, params)
        voip = await self._voip_analysis(file_path, params)
        malware = await self._malware_analysis(file_path, params)

        return {
            "file_path": file_path,
            "basic_info": basic,
            "protocol_analysis": protocol,
            "security_analysis": security,
            "performance_analysis": performance,
            "voip_analysis": voip,
            "malware_analysis": malware,
            "summary": {
                "packet_count": basic.get("packet_counts", {}).get("total", 0),
                "protocols_detected": len(basic.get("protocols_present", [])),
                "top_talkers": basic.get("conversations", {}).get("top_talkers", [])[:5],
                "security_findings": (
                    len(security.get("port_scans", []))
                    + len(security.get("brute_force", []))
                    + len(security.get("suspicious_dns", []))
                    + len(security.get("tcp_flag_anomalies", []))
                ),
                "tcp_retransmissions": protocol.get("retransmissions", {}).get("retransmission_count", 0),
            },
        }

    # ------------------------------------------------------------------
    # Knowledge-base storage
    # ------------------------------------------------------------------

    async def _store_analysis_results(self, file_path: str, analysis_type: str, result: Dict[str, Any]):
        try:
            title = f"Network analysis of {Path(file_path).name}"
            findings: List[str] = []

            summary = result.get("summary") or result.get("basic_info", {})
            if "packet_count" in summary:
                findings.append(f"Packets: {summary['packet_count']}")
            if "protocols_detected" in summary:
                findings.append(f"Protocols: {summary['protocols_detected']}")
            if "security_findings" in summary:
                findings.append(f"Security findings: {summary['security_findings']}")

            description = (
                f"Completed {analysis_type} analysis of {file_path}. "
                + "; ".join(findings) if findings else f"Completed {analysis_type} analysis of {file_path}"
            )

            fact_id = add_fact(
                title=title,
                description=description,
                confidence=0.8,
                evidence=[f"Network analysis of {file_path} using {analysis_type}"],
                source_references=[file_path],
                tags=["networking", analysis_type, "automated_analysis"],
                source_agent=self.agent_id,
            )
            self.logger.info(f"Stored results in knowledge base (fact {fact_id})")

            # Store individual security findings
            sec = result.get("security_analysis", {})
            for scan in sec.get("port_scans", []):
                add_fact(
                    title=f"Port scan: {scan.get('source', 'unknown')}",
                    description=f"{scan.get('scan_type', 'SYN scan')} by {scan.get('source')} -> {scan.get('target')}: {scan.get('port_count', 0)} ports",
                    confidence=0.85,
                    evidence=[f"Network security analysis of {file_path}"],
                    source_references=[file_path],
                    tags=["network_threat", "port_scan"],
                    source_agent=self.agent_id,
                )
        except Exception as e:
            self.logger.error(f"Failed to store results: {e}")

    # ------------------------------------------------------------------
    # Capabilities & utility
    # ------------------------------------------------------------------

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "agent_type": self.agent_type,
            "supported_analyses": [
                "basic", "protocol", "security", "performance",
                "voip", "malware", "comprehensive",
            ],
            "supported_formats": list(self.supported_formats),
            "available_tools": {k: v for k, v in self.analysis_tools.items() if v},
        }


# ======================================================================
# Parsing helpers
# ======================================================================

def _parse_capinfos(raw: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    for line in raw.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            info[key.strip()] = val.strip()
    return info


def _parse_tcp_output(raw: str) -> Dict[str, Any]:
    syn_count = 0
    fin_count = 0
    rst_count = 0
    retransmissions: List[Dict[str, Any]] = []
    dup_ack_count = 0
    flag_dist: Counter = Counter()

    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 7:
            continue

        flags_hex = parts[4].strip() if parts[4] else ""
        is_retrans = parts[5].strip() if parts[5] else ""
        is_dup_ack = parts[6].strip() if parts[6] else ""
        syn_flag = parts[7].strip() if len(parts) > 7 else ""
        fin_flag = parts[8].strip() if len(parts) > 8 else ""
        rst_flag = parts[9].strip() if len(parts) > 9 else ""

        if syn_flag == "1":
            syn_count += 1
        if fin_flag == "1":
            fin_count += 1
        if rst_flag == "1":
            rst_count += 1

        if flags_hex:
            flag_dist[flags_hex] += 1

        if is_retrans == "1":
            retransmissions.append({
                "frame": parts[0],
                "src": parts[1],
                "dst": parts[2],
            })
        if is_dup_ack == "1":
            dup_ack_count += 1

    return {
        "syn_count": syn_count,
        "fin_count": fin_count,
        "rst_count": rst_count,
        "flag_distribution": dict(flag_dist.most_common(20)),
        "retransmissions": {
            "retransmission_count": len(retransmissions),
            "sample": retransmissions[:20],
        },
        "dup_ack_count": dup_ack_count,
    }


def _parse_dns_output(raw: str) -> Dict[str, Any]:
    queries: List[str] = []
    response_codes: Counter = Counter()
    query_types: Counter = Counter()
    resolved_ips: List[str] = []
    response_names: List[str] = []

    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        qry_name = parts[3].strip() if parts[3] else ""
        resp_name = parts[4].strip() if parts[4] else ""
        is_response = parts[5].strip() if parts[5] else ""
        qry_type = parts[6].strip() if len(parts) > 6 else ""
        resolved_ip = parts[7].strip() if len(parts) > 7 else ""
        rcode = parts[8].strip() if len(parts) > 8 else ""

        if qry_name:
            queries.append(qry_name)
        if resp_name:
            response_names.append(resp_name)
        if rcode:
            response_codes[rcode] += 1
        if qry_type:
            query_types[qry_type] += 1
        if resolved_ip:
            resolved_ips.append(resolved_ip)

    return {
        "query_count": len(queries),
        "unique_domains": len(set(queries)),
        "sample_domains": list(set(queries))[:20],
        "response_codes": dict(response_codes),
        "query_types": dict(query_types),
        "resolved_ips": list(set(resolved_ips))[:20],
        "response_names": list(set(response_names))[:20],
    }


def _parse_http_output(raw: str) -> Dict[str, Any]:
    methods: Counter = Counter()
    status_codes: Counter = Counter()
    hosts: Counter = Counter()
    content_types: Counter = Counter()
    user_agents: Counter = Counter()
    uris: List[str] = []

    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        method = parts[3].strip() if parts[3] else ""
        status = parts[4].strip() if parts[4] else ""
        host = parts[5].strip() if len(parts) > 5 else ""
        uri = parts[6].strip() if len(parts) > 6 else ""
        ctype = parts[7].strip() if len(parts) > 7 else ""
        ua = parts[8].strip() if len(parts) > 8 else ""

        if method:
            methods[method] += 1
        if status:
            status_codes[status] += 1
        if host:
            hosts[host] += 1
        if ctype:
            content_types[ctype] += 1
        if ua:
            user_agents[ua] += 1
        if uri:
            uris.append(uri)

    return {
        "request_count": sum(methods.values()),
        "methods": dict(methods),
        "status_codes": dict(status_codes),
        "hosts": dict(hosts.most_common(20)),
        "content_types": dict(content_types),
        "top_user_agents": dict(user_agents.most_common(10)),
        "sample_uris": uris[:20],
    }


def _parse_tls_output(raw: str) -> Dict[str, Any]:
    handshake_types: Counter = Counter()
    versions: Counter = Counter()
    ciphersuites: Counter = Counter()
    alert_count = 0

    handshake_type_names = {
        "1": "ClientHello",
        "2": "ServerHello",
        "11": "Certificate",
        "12": "ServerKeyExchange",
        "14": "ServerHelloDone",
        "16": "ClientKeyExchange",
    }

    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        hs_type = parts[3].strip() if parts[3] else ""
        version = parts[4].strip() if len(parts) > 4 else ""
        cipher = parts[5].strip() if len(parts) > 5 else ""
        alert = parts[6].strip() if len(parts) > 6 else ""

        if hs_type:
            readable = handshake_type_names.get(hs_type, f"type_{hs_type}")
            handshake_types[readable] += 1
        if version:
            versions[version] += 1
        if cipher:
            ciphersuites[cipher] += 1
        if alert:
            alert_count += 1

    return {
        "handshake_count": sum(handshake_types.values()),
        "handshake_types": dict(handshake_types),
        "versions": dict(versions),
        "ciphersuites": dict(ciphersuites.most_common(20)),
        "alert_count": alert_count,
    }


# ======================================================================
# Security detection helpers
# ======================================================================

def _detect_port_scans(syn_raw: str) -> List[Dict[str, Any]]:
    """Detect SYN scan patterns: one source sending SYNs to many different destination ports."""
    src_dst_ports: Dict[str, set] = {}
    src_dst_target: Dict[str, set] = {}

    for line in syn_raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        frame_no = parts[0].strip()
        src_ip = parts[1].strip()
        dst_ip = parts[2].strip()
        dst_port = parts[3].strip()

        key = f"{src_ip}->{dst_ip}"
        src_dst_ports.setdefault(key, set()).add(dst_port)
        src_dst_target.setdefault(key, set()).add(dst_ip)

    scans: List[Dict[str, Any]] = []
    for key, ports in src_dst_ports.items():
        if len(ports) >= 5:
            src_ip, _, dst_ip = key.partition("->")
            scans.append({
                "source": src_ip,
                "target": dst_ip,
                "port_count": len(ports),
                "ports_sample": sorted(ports, key=lambda x: int(x) if x.isdigit() else 0)[:30],
                "scan_type": "SYN scan",
                "confidence": "high" if len(ports) >= 20 else "medium",
            })

    scans.sort(key=lambda s: s["port_count"], reverse=True)
    return scans


def _detect_brute_force(tcp_raw: str) -> List[Dict[str, Any]]:
    """Detect brute force: many SYN packets to the same destination port from one source."""
    attempts: Dict[str, int] = {}
    syn_pairs: Dict[str, set] = {}

    for line in tcp_raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        src_ip = parts[0].strip()
        dst_ip = parts[1].strip()
        dst_port = parts[2].strip()
        flags = parts[3].strip()

        if not (flags and flags != "0x002"):
            continue

        # SYN flag = 0x002
        is_syn = False
        try:
            flag_val = int(flags, 16) if flags.startswith("0x") else int(flags)
            is_syn = bool(flag_val & 0x002)
        except (ValueError, TypeError):
            continue

        if not is_syn:
            continue

        key = f"{src_ip}->{dst_ip}:{dst_port}"
        attempts[key] = attempts.get(key, 0) + 1
        syn_pairs.setdefault(key, set()).add(src_ip)

    brute: List[Dict[str, Any]] = []
    for key, count in attempts.items():
        if count >= 5:
            src_ip, _, rest = key.partition("->")
            dst_ip_port, _, _ = rest.rpartition(":")
            dst_ip, _, dst_port = dst_ip_port.partition(":") if ":" in dst_ip_port else (dst_ip_port, "", "")
            brute.append({
                "source": src_ip,
                "target": dst_ip,
                "port": dst_port,
                "attempt_count": count,
                "confidence": "high" if count >= 15 else "medium",
            })

    brute.sort(key=lambda b: b["attempt_count"], reverse=True)
    return brute


def _detect_dns_tunneling(dns_raw: str) -> List[Dict[str, Any]]:
    """Flag DNS queries with unusually long names (>50 chars) as tunneling indicators."""
    suspicious: List[Dict[str, Any]] = []

    for line in dns_raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        frame_no = parts[0].strip()
        src_ip = parts[1].strip()
        qry_name = parts[3].strip()
        qry_type = parts[4].strip() if len(parts) > 4 else ""

        if len(qry_name) > 50:
            suspicious.append({
                "frame": frame_no,
                "source": src_ip,
                "query_name": qry_name[:120],
                "query_type": qry_type,
                "name_length": len(qry_name),
                "reason": "long_subdomain",
                "confidence": "medium",
            })

    return suspicious


def _detect_flag_anomalies(tcp_raw: str) -> List[Dict[str, Any]]:
    """Detect TCP flag anomalies: NULL (no flags), XMAS (FIN+PSH+URG), etc."""
    anomalies: List[Dict[str, Any]] = []

    for line in tcp_raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        frame_no = parts[0].strip()
        src_ip = parts[1].strip()
        dst_ip = parts[2].strip()
        flags = parts[3].strip()
        src_port = parts[4].strip()
        dst_port = parts[5].strip()

        if not flags:
            continue

        try:
            flag_val = int(flags, 16) if flags.startswith("0x") else int(flags)
        except (ValueError, TypeError):
            continue

        fin = bool(flag_val & 0x001)
        syn = bool(flag_val & 0x002)
        rst = bool(flag_val & 0x004)
        psh = bool(flag_val & 0x008)
        ack = bool(flag_val & 0x010)
        urg = bool(flag_val & 0x020)

        if not any([fin, syn, rst, psh, ack, urg]):
            anomalies.append({
                "frame": frame_no,
                "src": src_ip, "dst": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
                "type": "NULL_scan",
                "flags_hex": flags,
                "confidence": "high",
            })
        elif fin and psh and urg and not syn and not ack:
            anomalies.append({
                "frame": frame_no,
                "src": src_ip, "dst": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
                "type": "XMAS_scan",
                "flags_hex": flags,
                "confidence": "high",
            })

    return anomalies


# ======================================================================
# Factory
# ======================================================================

def create_networking_agent(agent_id: str = None) -> NetworkingAgent:
    return NetworkingAgent(agent_id=agent_id)


# ======================================================================
# Manual test
# ======================================================================

if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO)

    async def test_networking_agent():
        agent = create_networking_agent("network_agent_001")
        print(f"Created agent: {agent.agent_id}")

        if await agent.initialize():
            print("Agent initialized")
        else:
            print("Init failed")
            return

        print(f"Capabilities: {json.dumps(agent.get_capabilities(), indent=2)}")

        test_task = Task(
            task_id="test_task_001",
            description="Analyze network traffic",
            agent_type="networking",
            priority=2,
            parameters={
                "file_path": "/tmp/network_traffic.pcapng",
                "analysis_type": "security",
            },
        )

        print("Executing task...")
        result = await agent.execute_task(test_task)
        print(json.dumps(result.to_dict(), indent=2, default=str))

        await agent.cleanup()
        print("Done")

    asyncio.run(test_networking_agent())
