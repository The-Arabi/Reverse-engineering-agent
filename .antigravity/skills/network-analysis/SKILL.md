---
name: network-analysis
description: Use when the user wants to analyze network packet captures (pcap/pcapng) or network traffic. Triggers on pcap, tshark, wireshark, network traffic, protocol analysis, packet analysis, or network forensics.
---

# Network Analysis Skill

Use the `re-lab` MCP server tools to analyze network packet captures.

## Quick Start

```
1. re_capinfos(pcap_file="<path>")
2. re_analyze(agent_type="network", file_path="<path>")
```

## Full Command Reference

```python
# Capture metadata
re_capinfos(pcap_file="capture.pcap")

# Full decode
re_tshark(pcap_file="capture.pcap", verbose=true)

# Filter by protocol
re_tshark(pcap_file="capture.pcap", filters=["http", "dns"])

# Extract specific fields
re_tshark(pcap_file="capture.pcap", fields=["http.host", "http.request.uri", "ip.src", "ip.dst"])

# Limit packets
re_tshark(pcap_file="capture.pcap", filters=["tcp.port==443"], max_packets=100)

# Custom tcpdump
re_run_command(command=["tcpdump", "-r", "capture.pcap", "-nn", "-c", "50"])
```

## Common Display Filters

```
http                          # HTTP traffic
dns                           # DNS queries
tls                           # TLS/SSL traffic
http.request.method==POST     # HTTP POST requests
tcp.port==443                 # HTTPS traffic
dns.qry.name contains "evil"  # Suspicious DNS
tcp.flags.syn==1              # New TCP connections
tcp.analysis.retransmission   # Retransmissions
ip.src==10.0.0.1             # Traffic from specific IP
```

## Suspicious Patterns

- Beacons: regular periodic connections to same IP
- DNS tunneling: unusually long domain names
- Data exfil: large outbound data compared to inbound
- C2: connections to high ports or non-standard protocols

## After Analysis

Store findings with `kb_add_fact`. Link related network indicators with `kb_link_items`.
Use `re_rag_search` to find similar past analyses.
