# Reverse Engineering Lab — Project Instructions

This is a **reverse engineering research platform** with 5 specialized AI agents, a shared knowledge base, and real tool integration via subprocesses.

## Project Setup (do this first)

If the project is not yet set up, configure it before doing any analysis:

```bash
# 1. Create a virtualenv and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Configure an LLM provider (interactive wizard: detects tools,
#    picks a provider, validates the API key, writes .env)
python setup_wizard.py

# 3. Verify setup through the MCP layer
#    re_setup_status()    → providers, RE tools, .env status
#    re_llm_status()      → active provider and model
#    re_available_tools() → which RE tools are installed
```

Manual alternative: `cp .env.template .env`, set `LLM_PROVIDER` and the matching `*_API_KEY`. A local Ollama install works too (no key needed).

If no LLM provider is configured, the agents will fail — configure one via `python setup_wizard.py` or `re_setup_provider(provider, api_key, model)`.

Note: `opencode.json` / `antigravity.json` start the `re-lab` MCP server with the repo-local `venv/bin/python -m mcp.opencode_server`. If you move the venv, repoint those commands.

## Architecture

- **5 analysis agents**: binary, firmware, networking, CPU, kernel
- **Knowledge base** (SQLite): persistent storage for facts, hypotheses, experiments
- **Debate system**: multi-agent structured debate for resolving conflicting findings
- **Self-critique**: LLM-powered review of each agent's output
- **Token budgets**: rate limiting and budget enforcement across agents
- **Monitoring**: Prometheus metrics + Grafana dashboards
- **RAG pipeline**: semantic search across all analysis results

## Complete Tool Reference (46 tools)

All tools are available via the `re-lab` MCP server.

### Agent Analysis
| Tool | Purpose |
|------|---------|
| `re_analyze(agent_type, file_path, analysis_type)` | Run full agent pipeline (binary/firmware/network/cpu/kernel) |

### Core RE Tools
| Tool | Purpose |
|------|---------|
| `re_file_identify(file_path)` | Identify file type, architecture, format |
| `re_readelf(file_path, headers/sections/symbols/all)` | ELF structure inspection |
| `re_objdump(file_path, disassemble/headers/functions)` | Disassemble and examine code |
| `re_strings(file_path, min_length, filter_pattern)` | Extract printable strings |
| `re_hexdump(file_path, length, offset)` | View raw hex bytes |
| `re_binwalk(file_path, scan_only/extract)` | Firmware scanning and extraction |
| `re_tshark(pcap_file, filters, fields, max_packets)` | Packet capture analysis |
| `re_capinfos(pcap_file)` | Pcap capture metadata |
| `re_run_command(command, timeout)` | Run any RE tool (radare2, strace, nmap, etc.) |

### GDB Tools
| Tool | Purpose |
|------|---------|
| `re_gdb(binary_path, commands)` | GDB batch analysis |
| `re_gdb_symbols(binary_path, use_nm, symbol_type)` | Symbol table (nm-style or readelf) |
| `re_gdb_registers(binary_path, extra_commands)` | CPU register values |
| `re_gdb_backtrace(binary_path, pre_commands)` | Stack backtrace |
| `re_gdb_memory(binary_path, address, format, unit, count)` | Memory inspection at address |

### Ghidra Tools
| Tool | Purpose |
|------|---------|
| `re_ghidra(file_path, scripts)` | Ghidra headless analysis |
| `re_ghidra_decompile(file_path, address)` | Decompile a specific function |
| `re_ghidra_functions(file_path)` | List all functions in binary |
| `re_ghidra_xrefs(file_path, address)` | Cross-references to/from address |
| `re_ghidra_imports(file_path)` | Import table analysis |

### Knowledge Base
| Tool | Purpose |
|------|---------|
| `kb_add_fact(title, description, confidence, evidence, tags)` | Store verified finding |
| `kb_add_hypothesis(title, description, basis, confidence)` | Store testable theory |
| `kb_add_experiment(title, description, setup, procedure, results, conclusion)` | Store experiment record |
| `kb_update_item(item_id, title, description, confidence, tags)` | Update existing item |
| `kb_delete_item(item_id)` | Delete an item |
| `kb_search(query, limit)` | Search knowledge base |
| `kb_get_item(item_id)` | Get specific item by ID |
| `kb_statistics()` | Knowledge base overview stats |
| `kb_link_items(source_id, target_id, relationship)` | Create relationships between findings |

### RAG Semantic Search
| Tool | Purpose |
|------|---------|
| `re_rag_search(query, top_k)` | Semantic search across all analysis results |
| `re_rag_context(query, max_tokens)` | Build LLM-ready context from KB items |

### Debate & Collaboration
| Tool | Purpose |
|------|---------|
| `re_debate(topic, assertions, max_rounds)` | Run structured multi-agent debate |

### Setup & Configuration
| Tool | Purpose |
|------|---------|
| `re_setup_status()` | Check providers, tools, .env status |
| `re_validate_api_key(provider, api_key)` | Validate an API key |
| `re_setup_provider(provider, api_key, model)` | Write provider config to .env |
| `re_llm_status()` | Check active LLM provider and model |
| `re_config_get()` | View all configuration values |

### Monitoring & System
| Tool | Purpose |
|------|---------|
| `re_metrics(format)` | View system metrics (json or prometheus) |
| `re_system_status()` | Full orchestrator status |
| `re_web_dashboard()` | Check if web dashboard is running |
| `re_available_tools()` | Check which RE tools are installed |

### Mission Management
| Tool | Purpose |
|------|---------|
| `re_create_mission(title, description, tags, file_path, objectives)` | Create a research mission with optional objectives |
| `re_list_missions()` | List all missions |
| `re_mission_update(mission_id, action)` | Start, pause, resume, or cancel a mission |
| `re_mission_detail(mission_id)` | Get mission details with objectives and agents |
| `re_mission_progress(mission_id)` | Get real-time progress of a running mission |
| `re_token_budget_status()` | View token usage and limits |

## How to Use

### Analyzing a binary
1. `re_analyze(agent_type="binary", file_path="<path>")` — full automated pipeline
2. Or step-by-step: `re_file_identify` → `re_readelf` → `re_objdump` → `re_strings` → `re_hexdump`
3. Deep analysis: `re_ghidra_decompile`, `re_gdb_symbols`, `re_gdb_memory`

### Analyzing firmware
1. `re_analyze(agent_type="firmware", file_path="<path>")` — full automated pipeline
2. Or step-by-step: `re_file_identify` → `re_binwalk` → `re_strings` → `re_run_command`

### Analyzing network captures
1. `re_analyze(agent_type="network", file_path="<path>")` — full automated pipeline
2. Or step-by-step: `re_capinfos` → `re_tshark` with protocol filters

### Resolving conflicts
1. `re_debate` → structured debate between agents
2. Store consensus with `kb_add_fact`

### Managing the project
1. `re_setup_status` → check configuration
2. `re_create_mission` → create mission with file_path and objectives
3. `re_mission_update` → start, pause, resume, cancel
4. `re_mission_progress` → poll real-time execution progress
5. `re_mission_detail` → detailed status with objective states
6. `re_metrics` → monitor execution
7. `re_system_status` → full system overview
8. `re_token_budget_status` → token usage tracking

### Semantic search
1. `re_rag_search(query)` — find similar past analyses
2. `re_rag_context(query)` — build LLM context from KB

## Tips

- Always start with `re_file_identify` to understand what you're working with.
- Use `re_analyze` for quick automated analysis, or individual tools for step-by-step.
- Use `re_rag_search` to find similar past analyses before starting.
- Store important findings in the knowledge base as you go.
- Use `re_debate` when findings conflict — the debate protocol resolves disagreements.
- Run `python setup_wizard.py` or use `re_setup_provider` to configure LLM providers.
- The web dashboard at `http://localhost:5000` provides a visual interface.
