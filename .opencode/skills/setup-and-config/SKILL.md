---
name: setup-and-config
description: Use when the user wants to configure the RE lab, set up API keys, check installed tools, validate LLM providers, or troubleshoot configuration. Triggers on setup, configure, API key, provider, install, tools, status, or environment.
---

# Setup & Configuration Skill

Use MCP tools to configure and validate the RE lab environment without leaving opencode.

## Check Current Status

```python
re_setup_status()      # providers, tools, .env status
re_llm_status()        # active LLM provider and model
re_available_tools()   # which RE tools are installed
re_config_get()        # all configuration values
```

## Configure an LLM Provider

Supported providers: `openai`, `google`, `anthropic`, `openrouter`, `nvidia_nim`, `ollama`

```python
# 1. Validate the key first
re_validate_api_key(provider="openai", api_key="sk-...")

# 2. Write it to .env
re_setup_provider(provider="openai", api_key="sk-...", model="gpt-4")
```

For Ollama (no key needed):
```python
re_validate_api_key(provider="ollama")
re_setup_provider(provider="ollama")
```

## Get Provider Setup Links

Each provider has a setup URL:
- OpenAI: https://platform.openai.com/api-keys
- Google AI Studio: https://aistudio.google.com/apikey
- Anthropic: https://console.anthropic.com/settings/keys
- OpenRouter: https://openrouter.ai/keys
- NVIDIA NIM: https://build.nvidia.com/
- Ollama: https://ollama.com/download

## Token Budget Management

```python
re_token_budget_status()  # view token usage and limits
```

## Check Web Dashboard

```python
re_web_dashboard()  # check if running, get URL
```

## Check System Status

```python
re_system_status()  # orchestrator, missions, agents, budgets, debates
re_metrics(format="json")  # execution metrics
re_metrics(format="prometheus")  # Prometheus exposition format
```

## Mission Management

```python
re_create_mission(title="...", description="...", tags=[...], file_path="/path/to/target", objectives=[
    {"title": "Scan binary", "description": "Identify file type", "priority": "high", "assigned_agents": ["binary"]},
    {"title": "Analyze functions", "description": "Decompile all functions", "priority": "medium", "assigned_agents": ["binary"], "dependencies": ["Scan binary"]},
])  # create with objectives
re_list_missions()  # list all
re_mission_update(mission_id, action="start")  # start execution
re_mission_progress(mission_id)  # poll real-time progress
re_mission_detail(mission_id)  # detailed status with objective states
```

## Full Tool Reference (46 tools)

All available tools:
- **Agent**: `re_analyze`
- **Analysis**: `re_file_identify`, `re_readelf`, `re_objdump`, `re_strings`, `re_hexdump`, `re_binwalk`, `re_tshark`, `re_capinfos`, `re_run_command`
- **GDB**: `re_gdb`, `re_gdb_symbols`, `re_gdb_registers`, `re_gdb_backtrace`, `re_gdb_memory`
- **Ghidra**: `re_ghidra`, `re_ghidra_decompile`, `re_ghidra_functions`, `re_ghidra_xrefs`, `re_ghidra_imports`
- **Knowledge Base**: `kb_add_fact`, `kb_add_hypothesis`, `kb_add_experiment`, `kb_update_item`, `kb_delete_item`, `kb_search`, `kb_get_item`, `kb_statistics`, `kb_link_items`
- **RAG**: `re_rag_search`, `re_rag_context`
- **Debate**: `re_debate`
- **Setup**: `re_setup_status`, `re_validate_api_key`, `re_setup_provider`, `re_llm_status`, `re_config_get`
- **Monitoring**: `re_metrics`, `re_system_status`, `re_web_dashboard`, `re_available_tools`
- **Missions**: `re_create_mission`, `re_list_missions`, `re_mission_update`, `re_mission_detail`, `re_mission_progress`, `re_token_budget_status`
